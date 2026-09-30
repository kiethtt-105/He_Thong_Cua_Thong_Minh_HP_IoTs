# smartlock/api/views.py
"""REST API v1 cho app di động. Tái dùng nghiệp vụ có sẵn (SmartlockUtils, access_control, mqtt_client)."""
import logging
import re
import secrets
from datetime import timedelta

from django.db import IntegrityError, transaction
from django.db.models import Q
from django.urls import reverse
from django.utils import timezone
from rest_framework import status
from rest_framework.exceptions import NotFound, PermissionDenied
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework.throttling import ScopedRateThrottle
from rest_framework.views import APIView

from .. import access_control
from ..email_templates import render_email
from ..models import (
    AccessCard, AccessEvent, Announcement, AuditLog, AutomationRule, AutomationRuleLog,
    CardDeviceAccess, Device, DeviceAccess, DeviceCommand, DeviceStatusLog, DoorPinCode,
    FaceProfile, NfcLog, Notification, Permission, ShareAccessCode,
)
from ..models import MobileSession
from ..mqtt_client import MqttPublishError, publish_command
from ..utils import DEFAULT_PERMISSIONS, SmartlockUtils as U
from .common import StandardPagination, device_context, fail, get_device
from . import serializers as sz

logger = logging.getLogger('smartlock.api')


def paginate(request, queryset, serializer_cls, **context):
    paginator = StandardPagination()
    page = paginator.paginate_queryset(queryset, request)
    context.setdefault('request', request)
    return paginator.get_paginated_response(serializer_cls(page, many=True, context=context).data)


def ensure_permissions():
    for code, name, desc, sensitive in DEFAULT_PERMISSIONS:
        Permission.objects.get_or_create(code=code, defaults={'name': name, 'description': desc,
                                                              'is_sensitive': sensitive})


def _version_tuple(v: str):
    return tuple(int(x) for x in re.findall(r'\d+', v or '0')[:3]) or (0,)


# ============================== APP CONFIG / ANNOUNCEMENTS ==============================
class AppConfigView(APIView):
    """GET /app/config/?version=1.0.0 — công khai, app gọi lúc khởi động."""
    authentication_classes = []
    permission_classes = [AllowAny]

    def get(self, request):
        from django.conf import settings as s
        current = request.query_params.get('version', '')
        minimum = getattr(s, 'MOBILE_MIN_APP_VERSION', '1.0.0')
        return Response({
            'min_app_version': minimum,
            'latest_app_version': getattr(s, 'MOBILE_LATEST_APP_VERSION', minimum),
            'force_update': bool(current) and _version_tuple(current) < _version_tuple(minimum),
            'registration_enabled': U.settings().registration_enabled,
            'access_token_seconds': getattr(s, 'MOBILE_ACCESS_TOKEN_SECONDS', 900),
            'server_time': timezone.now(),
        })


class AnnouncementListView(APIView):
    def get(self, request):
        qs = Announcement.objects.filter(is_active=True).order_by('-created_at')[:20]
        return Response(sz.AnnouncementSerializer(qs, many=True).data)


# ============================== ME / SESSIONS ==============================
class MeView(APIView):
    def get(self, request):
        return Response(sz.UserSerializer(request.user).data)

    def patch(self, request):
        s = sz.ProfileUpdateSerializer(data=request.data, partial=True)
        s.is_valid(raise_exception=True)
        user, d = request.user, s.validated_data
        before = {'full_name': user.full_name, 'phone': user.phone}
        if 'full_name' in d:
            user.full_name = d['full_name'].strip()[:100] or None
        if 'phone' in d:
            user.phone = d['phone'].strip()[:20] or None
        user.save(update_fields=['full_name', 'phone', 'updated_at'])
        after = {'full_name': user.full_name, 'phone': user.phone}
        changes = {k: [before[k], after[k]] for k in after if before[k] != after[k]}
        U.audit(request, 'PROFILE_UPDATED', target_user=user, metadata={'changes': changes} if changes else None)
        return Response(sz.UserSerializer(user).data)


class SessionListView(APIView):
    def get(self, request):
        now = timezone.now()
        qs = MobileSession.objects.filter(user=request.user, revoked_at__isnull=True, expires_at__gt=now)
        current = request.auth.id if isinstance(request.auth, MobileSession) else None
        return Response(sz.MobileSessionSerializer(qs, many=True, context={'current_session_id': current}).data)


class SessionDetailView(APIView):
    def delete(self, request, session_id):
        session = MobileSession.objects.filter(pk=session_id, user=request.user).first()
        if not session:
            raise NotFound('Không tìm thấy phiên.')
        session.revoke()
        U.audit(request, 'MOBILE_SESSION_REVOKED', target_user=request.user,
                metadata={'session_id': str(session.id)})
        return Response(status=status.HTTP_204_NO_CONTENT)


class PushTokenView(APIView):
    """PUT /me/push-token/ — cập nhật FCM token (FCM hay đổi token) / bật-tắt push cho phiên hiện tại."""

    def put(self, request):
        session = request.auth
        if not isinstance(session, MobileSession):
            return fail('BEARER_REQUIRED', 'Chỉ dùng được với phiên đăng nhập của app.')
        s = sz.PushTokenSerializer(data=request.data)
        s.is_valid(raise_exception=True)
        d = s.validated_data
        fields = []
        if 'fcm_token' in d:
            if d['fcm_token']:
                MobileSession.objects.filter(fcm_token=d['fcm_token']).exclude(pk=session.pk).update(fcm_token='')
            session.fcm_token = d['fcm_token']
            fields.append('fcm_token')
        if 'push_enabled' in d:
            session.push_enabled = d['push_enabled']
            fields.append('push_enabled')
        if fields:
            session.save(update_fields=fields)
        return Response({'push_enabled': session.push_enabled, 'has_token': bool(session.fcm_token)})


# ============================== DEVICES ==============================
class DeviceListCreateView(APIView):
    def get(self, request):
        qs = U.accessible_devices(request.user).order_by('name')
        ctx = device_context(request.user, qs)
        return Response(sz.DeviceSerializer(qs, many=True, context=ctx).data)

    def post(self, request):
        s = sz.DeviceCreateSerializer(data=request.data)
        s.is_valid(raise_exception=True)
        name = s.validated_data['name'].strip()[:100]
        if not name:
            return fail('INVALID_NAME', 'Tên thiết bị không được để trống.')
        code = f'DEV-{secrets.token_hex(4).upper()}'
        while Device.objects.filter(device_code=code).exists():
            code = f'DEV-{secrets.token_hex(4).upper()}'
        secret = secrets.token_hex(16)
        device = Device.objects.create(
            name=name, device_code=code, provisioning_secret_hash=U.hash_token(secret),
            status='offline', owner=request.user, battery_level=100)
        U.audit(request, 'DEVICE_ADDED', device=device, metadata={'device_code': code, 'via': 'mobile'})
        U.notify(request.user, 'Thiết bị mới đã được tạo',
                 f'Hãy cấu hình device code: {code}', device=device, type_='DEVICE')
        data = sz.DeviceSerializer(device, context=device_context(request.user, [device])).data
        # provisioning_secret CHỈ trả đúng 1 lần, DB chỉ lưu hash.
        return Response({**data, 'provisioning_secret': secret}, status=status.HTTP_201_CREATED)


class DeviceDetailView(APIView):
    def get(self, request, device_id):
        device = get_device(request, device_id)
        return Response(sz.DeviceSerializer(device, context=device_context(request.user, [device])).data)

    def patch(self, request, device_id):
        device = get_device(request, device_id, owner_only=True)
        s = sz.DeviceUpdateSerializer(data=request.data, partial=True)
        s.is_valid(raise_exception=True)
        d = s.validated_data
        fields = ('name', 'location', 'wifi_enabled', 'bluetooth_enabled', 'nfc_enabled')
        before = {f: getattr(device, f) for f in fields}
        for f in fields:
            if f in d:
                setattr(device, f, (d[f].strip() or None) if f == 'location' else d[f])
        device.save()
        changes = {f: [before[f], getattr(device, f)] for f in fields if before[f] != getattr(device, f)}
        U.audit(request, 'DEVICE_UPDATED', device=device, metadata={'changes': changes} if changes else None)
        return Response(sz.DeviceSerializer(device, context=device_context(request.user, [device])).data)


class DeviceCommandView(APIView):
    """POST /devices/{id}/command/ {"command": "LOCK|UNLOCK|REBOOT"} -> 202 + command_id (app poll GET /commands/{id}/)."""
    throttle_classes = [ScopedRateThrottle]
    throttle_scope = 'command'

    def get(self, request, device_id):
        device = get_device(request, device_id)
        qs = DeviceCommand.objects.filter(device=device).select_related('issued_by').order_by('-created_at')
        return paginate(request, qs, sz.DeviceCommandSerializer)

    def post(self, request, device_id):
        device = get_device(request, device_id)
        s = sz.CommandRequestSerializer(data=request.data)
        if not s.is_valid():
            U.audit(request, 'CMD_INVALID', device=device, success=False, severity='warning')
            s.is_valid(raise_exception=True)
        command = s.validated_data['command']

        needed = U.ALLOWED_COMMANDS[command]
        allowed = (device.owner_id == request.user.id) if needed is None \
            else U.has_permission(request.user, device, needed)
        if not allowed:
            U.audit(request, f'CMD_{command}_DENIED', device=device, success=False, severity='warning')
            return fail('FORBIDDEN', 'Bạn không có quyền thực hiện lệnh này.', status.HTTP_403_FORBIDDEN)
        if device.status != 'online':
            U.audit(request, f'CMD_{command}_FAILED', device=device, success=False,
                    metadata={'reason': 'device_not_online', 'status': device.status})
            return fail('DEVICE_OFFLINE', 'Thiết bị đang không online.', status.HTTP_409_CONFLICT)

        now = timezone.now()
        DeviceCommand.objects.filter(device=device, status__in=('pending', 'sent'),
                                     expires_at__lte=now).update(status='expired')
        if DeviceCommand.objects.filter(device=device, status__in=('pending', 'sent'), command_type=command,
                                        created_at__gte=now - timedelta(seconds=10)).exists():
            return fail('DUPLICATE_COMMAND', 'Lệnh này vừa được gửi, vui lòng chờ vài giây.', 429)

        cmd = DeviceCommand.objects.create(
            device=device, issued_by=request.user, command_type=command, status='pending',
            command_token_hash=U.hash_token(secrets.token_urlsafe(32)),
            expires_at=now + timedelta(seconds=U.COMMAND_TTL_SECONDS))
        try:
            publish_command(device.device_code, {'command_id': str(cmd.id), 'command': command,
                                                 'token': cmd.command_token_hash})
            cmd.status = 'sent'
            cmd.save(update_fields=['status'])
        except MqttPublishError as e:
            cmd.status = 'failed'
            cmd.save(update_fields=['status'])
            U.audit(request, f'CMD_{command}_FAILED', device=device, success=False,
                    metadata={'reason': 'mqtt_publish_failed', 'error': str(e)[:200]})
            return fail('DEVICE_UNREACHABLE', 'Không kết nối được tới thiết bị. Vui lòng thử lại.',
                        status.HTTP_502_BAD_GATEWAY, command_id=str(cmd.id))
        U.audit(request, f'CMD_{command}', device=device, metadata={'command_id': str(cmd.id), 'via': 'mobile'})
        return Response(sz.DeviceCommandSerializer(cmd).data, status=status.HTTP_202_ACCEPTED)


class CommandDetailView(APIView):
    """GET /commands/{id}/ — app poll trạng thái pending -> sent -> acknowledged/failed/expired."""

    def get(self, request, command_id):
        cmd = (DeviceCommand.objects.select_related('issued_by', 'device')
               .filter(pk=command_id, device__in=U.accessible_devices(request.user)).first())
        if not cmd:
            raise NotFound('Không tìm thấy lệnh.')
        if cmd.status in ('pending', 'sent') and cmd.expires_at <= timezone.now():
            cmd.status = 'expired'
            cmd.save(update_fields=['status'])
        return Response(sz.DeviceCommandSerializer(cmd).data)


class DeviceStatusHistoryView(APIView):
    def get(self, request, device_id):
        device = get_device(request, device_id)
        try:
            limit = max(1, min(int(request.query_params.get('limit', 100)), 500))
        except ValueError:
            limit = 100
        qs = DeviceStatusLog.objects.filter(device=device).order_by('-recorded_at')[:limit]
        return Response(sz.StatusLogSerializer(qs, many=True).data)


class DeviceAccessEventsView(APIView):
    """Lịch sử ra vào hợp nhất RFID/PIN/khuôn mặt: ?method=RFID|PIN|FACE&success=true|false"""

    def get(self, request, device_id):
        device = get_device(request, device_id)
        qs = AccessEvent.objects.filter(device=device).select_related('device', 'user').order_by('-created_at')
        method = request.query_params.get('method')
        if method in dict(AccessEvent.METHOD_CHOICES):
            qs = qs.filter(method=method)
        ok = request.query_params.get('success')
        if ok in ('true', 'false'):
            qs = qs.filter(success=(ok == 'true'))
        return paginate(request, qs, sz.AccessEventSerializer)


# ============================== SYNC ==============================
class SyncView(APIView):
    """GET /sync/ — 1 request lấy mọi thứ cho màn hình chính."""

    def get(self, request):
        user = request.user
        devices = U.accessible_devices(user).order_by('name')
        ctx = device_context(user, devices)
        notifs = Notification.objects.filter(user=user).order_by('-created_at')[:20]
        data = {
            'generated_at': timezone.now(),
            'unread_count': Notification.objects.filter(user=user, is_read=False).count(),
            'devices': sz.DeviceSerializer(devices, many=True, context=ctx).data,
            'notifications': sz.NotificationSerializer(notifs, many=True).data,
        }
        response = Response(data)
        response['Cache-Control'] = 'no-store'
        return response


# ============================== NOTIFICATIONS ==============================
class NotificationListView(APIView):
    def get(self, request):
        qs = Notification.objects.filter(user=request.user).order_by('-created_at')
        if request.query_params.get('unread') in ('1', 'true'):
            qs = qs.filter(is_read=False)
        return paginate(request, qs, sz.NotificationSerializer)

    def delete(self, request):
        """DELETE /notifications/ — xoá tất cả thông báo đã đọc."""
        n, _ = Notification.objects.filter(user=request.user, is_read=True).delete()
        return Response({'deleted': n})


class NotificationUnreadCountView(APIView):
    def get(self, request):
        return Response({'unread_count': Notification.objects.filter(user=request.user, is_read=False).count()})


class NotificationReadAllView(APIView):
    def post(self, request):
        n = Notification.objects.filter(user=request.user, is_read=False).update(is_read=True, read_at=timezone.now())
        return Response({'updated': n})


class NotificationDetailView(APIView):
    def _get(self, request, notification_id):
        n = Notification.objects.filter(pk=notification_id, user=request.user).first()
        if not n:
            raise NotFound('Không tìm thấy thông báo.')
        return n

    def post(self, request, notification_id):      # đánh dấu đã đọc
        n = self._get(request, notification_id)
        if not n.is_read:
            n.is_read, n.read_at = True, timezone.now()
            n.save(update_fields=['is_read', 'read_at'])
        return Response(sz.NotificationSerializer(n).data)

    def delete(self, request, notification_id):
        self._get(request, notification_id).delete()
        return Response(status=status.HTTP_204_NO_CONTENT)


# ============================== SHARE CODES / ACCESSES ==============================
class ShareCodeListCreateView(APIView):
    def get(self, request):
        qs = (ShareAccessCode.objects.filter(device__owner=request.user).select_related('device')
              .prefetch_related('permissions').order_by('-created_at'))
        return paginate(request, qs, sz.ShareCodeSerializer)

    def post(self, request):
        s = sz.ShareCodeCreateSerializer(data=request.data)
        s.is_valid(raise_exception=True)
        d = s.validated_data
        device = Device.objects.filter(pk=d['device_id'], owner=request.user).first()
        if not device:
            U.audit(request, 'SHARE_CODE_CREATE_DENIED', success=False, severity='warning')
            raise NotFound('Không tìm thấy thiết bị của bạn.')
        minutes = d.get('minutes') or min(U.settings().share_code_expiry_minutes, 1440)

        plain = None
        for _ in range(20):
            candidate = f'{secrets.randbelow(10 ** 6):06d}'
            if not ShareAccessCode.is_code_taken(candidate):
                plain = candidate
                break
        if not plain:
            return fail('CODE_GENERATION_FAILED', 'Không tạo được mã, vui lòng thử lại.',
                        status.HTTP_503_SERVICE_UNAVAILABLE)

        ensure_permissions()
        perms = list(Permission.objects.filter(code__in=d['permissions']))
        code = ShareAccessCode(device=device, created_by=request.user,
                               expires_at=timezone.now() + timedelta(minutes=minutes))
        code.set_code(plain)
        code.save()
        code.permissions.set(perms)
        U.audit(request, 'SHARE_CODE_CREATED', device=device,
                metadata={'code_id': str(code.id), 'minutes': minutes, 'permissions': sorted(p.code for p in perms)})

        emailed = None
        if d['recipient']:
            recipient = U.find_user(d['recipient'])
            if recipient and recipient.is_active:
                subject, html, text = render_email('share_code_notification.html', {
                    'full_name': recipient.full_name or recipient.username, 'device_name': device.name,
                    'share_code': plain, 'expiry_minutes': minutes,
                    'action_url': request.build_absolute_uri(reverse('smartlock:share-request'))})
                emailed = U.send_mail(subject, text, html, recipient.email)
            else:
                emailed = False
        # Mã thô chỉ trả ĐÚNG 1 LẦN ở đây (DB chỉ lưu hash).
        return Response({**sz.ShareCodeSerializer(code).data, 'code': plain, 'emailed': emailed},
                        status=status.HTTP_201_CREATED)


class ShareCodeDetailView(APIView):
    def delete(self, request, code_id):
        code = ShareAccessCode.objects.select_related('device').filter(pk=code_id, device__owner=request.user).first()
        if not code:
            raise NotFound('Không tìm thấy mã chia sẻ.')
        device, cid = code.device, str(code.id)
        code.delete()
        U.audit(request, 'SHARE_CODE_DELETED', device=device, metadata={'code_id': cid})
        return Response(status=status.HTTP_204_NO_CONTENT)


class ShareRedeemView(APIView):
    """POST /share/redeem/ {"code": "123456"} — nhận quyền truy cập thiết bị được chia sẻ."""
    throttle_classes = [ScopedRateThrottle]
    throttle_scope = 'redeem'

    def post(self, request):
        s = sz.RedeemSerializer(data=request.data)
        s.is_valid(raise_exception=True)
        user, ip, now = request.user, U.client_ip(request), timezone.now()
        plain = re.sub(r'\D', '', s.validated_data['code'])

        fails = (AuditLog.objects.filter(action='SHARE_CODE_REDEEM_FAILED', created_at__gte=now - timedelta(minutes=15))
                 .filter(Q(actor_user=user) | Q(ip_address=ip)).count())
        if fails >= 5:
            U.audit(request, 'SHARE_CODE_RATE_LIMITED', success=False, severity='critical')
            return fail('TOO_MANY_ATTEMPTS', 'Bạn nhập sai quá nhiều lần. Thử lại sau 15 phút.', 429)

        match = ShareAccessCode.find_active_by_code(plain) if len(plain) == 6 else None
        if not match:
            U.audit(request, 'SHARE_CODE_REDEEM_FAILED', success=False, severity='warning')
            return fail('INVALID_CODE', 'Mã chia sẻ không đúng hoặc đã hết hạn.', status.HTTP_400_BAD_REQUEST)
        if match.device.owner_id == user.id:
            return fail('OWN_DEVICE', 'Đây là thiết bị của chính bạn.', status.HTTP_400_BAD_REQUEST)

        with transaction.atomic():
            locked = ShareAccessCode.objects.select_for_update().filter(id=match.id).first()
            if not locked:
                U.audit(request, 'SHARE_CODE_REDEEM_FAILED', success=False, severity='warning',
                        metadata={'reason': 'already_used'})
                return fail('INVALID_CODE', 'Mã chia sẻ không đúng hoặc đã hết hạn.', status.HTTP_400_BAD_REQUEST)
            new_exp = now + timedelta(hours=U.SHARED_ACCESS_HOURS)
            perms = list(locked.permissions.all())
            access = DeviceAccess.objects.select_for_update().filter(device=match.device, user=user, is_active=True).first()
            if access:
                if access.expires_at is not None:
                    access.expires_at = max(access.expires_at, new_exp)
                    access.save(update_fields=['expires_at'])
                access.permissions.add(*perms)
            else:
                access = DeviceAccess.objects.create(device=match.device, user=user, source='SHARE_CODE', accepted=True,
                                                     valid_from=now, expires_at=new_exp, created_by=match.created_by)
                access.permissions.set(perms)
            locked.delete()

        U.audit(request, 'SHARE_CODE_REDEEMED', device=match.device, target_user=match.created_by,
                metadata={'access_id': str(access.id), 'permissions': sorted(p.code for p in perms)})
        U.notify(match.created_by, 'Mã chia sẻ đã được sử dụng',
                 f'{user.username} đã nhận quyền truy cập "{match.device.name}".', device=match.device, type_='SHARE')
        return Response(sz.DeviceAccessSerializer(access).data, status=status.HTTP_201_CREATED)


class MyAccessListView(APIView):
    """Các quyền tôi đang được chia sẻ trên thiết bị của người khác."""

    def get(self, request):
        now = timezone.now()
        qs = (DeviceAccess.objects.filter(user=request.user, is_active=True)
              .filter(Q(expires_at__isnull=True) | Q(expires_at__gt=now))
              .select_related('device', 'user').prefetch_related('permissions').order_by('-created_at'))
        return Response(sz.DeviceAccessSerializer(qs, many=True).data)


class MyAccessDetailView(APIView):
    def delete(self, request, access_id):   # tự rời khỏi thiết bị được chia sẻ
        access = DeviceAccess.objects.filter(pk=access_id, user=request.user, is_active=True).first()
        if not access:
            raise NotFound('Không tìm thấy quyền truy cập.')
        access.is_active, access.revoked_at = False, timezone.now()
        access.save(update_fields=['is_active', 'revoked_at'])
        U.audit(request, 'ACCESS_LEFT', device=access.device, metadata={'access_id': str(access.id)})
        return Response(status=status.HTTP_204_NO_CONTENT)


class DeviceAccessListView(APIView):
    """Chủ thiết bị xem ai đang được chia sẻ."""

    def get(self, request, device_id):
        device = get_device(request, device_id, owner_only=True)
        qs = (DeviceAccess.objects.filter(device=device, is_active=True)
              .select_related('user', 'device').prefetch_related('permissions').order_by('-created_at'))
        return Response(sz.DeviceAccessSerializer(qs, many=True).data)


class DeviceAccessDetailView(APIView):
    def _get(self, request, device_id, access_id):
        device = get_device(request, device_id, owner_only=True)
        access = DeviceAccess.objects.filter(pk=access_id, device=device, is_active=True).first()
        if not access:
            raise NotFound('Không tìm thấy quyền truy cập.')
        return device, access

    def patch(self, request, device_id, access_id):
        device, access = self._get(request, device_id, access_id)
        s = sz.DeviceAccessUpdateSerializer(data=request.data, partial=True)
        s.is_valid(raise_exception=True)
        d = s.validated_data
        if 'expires_at' in d:
            if d['expires_at'] is not None and d['expires_at'] <= access.valid_from:
                return fail('INVALID_EXPIRY', 'Thời điểm hết hạn phải sau thời điểm bắt đầu.')
            access.expires_at = d['expires_at']
            access.save(update_fields=['expires_at'])
        if 'permissions' in d:
            ensure_permissions()
            access.permissions.set(Permission.objects.filter(code__in=d['permissions']))
        U.audit(request, 'ACCESS_UPDATED', device=device, target_user=access.user,
                metadata={'access_id': str(access.id), 'permissions': d.get('permissions')})
        access.refresh_from_db()
        return Response(sz.DeviceAccessSerializer(access).data)

    def delete(self, request, device_id, access_id):
        device, access = self._get(request, device_id, access_id)
        access.is_active, access.revoked_at = False, timezone.now()
        access.save(update_fields=['is_active', 'revoked_at'])
        U.audit(request, 'ACCESS_REVOKED', device=device, target_user=access.user, severity='warning',
                metadata={'access_id': str(access.id)})
        return Response(status=status.HTTP_204_NO_CONTENT)


class PermissionListView(APIView):
    def get(self, request):
        ensure_permissions()
        return Response(sz.PermissionSerializer(Permission.objects.order_by('name'), many=True).data)


# ============================== DOOR PIN ==============================
class DoorPinListCreateView(APIView):
    def get(self, request, device_id):
        device = get_device(request, device_id, permission='manage_pins')
        qs = DoorPinCode.objects.filter(device=device).select_related('created_by').order_by('-created_at')
        return paginate(request, qs, sz.DoorPinSerializer)

    def post(self, request, device_id):
        device = get_device(request, device_id)
        if not U.has_permission(request.user, device, 'manage_pins'):
            U.audit(request, 'DOOR_PIN_CREATE_DENIED', device=device, success=False, severity='warning')
            raise PermissionDenied('Bạn không có quyền cấp mã PIN cho thiết bị này.')
        s = sz.DoorPinCreateSerializer(data=request.data)
        s.is_valid(raise_exception=True)
        d = s.validated_data
        try:
            plain = access_control.generate_unique_pin(device)
        except RuntimeError as e:
            return fail('PIN_GENERATION_FAILED', str(e), status.HTTP_409_CONFLICT)
        pin = access_control.issue_door_pin(device=device, created_by=request.user, plain_pin=plain,
                                            ttl_minutes=d['ttl_minutes'], label=d['label'].strip(),
                                            max_uses=d['max_uses'])
        U.audit(request, 'DOOR_PIN_CREATED', device=device, metadata={'pin_id': str(pin.id), 'via': 'mobile'})
        # PIN thô chỉ trả ĐÚNG 1 LẦN (không lưu, không log).
        return Response({**sz.DoorPinSerializer(pin).data, 'pin': plain}, status=status.HTTP_201_CREATED)


class DoorPinRevokeView(APIView):
    def post(self, request, device_id, pin_id):
        device = get_device(request, device_id, permission='manage_pins')
        pin = DoorPinCode.objects.filter(pk=pin_id, device=device).first()
        if not pin:
            raise NotFound('Không tìm thấy mã PIN.')
        pin.revoke()
        U.audit(request, 'DOOR_PIN_REVOKED', device=device, metadata={'pin_id': str(pin.id)})
        return Response(sz.DoorPinSerializer(pin).data)


# ============================== FACE PROFILES ==============================
class FaceProfileListCreateView(APIView):
    def get(self, request, device_id):
        device = get_device(request, device_id)
        qs = FaceProfile.objects.filter(device=device).select_related('user').order_by('-created_at')
        if not U.has_permission(request.user, device, 'manage_face_profiles'):
            qs = qs.filter(user=request.user)
        return Response(sz.FaceProfileSerializer(qs, many=True).data)

    def post(self, request, device_id):
        device = get_device(request, device_id)
        if not U.has_permission(request.user, device, 'manage_face_profiles'):
            U.audit(request, 'FACE_PROFILE_CREATE_DENIED', device=device, success=False, severity='warning')
            raise PermissionDenied('Bạn không có quyền đăng ký khuôn mặt cho thiết bị này.')
        s = sz.FaceRegisterSerializer(data=request.data)
        if not s.is_valid():
            U.audit(request, 'FACE_PROFILE_INVALID_EMBEDDING', device=device, success=False, severity='warning')
            s.is_valid(raise_exception=True)
        d = s.validated_data
        profile = access_control.register_face(
            device=device, user=request.user, embedding=d['embedding'],
            name=(d['name'] or request.user.full_name or request.user.username)[:100], consent_confirmed=True)
        return Response(sz.FaceProfileSerializer(profile).data, status=status.HTTP_201_CREATED)


class FaceProfileDetailView(APIView):
    def _get(self, request, device_id, profile_id):
        device = get_device(request, device_id)
        profile = FaceProfile.objects.filter(pk=profile_id, device=device).select_related('user').first()
        # Chủ thiết bị quản lý mọi hồ sơ; người khác chỉ hồ sơ của chính mình.
        if profile and profile.user_id != request.user.id and device.owner_id != request.user.id:
            profile = None
        if not profile:
            raise NotFound('Không tìm thấy hồ sơ khuôn mặt.')
        return device, profile

    def patch(self, request, device_id, profile_id):   # bật/tắt
        device, profile = self._get(request, device_id, profile_id)
        active = request.data.get('is_active')
        profile.is_active = (not profile.is_active) if active is None else bool(active)
        profile.save(update_fields=['is_active', 'updated_at'])
        U.audit(request, 'FACE_PROFILE_TOGGLED', device=device, target_user=profile.user,
                metadata={'face_profile_id': str(profile.id), 'is_active': profile.is_active})
        return Response(sz.FaceProfileSerializer(profile).data)

    def delete(self, request, device_id, profile_id):
        device, profile = self._get(request, device_id, profile_id)
        pid, target = str(profile.id), profile.user
        profile.delete()
        U.audit(request, 'FACE_PROFILE_DELETED', device=device, target_user=target, severity='warning',
                metadata={'face_profile_id': pid})
        return Response(status=status.HTTP_204_NO_CONTENT)


# ============================== NFC / RFID CARDS ==============================
class CardListCreateView(APIView):
    def get(self, request):
        qs = AccessCard.objects.filter(user=request.user).prefetch_related('carddeviceaccess_set').order_by('-created_at')
        return Response(sz.AccessCardSerializer(qs, many=True).data)

    def post(self, request):
        s = sz.CardRegisterSerializer(data=request.data)
        s.is_valid(raise_exception=True)
        d = s.validated_data
        device = Device.objects.filter(pk=d['device_id'], owner=request.user).first()
        if not device:
            raise NotFound('Không tìm thấy thiết bị của bạn.')
        uid = re.sub(r'[\s:\-]', '', d['uid']).upper()
        if len(uid) < 4:
            return fail('INVALID_UID', 'UID thẻ không hợp lệ.')
        try:
            with transaction.atomic():
                card = AccessCard.objects.create(card_uid_hash=U.hash_token(uid), user=request.user,
                                                 name=d['name'].strip()[:100] or None, is_active=True)
                CardDeviceAccess.objects.create(access_card=card, device=device)
        except IntegrityError:
            U.audit(request, 'CARD_REGISTER_FAILED', device=device, success=False, severity='warning',
                    metadata={'reason': 'duplicate'})
            return fail('CARD_EXISTS', 'Thẻ này đã được đăng ký.', status.HTTP_409_CONFLICT)
        NfcLog.objects.create(nfc_tag=card, device=device, user=request.user, event_type='CARD_REGISTER',
                              ip_address=U.client_ip(request), user_agent=U.user_agent(request))
        U.audit(request, 'CARD_REGISTERED', device=device, metadata={'card_id': str(card.id), 'via': 'mobile'})
        return Response(sz.AccessCardSerializer(card).data, status=status.HTTP_201_CREATED)


class CardDetailView(APIView):
    def _get(self, request, card_id):
        card = AccessCard.objects.filter(pk=card_id, user=request.user).first()
        if not card:
            U.audit(request, 'CARD_NOT_FOUND', success=False, severity='warning', metadata={'card_id': str(card_id)})
            raise NotFound('Không tìm thấy thẻ.')
        return card

    def patch(self, request, card_id):
        card = self._get(request, card_id)
        s = sz.CardUpdateSerializer(data=request.data, partial=True)
        s.is_valid(raise_exception=True)
        d = s.validated_data
        if 'name' in d:
            card.name = d['name'].strip()[:100] or None
        if 'is_active' in d:
            card.is_active = d['is_active']
        card.save()
        U.audit(request, 'CARD_UPDATED', metadata={'card_id': str(card.id), 'is_active': card.is_active})
        return Response(sz.AccessCardSerializer(card).data)

    def delete(self, request, card_id):
        card = self._get(request, card_id)
        info = {'card_id': str(card.id), 'name': card.name}
        card.delete()
        U.audit(request, 'CARD_DELETED', metadata=info)
        return Response(status=status.HTTP_204_NO_CONTENT)


# ============================== AUTOMATION RULES ==============================
class RuleListCreateView(APIView):
    def get(self, request):
        qs = AutomationRule.objects.filter(owner=request.user).order_by('-created_at')
        return paginate(request, qs, sz.AutomationRuleSerializer)

    def post(self, request):
        s = sz.AutomationRuleSerializer(data=request.data, context={'request': request})
        s.is_valid(raise_exception=True)
        rule = s.save(owner=request.user)
        U.audit(request, 'AUTOMATION_RULE_CREATED', device=rule.device, metadata={'rule_id': str(rule.id)})
        return Response(s.data, status=status.HTTP_201_CREATED)


class RuleDetailView(APIView):
    def _get(self, request, rule_id):
        rule = AutomationRule.objects.filter(pk=rule_id, owner=request.user).first()
        if not rule:
            raise NotFound('Không tìm thấy luật.')
        return rule

    def get(self, request, rule_id):
        return Response(sz.AutomationRuleSerializer(self._get(request, rule_id), context={'request': request}).data)

    def patch(self, request, rule_id):
        rule = self._get(request, rule_id)
        s = sz.AutomationRuleSerializer(rule, data=request.data, partial=True, context={'request': request})
        s.is_valid(raise_exception=True)
        s.save()
        U.audit(request, 'AUTOMATION_RULE_UPDATED', device=rule.device, metadata={'rule_id': str(rule.id)})
        return Response(s.data)

    def delete(self, request, rule_id):
        rule = self._get(request, rule_id)
        rid, dev = str(rule.id), rule.device
        rule.delete()
        U.audit(request, 'AUTOMATION_RULE_DELETED', device=dev, metadata={'rule_id': rid})
        return Response(status=status.HTTP_204_NO_CONTENT)


class RuleLogListView(APIView):
    def get(self, request, rule_id):
        rule = AutomationRule.objects.filter(pk=rule_id, owner=request.user).first()
        if not rule:
            raise NotFound('Không tìm thấy luật.')
        return paginate(request, AutomationRuleLog.objects.filter(rule=rule).order_by('-triggered_at'),
                        sz.AutomationRuleLogSerializer)


class RuleMetaView(APIView):
    """GET /automation-rules/meta/ — danh sách trigger/action để app dựng form."""

    def get(self, request):
        return Response({'triggers': [{'value': v, 'label': l} for v, l in AutomationRule.TRIGGER_CHOICES],
                         'actions': [{'value': v, 'label': l} for v, l in AutomationRule.ACTION_CHOICES]})


# ============================== AUDIT LOG ==============================
class AuditLogListView(APIView):
    """?status=ok|fail&q=<từ khoá action>&device=<uuid>"""

    def get(self, request):
        user = request.user
        qs = (AuditLog.objects.filter(Q(actor_user=user) | Q(target_user=user) | Q(device__owner=user))
              .select_related('device', 'actor_user').order_by('-created_at'))
        st = request.query_params.get('status')
        if st in ('ok', 'fail'):
            qs = qs.filter(success=(st == 'ok'))
        q = (request.query_params.get('q') or '').strip()
        if q:
            qs = qs.filter(action__icontains=q)
        dev = U.parse_uuid(request.query_params.get('device'))
        if dev:
            qs = qs.filter(device_id=dev)
        return paginate(request, qs, sz.AuditLogSerializer)
