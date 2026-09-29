# smartlock/api/views.py
"""
API JSON cho web (phần USER). Xác thực bằng session cookie hiện có (SessionAuthentication + CSRF),
tái dùng đúng nghiệp vụ / audit / thông báo của views.py. Đăng nhập, đăng ký, quên mật khẩu và 2FA
vẫn dùng các trang hiện tại (phiên pending_2fa/passkey gắn chặt với session).

Quy ước lỗi: {"detail": "..."} hoặc {"field": ["..."]} (lỗi validate); 401 chưa đăng nhập, 403 không đủ quyền,
404 không thấy, 409 xung đột trạng thái, 429 bị giới hạn tốc độ, 502 lỗi MQTT.
"""
import re
import secrets
from datetime import timedelta

from django.contrib.auth import update_session_auth_hash
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError as DjangoValidationError
from django.db import IntegrityError, transaction
from django.db.models import Count, Q
from django.db.models.functions import TruncDate
from django.urls import reverse
from django.utils import timezone
from rest_framework import status
from rest_framework.exceptions import NotFound, PermissionDenied, ValidationError
from rest_framework.response import Response
from rest_framework.throttling import ScopedRateThrottle
from rest_framework.views import APIView

from .. import access_control
from ..email_templates import render_email
from ..models import (
    AccessCard, AccessEvent, Announcement, AuditLog, AutomationRule, AutomationRuleLog,
    CardDeviceAccess, Device, DeviceAccess, DeviceCommand, DeviceStatusLog, DoorPinCode,
    FaceProfile, NfcLog, NfcReader, Notification, Permission, ShareAccessCode, SupportRequest, User,
)
from ..mqtt_client import MqttPublishError, publish_command
from ..utils import SmartlockUtils as U
from . import serializers as S
from .common import (
    StandardPagination, ensure_default_permissions, get_accessible_device, get_owned_device, paginate,
    require_permission, resolve_permissions, secret_response, unique_share_plain, visible_logs,
    with_lock_state,
)

FAILED_REDEEM_LIMIT = 5
FAILED_REDEEM_WINDOW = timedelta(minutes=15)


def _valid(serializer_cls, request, **kwargs):
    s = serializer_cls(data=request.data, **kwargs)
    s.is_valid(raise_exception=True)
    return s.validated_data


def _admins():
    return User.objects.filter(Q(is_staff=True) | Q(is_superuser=True) | Q(is_admin=True),
                               is_active=True).exclude(email='')


# ====================== META / CSRF ======================
class CsrfView(APIView):
    """GET để trình duyệt nhận cookie csrftoken (gắn ensure_csrf_cookie ở urls.py).
    Client gửi lại giá trị đó trong header X-CSRFToken cho mọi POST/PATCH/DELETE."""
    authentication_classes = []
    permission_classes = []

    def get(self, request):
        return Response({'detail': 'ok'})


class MetaView(APIView):
    """Danh sách lựa chọn cho dropdown phía web."""
    def get(self, request):
        ensure_default_permissions()
        return Response({
            'permissions': S.PermissionSerializer(Permission.objects.order_by('name'), many=True).data,
            'automation_triggers': [{'value': v, 'label': l} for v, l in AutomationRule.TRIGGER_CHOICES],
            'automation_actions': [{'value': v, 'label': l} for v, l in AutomationRule.ACTION_CHOICES],
            'support_actions': [{'value': v, 'label': l}
                                for v, l in SupportRequest._meta.get_field('action').choices],
            'access_methods': [{'value': v, 'label': l} for v, l in AccessEvent.METHOD_CHOICES],
            'commands': sorted(U.ALLOWED_COMMANDS),
            'share_code_default_minutes': min(U.settings().share_code_expiry_minutes, 1440),
        })


# ====================== TÀI KHOẢN ======================
class MeView(APIView):
    def get(self, request):
        return Response(S.MeSerializer(request.user).data)

    def patch(self, request):
        data = _valid(S.ProfileUpdateSerializer, request, partial=True)
        user = request.user
        before = {'full_name': user.full_name, 'phone': user.phone}
        for field, value in data.items():
            setattr(user, field, (value or '').strip() or None)
        user.save(update_fields=[*data.keys(), 'updated_at'])
        after = {'full_name': user.full_name, 'phone': user.phone}
        changes = {k: [before[k], after[k]] for k in after if before[k] != after[k]}
        U.audit(request, 'PROFILE_UPDATED', target_user=user, metadata={'changes': changes} if changes else None)
        return Response(S.MeSerializer(user).data)


class ChangePasswordView(APIView):
    def post(self, request):
        data = _valid(S.ChangePasswordSerializer, request)
        user = request.user
        recent_fails = AuditLog.objects.filter(
            action='PASSWORD_CHANGE_FAILED', actor_user=user,
            created_at__gte=timezone.now() - timedelta(minutes=15)).count()
        if recent_fails >= 5:
            return Response({'detail': 'Nhập sai mật khẩu hiện tại quá nhiều lần. Thử lại sau 15 phút.'},
                            status=status.HTTP_429_TOO_MANY_REQUESTS)
        if not user.check_password(data['old_password']):
            U.audit(request, 'PASSWORD_CHANGE_FAILED', success=False, severity='warning', target_user=user)
            raise ValidationError({'old_password': ['Mật khẩu hiện tại không đúng.']})
        if data['new_password1'] != data['new_password2']:
            raise ValidationError({'new_password2': ['Mật khẩu mới không khớp.']})
        try:
            validate_password(data['new_password1'], user)
        except DjangoValidationError as e:
            raise ValidationError({'new_password1': list(e.messages)})
        user.set_password(data['new_password1'])
        user.save()
        update_session_auth_hash(request._request, user)     # giữ phiên hiện tại, các phiên khác bị vô hiệu
        U.audit(request, 'PASSWORD_CHANGED', severity='warning', target_user=user)
        U.notify(user, 'Mật khẩu đã thay đổi', 'Bạn vừa đổi mật khẩu tài khoản.',
                 severity='warning', type_='SECURITY')
        return Response({'detail': 'Đã đổi mật khẩu.'})


# ====================== DASHBOARD ======================
class DashboardView(APIView):
    def get(self, request):
        user = request.user
        devices = U.accessible_devices(user)
        today = timezone.localdate()
        days = [today - timedelta(days=i) for i in range(6, -1, -1)]
        counts = {r['d']: r['c'] for r in
                  visible_logs(user).filter(created_at__date__gte=days[0])
                  .annotate(d=TruncDate('created_at')).values('d').annotate(c=Count('id'))}
        now = timezone.now()
        return Response({
            'total_devices': devices.count(),
            'online_devices': devices.filter(status='online').count(),
            'unread_count': Notification.objects.filter(user=user, is_read=False).count(),
            'inactive_cards': AccessCard.objects.filter(user=user, is_active=False).count(),
            'active_share_codes': ShareAccessCode.objects.filter(
                device__owner=user, expires_at__gt=now).count(),
            'recent_notifications': S.NotificationSerializer(
                Notification.objects.filter(user=user).select_related('device').order_by('-created_at')[:4],
                many=True).data,
            'recent_logs': S.AuditLogSerializer(
                visible_logs(user).select_related('device', 'actor_user', 'target_user')
                .order_by('-created_at')[:6], many=True).data,
            'announcements': S.AnnouncementSerializer(
                Announcement.objects.filter(is_active=True).order_by('-created_at')[:3], many=True).data,
            'chart': {'labels': [d.strftime('%d/%m') for d in days],
                      'values': [counts.get(d, 0) for d in days]},
        })


class AnnouncementListView(APIView):
    def get(self, request):
        qs = Announcement.objects.filter(is_active=True).order_by('-created_at')[:20]
        return Response(S.AnnouncementSerializer(qs, many=True).data)


# ====================== THIẾT BỊ ======================
class DeviceListCreateView(APIView):
    def get(self, request):
        qs = with_lock_state(U.accessible_devices(request.user)).order_by('name')
        return Response(S.DeviceSerializer(qs, many=True, context={'request': request}).data)

    def post(self, request):
        data = _valid(S.DeviceCreateSerializer, request)
        user = request.user
        name = data['name'].strip()
        if not name:
            raise ValidationError({'name': ['Tên thiết bị không được để trống.']})

        device_code = f'DEV-{secrets.token_hex(4).upper()}'
        while Device.objects.filter(device_code=device_code).exists():
            device_code = f'DEV-{secrets.token_hex(4).upper()}'
        provisioning_secret = secrets.token_hex(16)      # chỉ hiện 1 lần, DB chỉ lưu hash
        device = Device.objects.create(
            name=name, device_code=device_code,
            provisioning_secret_hash=U.hash_token(provisioning_secret),
            status='offline', owner=user,      # 'provisioning' bắt buộc owner=NULL (chk_devices_owner_vs_status)
            bluetooth_enabled=True, wifi_enabled=True, nfc_enabled=True, battery_level=100,
        )
        U.audit(request, 'DEVICE_ADDED', device=device, metadata={'device_code': device_code})
        U.notify(user, 'Thiết bị mới đã được tạo',
                 f'Dữ liệu thiết bị đã được khởi tạo. Vui lòng cấu hình device code: {device_code}',
                 device=device, type_='DEVICE')

        subject, html, plain = render_email('device_added.html', {
            'full_name': user.full_name or user.username, 'device_name': device.name,
            'device_code': device.device_code,
            'action_url': request.build_absolute_uri(reverse('smartlock:device-detail', args=[device.id])),
        })
        U.send_mail(subject, plain, html, user.email)
        a_subject, a_html, a_plain = render_email('admin_device_approval.html', {
            'user_email': user.email, 'device_code': device.device_code,
            'action_url': request.build_absolute_uri(reverse('smartlock:audit-logs')) + '?all=1&q=DEVICE_ADDED',
        })
        for admin in _admins():
            U.send_mail(a_subject, a_plain, a_html, admin.email)

        device = with_lock_state(Device.objects.filter(pk=device.pk)).first()
        return secret_response({
            'device': S.DeviceSerializer(device, context={'request': request}).data,
            'provisioning_secret': provisioning_secret,
            'notice': 'provisioning_secret chỉ hiển thị một lần, hãy lưu lại.',
        }, status=status.HTTP_201_CREATED)


class DeviceDetailView(APIView):
    def get(self, request, device_id):
        device = get_accessible_device(request.user, device_id)
        is_owner = device.owner_id == request.user.id
        last = DeviceStatusLog.objects.filter(device=device).order_by('-recorded_at').first()
        cmds = DeviceCommand.objects.filter(device=device).select_related('issued_by')
        if not is_owner:
            cmds = cmds.filter(issued_by=request.user)
        return Response({
            'device': S.DeviceSerializer(device, context={'request': request}).data,
            'last_status': S.StatusLogSerializer(last).data if last else None,
            'recent_commands': S.DeviceCommandSerializer(cmds.order_by('-created_at')[:6], many=True).data,
        })

    def patch(self, request, device_id):
        device = get_accessible_device(request.user, device_id)
        if device.owner_id != request.user.id:
            U.audit(request, 'DEVICE_UPDATE_DENIED', device=device, success=False, severity='warning')
            raise PermissionDenied('Chỉ chủ thiết bị mới được chỉnh sửa.')
        data = _valid(S.DeviceUpdateSerializer, request, partial=True)
        fields = ('name', 'location', 'wifi_enabled', 'bluetooth_enabled', 'nfc_enabled')
        before = {f: getattr(device, f) for f in fields}
        if 'name' in data:
            device.name = data['name'].strip()[:100]
        if 'location' in data:
            device.location = (data['location'] or '').strip()[:255] or None
        for f in ('wifi_enabled', 'bluetooth_enabled', 'nfc_enabled'):
            if f in data:
                setattr(device, f, data[f])
        if not device.name:
            raise ValidationError({'name': ['Tên thiết bị không được để trống.']})
        device.save(update_fields=[*fields, 'updated_at'])
        changes = {f: [before[f], getattr(device, f)] for f in fields if before[f] != getattr(device, f)}
        U.audit(request, 'DEVICE_UPDATED', device=device, metadata={'changes': changes} if changes else None)
        return Response(S.DeviceSerializer(device, context={'request': request}).data)


class DeviceStatusLogListView(APIView):
    def get(self, request, device_id):
        device = get_accessible_device(request.user, device_id)
        qs = DeviceStatusLog.objects.filter(device=device).order_by('-recorded_at')
        return paginate(request, qs, S.StatusLogSerializer)


class DeviceCommandView(APIView):
    """POST {"command": "LOCK|UNLOCK|REBOOT"}. Trả 202 + command_id; poll GET .../commands/<id>/ để biết ack."""
    throttle_classes = [ScopedRateThrottle]
    throttle_scope = 'command'

    LABELS = {'LOCK': 'Khóa', 'UNLOCK': 'Mở khóa', 'REBOOT': 'Khởi động lại'}

    def post(self, request, device_id):
        device = get_accessible_device(request.user, device_id)
        command = str(request.data.get('command') or '').upper()
        if command not in U.ALLOWED_COMMANDS:
            U.audit(request, 'CMD_INVALID', device=device, success=False, severity='warning',
                    metadata={'command': command[:30]})
            return Response({'detail': 'Lệnh không hợp lệ.'}, status=status.HTTP_400_BAD_REQUEST)

        needed = U.ALLOWED_COMMANDS[command]
        allowed = (device.owner_id == request.user.id) if needed is None \
            else U.has_permission(request.user, device, needed)
        if not allowed:
            U.audit(request, f'CMD_{command}_DENIED', device=device, success=False, severity='warning')
            return Response({'detail': 'Bạn không có quyền thực hiện lệnh này.'}, status=status.HTTP_403_FORBIDDEN)
        if device.status != 'online':
            U.audit(request, f'CMD_{command}_FAILED', device=device, success=False,
                    metadata={'reason': 'device_not_online', 'status': device.status})
            return Response({'detail': 'Thiết bị đang không online.'}, status=status.HTTP_409_CONFLICT)

        now = timezone.now()
        DeviceCommand.objects.filter(device=device, status__in=('pending', 'sent'),
                                     expires_at__lte=now).update(status='expired')
        if DeviceCommand.objects.filter(device=device, status__in=('pending', 'sent'), command_type=command,
                                        created_at__gte=now - timedelta(seconds=10)).exists():
            U.audit(request, f'CMD_{command}_FAILED', device=device, success=False,
                    metadata={'reason': 'duplicate_pending'})
            return Response({'detail': 'Lệnh này vừa được gửi, vui lòng chờ vài giây.'},
                            status=status.HTTP_429_TOO_MANY_REQUESTS)

        cmd = DeviceCommand.objects.create(
            device=device, issued_by=request.user, command_type=command, status='pending',
            command_token_hash=U.hash_token(secrets.token_urlsafe(32)),
            expires_at=now + timedelta(seconds=U.COMMAND_TTL_SECONDS),
        )
        try:
            publish_command(device.device_code, {
                'command_id': str(cmd.id), 'command': command, 'token': cmd.command_token_hash})
            cmd.status = 'sent'
            cmd.save(update_fields=['status'])
        except MqttPublishError as e:
            cmd.status = 'failed'
            cmd.save(update_fields=['status'])
            U.audit(request, f'CMD_{command}_FAILED', device=device, success=False,
                    metadata={'reason': 'mqtt_publish_failed', 'error': str(e)[:200]})
            return Response({'detail': 'Không kết nối được tới thiết bị. Vui lòng thử lại.'},
                            status=status.HTTP_502_BAD_GATEWAY)

        U.audit(request, f'CMD_{command}', device=device, metadata={'command_id': str(cmd.id)})
        return Response({'command_id': str(cmd.id), 'status': cmd.status,
                         'message': f'Đã gửi lệnh {self.LABELS.get(command, command)} tới "{device.name}".'},
                        status=status.HTTP_202_ACCEPTED)


class DeviceCommandListView(APIView):
    def get(self, request, device_id):
        device = get_accessible_device(request.user, device_id)
        qs = DeviceCommand.objects.filter(device=device).select_related('issued_by')
        if device.owner_id != request.user.id:
            qs = qs.filter(issued_by=request.user)
        return paginate(request, qs.order_by('-created_at'), S.DeviceCommandSerializer)


class DeviceCommandDetailView(APIView):
    """Web poll trạng thái lệnh: pending -> sent -> acknowledged | failed | expired."""
    def get(self, request, device_id, command_id):
        device = get_accessible_device(request.user, device_id)
        cmd = DeviceCommand.objects.select_related('issued_by').filter(id=command_id, device=device).first()
        if not cmd or (device.owner_id != request.user.id and cmd.issued_by_id != request.user.id):
            raise NotFound('Không tìm thấy lệnh.')
        if cmd.status in ('pending', 'sent') and cmd.expires_at <= timezone.now():
            cmd.status = 'expired'
            cmd.save(update_fields=['status'])
        return Response(S.DeviceCommandSerializer(cmd).data)


# ====================== QUYỀN TRUY CẬP & CHIA SẺ ======================
class PermissionListView(APIView):
    def get(self, request):
        ensure_default_permissions()
        return Response(S.PermissionSerializer(Permission.objects.order_by('name'), many=True).data)


class DeviceAccessListCreateView(APIView):
    """Chủ thiết bị: xem / cấp quyền trực tiếp cho người dùng khác (email hoặc username)."""
    def get(self, request, device_id):
        device = get_owned_device(request.user, device_id)
        qs = (DeviceAccess.objects.filter(device=device, is_active=True)
              .select_related('user').prefetch_related('permissions').order_by('-created_at'))
        return Response(S.DeviceAccessSerializer(qs, many=True).data)

    def post(self, request, device_id):
        user = request.user
        device = get_owned_device(user, device_id)
        data = _valid(S.AccessGrantSerializer, request)
        perms = resolve_permissions(data.get('permissions'))
        expires = data.get('expires_at')
        target = U.find_user(data['identifier'])
        if not target or not target.is_active:
            U.audit(request, 'ACCESS_GRANT_FAILED', device=device, success=False,
                    username_attempt=data['identifier'][:150], metadata={'reason': 'user_not_found'})
            raise ValidationError({'identifier': ['Không tìm thấy người dùng (email hoặc username).']})
        if target.id == user.id:
            raise ValidationError({'identifier': ['Bạn đã là chủ thiết bị này.']})
        if expires and expires <= timezone.now():
            raise ValidationError({'expires_at': ['Thời điểm hết hạn phải ở tương lai.']})

        with transaction.atomic():
            access = (DeviceAccess.objects.select_for_update()
                      .filter(device=device, user=target, is_active=True).order_by('-created_at').first())
            if access:
                access.expires_at = expires
                access.accepted = True
                access.save(update_fields=['expires_at', 'accepted'])
            else:
                access = DeviceAccess.objects.create(device=device, user=target, created_by=user,
                                                     accepted=True, source='DIRECT', expires_at=expires)
            access.permissions.set(perms)
        codes = sorted(p.code for p in perms)
        U.audit(request, 'ACCESS_GRANTED', device=device, target_user=target,
                metadata={'access_id': str(access.id), 'permissions': codes,
                          'expires_at': expires.isoformat() if expires else None})
        U.notify(target, 'Bạn được cấp quyền thiết bị',
                 f'{user.username} đã cấp quyền cho bạn trên "{device.name}".', device=device, type_='ACCESS')
        return Response(S.DeviceAccessSerializer(access).data, status=status.HTTP_201_CREATED)


class DeviceAccessDetailView(APIView):
    def _get(self, request, device_id, access_id):
        device = get_owned_device(request.user, device_id)
        access = (DeviceAccess.objects.select_related('user')
                  .filter(id=access_id, device=device, is_active=True).first())
        if not access:
            U.audit(request, 'ACCESS_NOT_FOUND', device=device, success=False, severity='warning')
            raise NotFound('Không tìm thấy quyền truy cập.')
        return device, access

    def patch(self, request, device_id, access_id):
        device, access = self._get(request, device_id, access_id)
        data = _valid(S.AccessUpdateSerializer, request, partial=True)
        old_codes = sorted(p.code for p in access.permissions.all())
        if 'permissions' in data:
            access.permissions.set(resolve_permissions(data['permissions']))
        if 'expires_at' in data:
            exp = data['expires_at']
            if exp and exp <= timezone.now():
                raise ValidationError({'expires_at': ['Thời điểm hết hạn phải ở tương lai.']})
            access.expires_at = exp
            access.save(update_fields=['expires_at'])
        new_codes = sorted(p.code for p in access.permissions.all())
        U.audit(request, 'ACCESS_UPDATED', device=device, target_user=access.user,
                metadata={'access_id': str(access.id), 'from': old_codes, 'to': new_codes})
        access = DeviceAccess.objects.select_related('user').prefetch_related('permissions').get(pk=access.pk)
        return Response(S.DeviceAccessSerializer(access).data)

    def delete(self, request, device_id, access_id):
        device, access = self._get(request, device_id, access_id)
        access.is_active = False
        access.revoked_at = timezone.now()
        access.save(update_fields=['is_active', 'revoked_at'])
        # Lệnh đang chờ do người bị thu hồi gửi không được phép chạy tiếp.
        cancelled = DeviceCommand.objects.filter(
            device=device, issued_by=access.user, status='pending').update(status='failed')
        U.audit(request, 'ACCESS_REVOKED', device=device, target_user=access.user, severity='warning',
                metadata={'access_id': str(access.id), 'cancelled_commands': cancelled})
        U.notify(access.user, 'Quyền truy cập bị thu hồi',
                 f'Quyền của bạn trên "{device.name}" đã bị thu hồi.', severity='warning',
                 device=device, type_='ACCESS')
        return Response(status=status.HTTP_204_NO_CONTENT)


class MyAccessListView(APIView):
    """Các quyền mình đang được người khác cấp (còn hiệu lực)."""
    def get(self, request):
        now = timezone.now()
        qs = (DeviceAccess.objects.filter(user=request.user, is_active=True)
              .filter(Q(expires_at__isnull=True) | Q(expires_at__gt=now))
              .select_related('device').prefetch_related('permissions').order_by('-created_at'))
        return Response({'access_hours': U.SHARED_ACCESS_HOURS,
                         'results': S.MyAccessSerializer(qs, many=True).data})


class ShareCodeListCreateView(APIView):
    def get(self, request):
        qs = (ShareAccessCode.objects.filter(device__owner=request.user)
              .select_related('device').prefetch_related('permissions').order_by('-created_at'))
        return Response(S.ShareCodeSerializer(qs, many=True).data)

    def post(self, request):
        user = request.user
        data = _valid(S.ShareCodeCreateSerializer, request)
        device = get_owned_device(user, data['device_id'])
        minutes = data.get('minutes') or min(U.settings().share_code_expiry_minutes, 1440)
        perms = resolve_permissions(data.get('permissions'))
        plain = unique_share_plain()
        if not plain:
            return Response({'detail': 'Không tạo được mã, vui lòng thử lại.'},
                            status=status.HTTP_503_SERVICE_UNAVAILABLE)
        code = ShareAccessCode(device=device, created_by=user,
                               expires_at=timezone.now() + timedelta(minutes=minutes))
        code.set_code(plain)
        code.save()
        code.permissions.set(perms)
        U.audit(request, 'SHARE_CODE_CREATED', device=device,
                metadata={'code_id': str(code.id), 'minutes': minutes,
                          'permissions': sorted(p.code for p in perms)})

        email_status = None
        recipient_id = (data.get('recipient') or '').strip()
        if recipient_id:
            recipient = U.find_user(recipient_id)
            if not recipient or not recipient.is_active:
                email_status = 'recipient_not_found'
            else:
                subject, html, plain_text = render_email('share_code_notification.html', {
                    'full_name': recipient.full_name or recipient.username, 'device_name': device.name,
                    'share_code': plain, 'expiry_minutes': minutes,
                    'action_url': request.build_absolute_uri(reverse('smartlock:share-request')),
                })
                email_status = 'sent' if U.send_mail(subject, plain_text, html, recipient.email) else 'failed'

        code = ShareAccessCode.objects.select_related('device').prefetch_related('permissions').get(pk=code.pk)
        # Mã gốc chỉ trả đúng 1 lần ở đây (DB chỉ lưu hash một chiều).
        return secret_response({**S.ShareCodeSerializer(code).data, 'code': plain, 'email_status': email_status},
                               status=status.HTTP_201_CREATED)


class ShareCodeDetailView(APIView):
    def delete(self, request, code_id):
        code = (ShareAccessCode.objects.select_related('device')
                .filter(id=code_id, device__owner=request.user).first())
        if not code:
            raise NotFound('Không tìm thấy mã chia sẻ.')
        device, cid = code.device, str(code.id)
        code.delete()
        U.audit(request, 'SHARE_CODE_DELETED', device=device, metadata={'code_id': cid})
        return Response(status=status.HTTP_204_NO_CONTENT)


class ShareCodeRedeemView(APIView):
    """Người nhận nhập mã 6 số để được cấp quyền (24h). Giới hạn 5 lần sai / 15 phút theo user hoặc IP."""
    throttle_classes = [ScopedRateThrottle]
    throttle_scope = 'redeem'

    def post(self, request):
        user = request.user
        ip = U.client_ip(request)
        now = timezone.now()
        plain = re.sub(r'\D', '', _valid(S.ShareCodeRedeemSerializer, request)['code'])

        fails = (AuditLog.objects
                 .filter(action='SHARE_CODE_REDEEM_FAILED', created_at__gte=now - FAILED_REDEEM_WINDOW)
                 .filter(Q(actor_user=user) | Q(ip_address=ip)).count())
        if fails >= FAILED_REDEEM_LIMIT:
            U.audit(request, 'SHARE_CODE_RATE_LIMITED', success=False, severity='critical')
            return Response({'detail': 'Bạn nhập sai quá nhiều lần. Vui lòng thử lại sau 15 phút.'},
                            status=status.HTTP_429_TOO_MANY_REQUESTS)

        match = ShareAccessCode.find_active_by_code(plain) if len(plain) == 6 else None
        if not match:
            U.audit(request, 'SHARE_CODE_REDEEM_FAILED', success=False, severity='warning')
            raise ValidationError({'code': ['Mã chia sẻ không đúng hoặc đã hết hạn.']})
        if match.device.owner_id == user.id:
            U.audit(request, 'SHARE_CODE_OWN_DEVICE', device=match.device, success=False)
            raise ValidationError({'code': ['Đây là thiết bị của chính bạn.']})

        with transaction.atomic():
            locked = ShareAccessCode.objects.select_for_update().filter(id=match.id).first()
            if not locked:      # người khác vừa dùng mã này
                locked = None
            else:
                new_exp = now + timedelta(hours=U.SHARED_ACCESS_HOURS)
                perms = list(locked.permissions.all())
                access = (DeviceAccess.objects.select_for_update()
                          .filter(device=match.device, user=user, is_active=True).first())
                if access:      # đã có quyền: gia hạn + gộp quyền
                    if access.expires_at is not None:
                        access.expires_at = max(access.expires_at, new_exp)
                        access.save(update_fields=['expires_at'])
                    access.permissions.add(*perms)
                else:
                    access = DeviceAccess.objects.create(
                        device=match.device, user=user, source='SHARE_CODE', accepted=True,
                        valid_from=now, expires_at=new_exp, created_by=match.created_by)
                    access.permissions.set(perms)
                locked.delete()
        if locked is None:
            U.audit(request, 'SHARE_CODE_REDEEM_FAILED', success=False, severity='warning',
                    metadata={'reason': 'already_used'})
            raise ValidationError({'code': ['Mã chia sẻ không đúng hoặc đã hết hạn.']})

        U.audit(request, 'SHARE_CODE_REDEEMED', device=match.device, target_user=match.created_by,
                metadata={'access_id': str(access.id), 'permissions': sorted(p.code for p in perms)})
        U.notify(match.created_by, 'Mã chia sẻ đã được sử dụng',
                 f'{user.username} đã nhận quyền truy cập "{match.device.name}".',
                 device=match.device, type_='SHARE')
        access = DeviceAccess.objects.select_related('device').prefetch_related('permissions').get(pk=access.pk)
        return Response(S.MyAccessSerializer(access).data)


# ====================== NFC ======================
class NfcReaderListCreateView(APIView):
    def get(self, request, device_id):
        device = get_owned_device(request.user, device_id)
        qs = NfcReader.objects.filter(device=device).order_by('-created_at')
        return Response(S.NfcReaderSerializer(qs, many=True).data)

    def post(self, request, device_id):
        device = get_owned_device(request.user, device_id)
        data = _valid(S.NfcReaderCreateSerializer, request)
        name = (data.get('name') or '').strip()[:100] or 'Đầu đọc mô phỏng'
        with transaction.atomic():
            reader = NfcReader.objects.create(device=device, reader_mode='simulated', name=name, is_active=True)
            NfcLog.objects.create(reader=reader, device=device, user=request.user,
                                  event_type='READER_CONNECTED', ip_address=U.client_ip(request),
                                  user_agent=U.user_agent(request))
        U.audit(request, 'NFC_READER_ADDED', device=device, metadata={'reader_id': str(reader.id), 'name': name})
        return Response(S.NfcReaderSerializer(reader).data, status=status.HTTP_201_CREATED)


class NfcReaderDetailView(APIView):
    def patch(self, request, device_id, reader_id):
        device = get_owned_device(request.user, device_id)
        reader = NfcReader.objects.filter(id=reader_id, device=device).first()
        if not reader:
            U.audit(request, 'NFC_READER_NOT_FOUND', device=device, success=False, severity='warning')
            raise NotFound('Không tìm thấy đầu đọc.')
        data = _valid(S.NfcReaderUpdateSerializer, request, partial=True)
        events = []
        if 'is_active' in data and data['is_active'] != reader.is_active:
            reader.is_active = data['is_active']
            events.append(('READER_CONNECTED' if reader.is_active else 'READER_DISCONNECTED',
                           'NFC_READER_ENABLED' if reader.is_active else 'NFC_READER_DISABLED'))
        if 'auto_register' in data and data['auto_register'] != reader.auto_register:
            reader.auto_register = data['auto_register']
            events.append(('CONFIG_UPDATED',
                           'NFC_AUTO_REGISTER_ON' if reader.auto_register else 'NFC_AUTO_REGISTER_OFF'))
        if events:
            reader.save()
            for event_type, audit_action in events:
                NfcLog.objects.create(reader=reader, device=device, user=request.user, event_type=event_type,
                                      ip_address=U.client_ip(request), user_agent=U.user_agent(request))
                U.audit(request, audit_action, device=device, metadata={'reader_id': str(reader.id)})
        return Response(S.NfcReaderSerializer(reader).data)


class NfcLogListView(APIView):
    def get(self, request, device_id):
        device = get_owned_device(request.user, device_id)
        qs = (NfcLog.objects.filter(device=device).select_related('nfc_tag', 'reader')
              .order_by('-created_at'))
        return paginate(request, qs, S.NfcLogSerializer)


class NfcCardRegisterView(APIView):
    """Đăng ký thẻ NFC/RFID mới cho 1 thiết bị của mình (UID được hash SHA-256, không lưu thô)."""
    def post(self, request, device_id):
        user = request.user
        device = get_owned_device(user, device_id)
        data = _valid(S.CardRegisterSerializer, request)
        uid = re.sub(r'[\s:\-]', '', data['uid']).upper()
        name = (data.get('name') or '').strip()[:100] or None
        if len(uid) < 4:
            raise ValidationError({'uid': ['UID thẻ không hợp lệ.']})
        try:
            with transaction.atomic():
                card = AccessCard.objects.create(card_uid_hash=U.hash_token(uid), user=user, name=name,
                                                 is_active=True)
                CardDeviceAccess.objects.create(access_card=card, device=device)
        except IntegrityError:
            U.audit(request, 'CARD_REGISTER_FAILED', device=device, success=False, severity='warning',
                    metadata={'reason': 'duplicate'})
            raise ValidationError({'uid': ['Thẻ này đã được đăng ký.']})
        reader = NfcReader.objects.filter(device=device, is_active=True).first()
        NfcLog.objects.create(reader=reader, nfc_tag=card, device=device, user=user, event_type='CARD_REGISTER',
                              ip_address=U.client_ip(request), user_agent=U.user_agent(request))
        U.audit(request, 'CARD_REGISTERED', device=device, metadata={'card_id': str(card.id), 'name': name})

        subject, html, plain = render_email('admin_nfc_approval.html', {
            'user_email': user.email, 'card_name': name or 'Thẻ không tên', 'card_uid': uid,
            'action_url': request.build_absolute_uri(reverse('smartlock:audit-logs')) + '?all=1&q=CARD_REGISTERED',
        })
        for admin in _admins():
            U.send_mail(subject, plain, html, admin.email)
        card = AccessCard.objects.prefetch_related('carddeviceaccess_set__device').get(pk=card.pk)
        return Response(S.AccessCardSerializer(card).data, status=status.HTTP_201_CREATED)


class AccessCardListView(APIView):
    def get(self, request):
        qs = (AccessCard.objects.filter(user=request.user)
              .prefetch_related('carddeviceaccess_set__device').order_by('-created_at'))
        return Response(S.AccessCardSerializer(qs, many=True).data)


class AccessCardDetailView(APIView):
    def _card(self, request, card_id):
        card = (AccessCard.objects.filter(id=card_id, user=request.user)
                .prefetch_related('carddeviceaccess_set__device').first())
        if not card:
            U.audit(request, 'CARD_NOT_FOUND', success=False, severity='warning',
                    metadata={'card_id': str(card_id)[:64]})
            raise NotFound('Không tìm thấy thẻ.')
        return card

    def patch(self, request, card_id):
        card = self._card(request, card_id)
        data = _valid(S.CardUpdateSerializer, request, partial=True)
        if 'name' in data:
            old = card.name
            card.name = (data['name'] or '').strip()[:100] or None
            U.audit(request, 'CARD_RENAMED', metadata={'card_id': str(card.id), 'from': old, 'to': card.name})
        if 'is_active' in data and data['is_active'] != card.is_active:
            card.is_active = data['is_active']
            U.audit(request, 'CARD_ENABLED' if card.is_active else 'CARD_DISABLED',
                    metadata={'card_id': str(card.id), 'name': card.name})
        card.save()
        return Response(S.AccessCardSerializer(card).data)

    def delete(self, request, card_id):
        card = self._card(request, card_id)
        info = {'card_id': str(card.id), 'name': card.name,
                'devices': [str(a.device_id) for a in card.carddeviceaccess_set.all()]}
        card.delete()
        U.audit(request, 'CARD_DELETED', metadata=info)
        return Response(status=status.HTTP_204_NO_CONTENT)


# ====================== MÃ PIN CHO KHÁCH ======================
class DoorPinListCreateView(APIView):
    """Cần quyền manage_pins (chủ thiết bị luôn có)."""
    def get(self, request, device_id):
        device = get_accessible_device(request.user, device_id)
        require_permission(request, device, 'manage_pins')
        qs = DoorPinCode.objects.filter(device=device).select_related('created_by').order_by('-created_at')
        return paginate(request, qs, S.DoorPinSerializer)

    def post(self, request, device_id):
        device = get_accessible_device(request.user, device_id)
        require_permission(request, device, 'manage_pins', 'DOOR_PIN_CREATE_DENIED')
        data = _valid(S.DoorPinIssueSerializer, request)
        label = (data.get('label') or '').strip()[:100]
        try:
            plain_pin = access_control.generate_unique_pin(device)
        except RuntimeError as e:
            return Response({'detail': str(e)}, status=status.HTTP_409_CONFLICT)
        pin = access_control.issue_door_pin(      # tự ghi AuditLog DOOR_PIN_ISSUED
            device=device, created_by=request.user, plain_pin=plain_pin,
            ttl_minutes=data['ttl_minutes'], label=label, max_uses=data['max_uses'])
        # PIN thô chỉ trả 1 lần - không lưu, không log.
        return secret_response({**S.DoorPinSerializer(pin).data, 'pin': plain_pin},
                               status=status.HTTP_201_CREATED)


class DoorPinRevokeView(APIView):
    def post(self, request, device_id, pin_id):
        device = get_accessible_device(request.user, device_id)
        require_permission(request, device, 'manage_pins', 'DOOR_PIN_REVOKE_DENIED')
        pin = DoorPinCode.objects.select_related('created_by').filter(id=pin_id, device=device).first()
        if not pin:
            raise NotFound('Không tìm thấy mã PIN.')
        if not pin.is_revoked:
            pin.revoke()
            U.audit(request, 'DOOR_PIN_REVOKED', device=device, metadata={'pin_id': str(pin.id)})
        return Response(S.DoorPinSerializer(pin).data)


# ====================== KHUÔN MẶT ======================
class FaceProfileListCreateView(APIView):
    """Chủ thiết bị thấy hồ sơ của mọi người; người khác chỉ thấy hồ sơ của chính mình."""
    def get(self, request, device_id):
        device = get_accessible_device(request.user, device_id)
        qs = FaceProfile.objects.filter(device=device).select_related('user').order_by('-created_at')
        if device.owner_id != request.user.id:
            qs = qs.filter(user=request.user)
        return Response(S.FaceProfileSerializer(qs, many=True).data)

    def post(self, request, device_id):
        user = request.user
        device = get_accessible_device(user, device_id)
        require_permission(request, device, 'manage_face_profiles', 'FACE_PROFILE_CREATE_DENIED')
        data = _valid(S.FaceRegisterSerializer, request)
        name = ((data.get('name') or '').strip() or user.full_name or user.username)[:100]
        profile = access_control.register_face(device=device, user=user, embedding=data['embedding'],
                                               name=name, consent_confirmed=True)
        return Response(S.FaceProfileSerializer(profile).data, status=status.HTTP_201_CREATED)


class FaceProfileDetailView(APIView):
    def _get(self, request, device_id, profile_id):
        device = get_accessible_device(request.user, device_id)
        profile = FaceProfile.objects.select_related('user').filter(id=profile_id, device=device).first()
        if profile and profile.user_id != request.user.id and device.owner_id != request.user.id:
            profile = None
        if not profile:
            raise NotFound('Không tìm thấy hồ sơ khuôn mặt.')
        return device, profile

    def patch(self, request, device_id, profile_id):
        device, profile = self._get(request, device_id, profile_id)
        data = _valid(S.FaceProfileUpdateSerializer, request)
        profile.is_active = data['is_active']
        profile.save(update_fields=['is_active', 'updated_at'])
        U.audit(request, 'FACE_PROFILE_TOGGLED', device=device, target_user=profile.user,
                metadata={'face_profile_id': str(profile.id), 'is_active': profile.is_active})
        return Response(S.FaceProfileSerializer(profile).data)

    def delete(self, request, device_id, profile_id):
        """Xoá hẳn dữ liệu sinh trắc học (quyền xoá dữ liệu cá nhân theo NĐ 13/2023)."""
        device, profile = self._get(request, device_id, profile_id)
        pid, owner = str(profile.id), profile.user
        profile.delete()
        U.audit(request, 'FACE_PROFILE_DELETED', device=device, target_user=owner,
                severity='warning', metadata={'face_profile_id': pid})
        return Response(status=status.HTTP_204_NO_CONTENT)


# ====================== LỊCH SỬ RA VÀO ======================
class AccessEventListView(APIView):
    """?device=<uuid>&method=RFID|PIN|FACE&success=true|false. Chủ thiết bị thấy mọi lượt,
    người được chia sẻ chỉ thấy lượt của chính mình."""
    def get(self, request):
        user = request.user
        qs = (AccessEvent.objects.filter(device__in=U.accessible_devices(user))
              .filter(Q(device__owner=user) | Q(user=user))
              .select_related('device', 'user').order_by('-created_at'))
        dev = U.parse_uuid(request.query_params.get('device'))
        if request.query_params.get('device'):
            qs = qs.filter(device_id=dev) if dev else qs.none()
        method = request.query_params.get('method')
        if method in dict(AccessEvent.METHOD_CHOICES):
            qs = qs.filter(method=method)
        ok = request.query_params.get('success')
        if ok in ('true', 'false'):
            qs = qs.filter(success=(ok == 'true'))
        return paginate(request, qs, S.AccessEventSerializer)


# ====================== YÊU CẦU HỖ TRỢ ======================
class SupportRequestListCreateView(APIView):
    def get(self, request):
        now = timezone.now()
        SupportRequest.objects.filter(status='pending', expires_at__lte=now).update(
            status='expired', completed_at=now)
        qs = SupportRequest.objects.filter(requested_by=request.user).select_related('device').order_by('-created_at')
        return paginate(request, qs, S.SupportRequestSerializer)

    def post(self, request):
        user = request.user
        data = _valid(S.SupportRequestCreateSerializer, request)
        device = Device.objects.filter(id=data['device_id'], owner=user).first()
        if not device:
            U.audit(request, 'SUPPORT_REQUEST_DENIED', success=False, severity='warning',
                    metadata={'reason': 'not_owner'})
            raise NotFound('Không phải thiết bị của bạn.')
        action = data['action']
        if SupportRequest.objects.filter(device=device, requested_by=user, status='pending').count() >= 5:
            return Response({'detail': 'Bạn đang có quá nhiều yêu cầu chờ xử lý cho thiết bị này.'},
                            status=status.HTTP_409_CONFLICT)

        now = timezone.now()
        auth_code = secrets.token_hex(4).upper()
        recovery = secrets.token_hex(4).upper() if action in U.RECOVERY_ACTIONS else None
        sr = SupportRequest.objects.create(
            device=device, requested_by=user, action=action,
            scope=(data.get('scope') or '').strip()[:100] or None,
            authorization_code_hash=U.hash_token(auth_code),
            recovery_code_hash=U.hash_token(recovery) if recovery else None,
            expires_at=now + timedelta(hours=U.SUPPORT_TTL_HOURS),
        )
        U.audit(request, 'SUPPORT_REQUEST_CREATED', device=device,
                metadata={'request_id': str(sr.id), 'action': action})
        if recovery:    # reset / khôi phục / chuyển chủ ảnh hưởng quyền sở hữu -> báo admin qua email
            ctx = {'device_name': device.name, 'action_url': request.build_absolute_uri(
                reverse('smartlock:support-request-detail', args=[sr.id]))}
            for admin in _admins():
                ctx['full_name'] = admin.full_name or admin.username
                subject, html, plain = render_email('recovery_notification.html', ctx)
                U.send_mail(subject, plain, html, admin.email)

        sr = SupportRequest.objects.select_related('device').get(pk=sr.pk)
        return secret_response({**S.SupportRequestSerializer(sr).data,
                                'authorization_code': auth_code, 'recovery_code': recovery,
                                'notice': 'Các mã chỉ hiển thị một lần, hãy lưu lại.'},
                               status=status.HTTP_201_CREATED)


class SupportRequestDetailView(APIView):
    def get(self, request, request_id):
        sr = SupportRequest.objects.select_related('device').filter(
            id=request_id, requested_by=request.user).first()
        if not sr:
            raise NotFound('Không tìm thấy yêu cầu.')
        if sr.status == 'pending' and sr.expires_at <= timezone.now():
            sr.status, sr.completed_at = 'expired', timezone.now()
            sr.save(update_fields=['status', 'completed_at'])
        return Response(S.SupportRequestSerializer(sr).data)


class SupportRequestCancelView(APIView):
    def post(self, request, request_id):
        sr = SupportRequest.objects.select_related('device').filter(
            id=request_id, requested_by=request.user).first()
        if not sr:
            raise NotFound('Không tìm thấy yêu cầu.')
        if not (sr.status == 'pending' and sr.expires_at > timezone.now()):
            return Response({'detail': 'Chỉ có thể hủy yêu cầu đang chờ xử lý.'}, status=status.HTTP_409_CONFLICT)
        sr.status, sr.completed_at = 'cancelled', timezone.now()
        sr.save(update_fields=['status', 'completed_at'])
        U.audit(request, 'SUPPORT_REQUEST_CANCELLED', device=sr.device, metadata={'request_id': str(sr.id)})
        return Response(S.SupportRequestSerializer(sr).data)


# ====================== THÔNG BÁO ======================
class NotificationListView(APIView):
    """?filter=unread để chỉ lấy chưa đọc. Kèm unread_count."""
    def get(self, request):
        qs = Notification.objects.filter(user=request.user).select_related('device').order_by('-created_at')
        if request.query_params.get('filter') == 'unread':
            qs = qs.filter(is_read=False)
        resp = paginate(request, qs, S.NotificationSerializer)
        resp.data['unread_count'] = Notification.objects.filter(user=request.user, is_read=False).count()
        return resp


class NotificationUnreadCountView(APIView):
    def get(self, request):
        return Response({'unread_count': Notification.objects.filter(user=request.user, is_read=False).count()})


class NotificationReadView(APIView):
    def post(self, request, notification_id):
        n = Notification.objects.filter(user=request.user, id=notification_id).first()
        if not n:
            raise NotFound('Không tìm thấy thông báo.')
        if not n.is_read:
            n.is_read, n.read_at = True, timezone.now()
            n.save(update_fields=['is_read', 'read_at'])
        return Response(S.NotificationSerializer(n).data)


class NotificationReadAllView(APIView):
    def post(self, request):
        n = Notification.objects.filter(user=request.user, is_read=False).update(
            is_read=True, read_at=timezone.now())
        return Response({'updated': n})


class NotificationDetailView(APIView):
    def delete(self, request, notification_id):
        deleted, _ = Notification.objects.filter(user=request.user, id=notification_id).delete()
        if not deleted:
            raise NotFound('Không tìm thấy thông báo.')
        return Response(status=status.HTTP_204_NO_CONTENT)


class NotificationDeleteReadView(APIView):
    def delete(self, request):
        deleted, _ = Notification.objects.filter(user=request.user, is_read=True).delete()
        return Response({'deleted': deleted})


# ====================== LUẬT TỰ ĐỘNG HOÁ ======================
class AutomationRuleListCreateView(APIView):
    def get(self, request):
        qs = AutomationRule.objects.filter(owner=request.user).select_related('device').order_by('-created_at')
        return Response(S.AutomationRuleSerializer(qs, many=True, context={'request': request}).data)

    def post(self, request):
        s = S.AutomationRuleSerializer(data=request.data, context={'request': request})
        s.is_valid(raise_exception=True)
        rule = s.save(owner=request.user)
        U.audit(request, 'AUTOMATION_RULE_CREATED', device=rule.device,
                metadata={'rule_id': str(rule.id), 'trigger_type': rule.trigger_type,
                          'action_type': rule.action_type})
        return Response(S.AutomationRuleSerializer(rule, context={'request': request}).data,
                        status=status.HTTP_201_CREATED)


class AutomationRuleDetailView(APIView):
    def _rule(self, request, rule_id):
        rule = AutomationRule.objects.select_related('device').filter(id=rule_id, owner=request.user).first()
        if not rule:
            U.audit(request, 'AUTOMATION_RULE_NOT_FOUND', success=False, severity='warning')
            raise NotFound('Không tìm thấy luật.')
        return rule

    def get(self, request, rule_id):
        return Response(S.AutomationRuleSerializer(self._rule(request, rule_id),
                                                   context={'request': request}).data)

    def patch(self, request, rule_id):
        rule = self._rule(request, rule_id)
        s = S.AutomationRuleSerializer(rule, data=request.data, partial=True, context={'request': request})
        s.is_valid(raise_exception=True)
        rule = s.save()
        U.audit(request, 'AUTOMATION_RULE_UPDATED', device=rule.device, metadata={'rule_id': str(rule.id)})
        return Response(S.AutomationRuleSerializer(rule, context={'request': request}).data)

    def delete(self, request, rule_id):
        rule = self._rule(request, rule_id)
        device, rid = rule.device, str(rule.id)
        rule.delete()
        U.audit(request, 'AUTOMATION_RULE_DELETED', device=device, severity='warning',
                metadata={'rule_id': rid})
        return Response(status=status.HTTP_204_NO_CONTENT)


class AutomationRuleToggleView(APIView):
    def post(self, request, rule_id):
        rule = AutomationRule.objects.select_related('device').filter(id=rule_id, owner=request.user).first()
        if not rule:
            raise NotFound('Không tìm thấy luật.')
        rule.is_active = not rule.is_active
        rule.save(update_fields=['is_active', 'updated_at'])
        U.audit(request, 'AUTOMATION_RULE_TOGGLED', device=rule.device,
                metadata={'rule_id': str(rule.id), 'is_active': rule.is_active})
        return Response(S.AutomationRuleSerializer(rule, context={'request': request}).data)


class AutomationRuleLogListView(APIView):
    def get(self, request, rule_id):
        rule = AutomationRule.objects.filter(id=rule_id, owner=request.user).first()
        if not rule:
            raise NotFound('Không tìm thấy luật.')
        qs = AutomationRuleLog.objects.filter(rule=rule).select_related('device').order_by('-triggered_at')
        return paginate(request, qs, S.AutomationRuleLogSerializer)


# ====================== NHẬT KÝ HOẠT ĐỘNG ======================
class AuditLogListView(APIView):
    """?status=ok|fail&q=<từ khoá action>. Chỉ log liên quan tới mình / thiết bị của mình."""
    def get(self, request):
        qs = (visible_logs(request.user).select_related('device', 'actor_user', 'target_user')
              .order_by('-created_at'))
        st = request.query_params.get('status')
        if st == 'ok':
            qs = qs.filter(success=True)
        elif st == 'fail':
            qs = qs.filter(success=False)
        q = (request.query_params.get('q') or '').strip()
        if q:
            qs = qs.filter(action__icontains=q)
        return paginate(request, qs, S.AuditLogSerializer)