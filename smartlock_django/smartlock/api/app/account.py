"""Tài khoản của tôi - /api/app/me/..., /api/app/bootstrap/, /api/app/snapshot/"""
import hashlib
import json
from datetime import timedelta

from django.contrib.auth import update_session_auth_hash
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError
from django.db.models import Count, OuterRef, Q, Subquery
from django.db.models.functions import TruncDate
from django.http import HttpResponse
from django.utils import timezone

from .access import _card_json, _face_json, _pin_json, _reader_json, _share_json
from .serializers import command_json, device_json, event_json, notification_json, session_json, user_json
from smartlock import services
from smartlock.api.common import (
    api,
    ApiError,
    claim_fcm_token,
    iso,
    ok,
    read_json,
    revoke_all_sessions,
    s,
    uuid_or_404,
)
from smartlock.models import (
    AccessCard,
    AccessEvent,
    Announcement,
    AuditLog,
    Device,
    DeviceAccess,
    DeviceCommand,
    DeviceStatusLog,
    DoorPinCode,
    FaceProfile,
    Fido2Credential,
    MobileSession,
    NfcLog,
    NfcReader,
    Notification,
    TwoFactorConfig,
)


# ======================================================================
# views.py - Tài khoản: hồ sơ, đổi mật khẩu, phiên đăng nhập, push token, trạng thái 2FA, bootstrap (tải 1 lần khi mở app/web).
# ======================================================================

@api('GET', 'PATCH', auth='any')
def me(request):
    user = request.user
    if request.method == 'PATCH':
        data = read_json(request)
        before = {'full_name': user.full_name, 'phone': user.phone}
        if 'full_name' in data:
            user.full_name = s(data, 'full_name', 100) or None
        if 'phone' in data:
            user.phone = s(data, 'phone', 20) or None
        user.save(update_fields=['full_name', 'phone', 'updated_at'])
        after = {'full_name': user.full_name, 'phone': user.phone}
        changes = {k: [before[k], after[k]] for k in after if before[k] != after[k]}
        services.audit(request, 'PROFILE_UPDATED', target_user=user, metadata={'changes': changes} if changes else None)
    return ok({'user': user_json(user),
               'device_count': Device.objects.filter(owner=user).count(),
               'card_count': AccessCard.objects.filter(user=user).count()})


@api('POST', auth='any')
def change_password(request):
    user, data = request.user, read_json(request)
    old, new = str(data.get('old_password') or ''), str(data.get('new_password') or '')
    recent = AuditLog.objects.filter(action='PASSWORD_CHANGE_FAILED', actor_user=user,
                                     created_at__gte=timezone.now() - timedelta(minutes=15)).count()
    if recent >= 5:
        raise ApiError('RATE_LIMITED', 'Nhập sai mật khẩu hiện tại quá nhiều lần. Thử lại sau 15 phút.', 429)
    if not user.check_password(old):
        services.audit(request, 'PASSWORD_CHANGE_FAILED', success=False, severity='warning', target_user=user)
        raise ApiError('WRONG_PASSWORD', 'Mật khẩu hiện tại không đúng.', 400, field='old_password')
    if old == new:
        raise ApiError('SAME_PASSWORD', 'Mật khẩu mới phải khác mật khẩu hiện tại.', 400, field='new_password')
    try:
        validate_password(new, user)
    except ValidationError as e:
        raise ApiError('WEAK_PASSWORD', ' '.join(e.messages), 400, field='new_password')
    user.set_password(new)
    user.save()
    if request.client_type == 'web':
        update_session_auth_hash(request, user)        # giữ phiên web hiện tại; các phiên web khác tự hết hiệu lực
    # app: giữ phiên đang dùng; web: không có MobileSession nên thu hồi mọi phiên app
    others = revoke_all_sessions(user, exclude=request.api_session)
    services.audit(request, 'PASSWORD_CHANGED', severity='warning', target_user=user,
                   metadata={'channel': request.client_type, 'revoked_other_sessions': others})
    services.notify(user, 'Mật khẩu đã thay đổi', 'Bạn vừa đổi mật khẩu tài khoản.', severity='warning',
                    type_='SECURITY')
    return ok({'revoked_other_sessions': others})


@api('GET', auth='any')
def sessions_list(request):
    """Danh sách phiên đăng nhập trên app. Web gọi cũng được (để xem/đăng xuất các thiết bị di động);
    phiên web là cookie của Django nên không nằm trong danh sách này."""
    qs = MobileSession.objects.filter(user=request.user, revoked_at__isnull=True,
                                      expires_at__gt=timezone.now()).order_by('-created_at')
    current = request.api_session.id if request.api_session else None
    return ok({'sessions': [session_json(m, current) for m in qs]})


@api('DELETE', auth='any')
def session_revoke(request, session_id):
    m = MobileSession.objects.filter(pk=uuid_or_404(session_id), user=request.user).first()
    if not m:
        raise ApiError('NOT_FOUND', 'Không tìm thấy phiên đăng nhập.', 404)
    m.revoke()
    services.audit(request, 'MOBILE_SESSION_REVOKED', metadata={'session_id': str(m.id), 'channel': request.client_type})
    return ok()


@api('PUT', 'DELETE', auth='any')
def push_token(request):
    session = request.api_session
    if session is None:                                    # web không có FCM token / phiên app
        raise ApiError('APP_ONLY', 'Chức năng push token chỉ dành cho app di động.', 400)
    if request.method == 'DELETE':
        session.fcm_token = ''
        session.save(update_fields=['fcm_token'])
        return ok()
    data = read_json(request)
    token = s(data, 'fcm_token', 512)
    if token:
        claim_fcm_token(session, token)
    if 'push_enabled' in data:
        session.push_enabled = bool(data['push_enabled'])
        session.save(update_fields=['push_enabled'])
    return ok({'push_enabled': session.push_enabled, 'has_push_token': bool(session.fcm_token)})


@api('GET', auth='any')
def two_factor_status(request):
    cfg = TwoFactorConfig.objects.filter(user=request.user).first()
    methods = cfg.available_methods() if cfg else []
    return ok({'enabled': request.user.two_fa_enabled, 'methods': methods,
               'usable_in_app': [m for m in methods if m in ('totp', 'email')],
               'manage_on_web': True})


@api('GET', auth='any')
def bootstrap(request):
    user = request.user
    latest = (DeviceStatusLog.objects.filter(device=OuterRef('pk')).order_by('-recorded_at').values('lock_state')[:1])
    devices = list(services.accessible_devices(user).select_related('owner')
                   .annotate(last_lock_state=Subquery(latest)).order_by('name'))
    perms = services.permission_map(user, devices)
    notes = Notification.objects.filter(user=user).order_by('-created_at')[:20]
    return ok({
        'server_time': iso(timezone.now()),
        'user': user_json(user),
        'unread_count': Notification.objects.filter(user=user, is_read=False).count(),
        'devices': [device_json(d, user, perms[d.id], d.last_lock_state) for d in devices],
        'notifications': [notification_json(n) for n in notes],
        'announcements': [{'id': str(a.id), 'title': a.title, 'body': a.body, 'level': a.level,
                           'created_at': iso(a.created_at)}
                          for a in Announcement.objects.filter(is_active=True).order_by('-created_at')[:5]],
    })


# ====================== SNAPSHOT: TOÀN BỘ dữ liệu của CHÍNH user này (client cache + làm mới 2-5s) ======================
# Mỗi section lọc theo quyền của user giống hệt endpoint riêng của nó (chủ khoá thấy hết, người được chia sẻ chỉ thấy
# phần được phép). Trả kèm ETag: client gửi If-None-Match, không đổi gì -> 304 rỗng (nhẹ băng thông, không vẽ lại UI).
SNAPSHOT_LIMITS = {'notifications': 50, 'history': 50, 'audit': 50, 'pins': 200, 'commands': 50, 'nfc_logs': 30}


def _snapshot_payload(request) -> dict:
    user = request.user
    now = timezone.now()
    latest = (DeviceStatusLog.objects.filter(device=OuterRef('pk')).order_by('-recorded_at').values('lock_state')[:1])
    devices = list(services.accessible_devices(user).select_related('owner')
                   .annotate(last_lock_state=Subquery(latest)).order_by('name'))
    perms = services.permission_map(user, devices)

    # ---- thẻ NFC (cùng logic cards_list) ----
    nfc_managed = list(services.devices_with_permission(user, 'manage_nfc').values_list('id', 'owner_id'))
    owned_ids = {i for i, o in nfc_managed if o == user.id}
    cards = (AccessCard.objects.filter(Q(user=user) | Q(carddeviceaccess__device_id__in=owned_ids)).distinct()
             .select_related('user').prefetch_related('carddeviceaccess_set__device').order_by('-created_at'))

    # ---- đầu đọc / PIN / khuôn mặt: gộp theo thiết bị, client nhóm lại bằng device_id ----
    readers = NfcReader.objects.filter(device__in=services.devices_with_permission(user, 'manage_nfc')) \
        .order_by('-created_at')
    pins = (DoorPinCode.objects.filter(device__in=services.devices_with_permission(user, 'manage_pins'))
            .filter(Q(device__owner=user) | Q(created_by=user))          # không phải chủ: chỉ thấy mã mình tạo
            .select_related('created_by').order_by('-created_at')[:SNAPSHOT_LIMITS['pins']])
    faces = (FaceProfile.objects.filter(device__in=services.devices_with_permission(user, 'manage_face_profiles'))
             .filter(Q(device__owner=user) | Q(user=user))                # không phải chủ: chỉ hồ sơ của mình
             .select_related('user').order_by('-created_at'))

    # ---- chia sẻ: mình chia sẻ cho người khác (chủ khoá) + được chia sẻ cho mình ----
    share_qs = DeviceAccess.objects.select_related('device', 'user', 'created_by').prefetch_related('permissions')
    shares_out = share_qs.filter(device__owner=user, is_active=True).order_by('-created_at')
    shares_in = (share_qs.filter(user=user, is_active=True)
                 .filter(Q(expires_at__isnull=True) | Q(expires_at__gt=now)).order_by('-created_at'))

    # ---- lịch sử ra vào + nhật ký + thông báo ----
    history = (AccessEvent.objects.filter(device__in=services.devices_with_permission(user, 'view_history'))
               .select_related('device', 'user').order_by('-created_at')[:SNAPSHOT_LIMITS['history']])
    audit = services.visible_logs(user).select_related('device').order_by('-created_at')[:SNAPSHOT_LIMITS['audit']]
    notes = Notification.objects.filter(user=user).order_by('-created_at')[:SNAPSHOT_LIMITS['notifications']]

    # ---- bảo mật tài khoản (không có bí mật TOTP, không có khoá công khai) ----
    cfg = TwoFactorConfig.objects.filter(user=user).first()
    passkeys = Fido2Credential.objects.filter(user=user).order_by('created_at')
    sessions = MobileSession.objects.filter(user=user, revoked_at__isnull=True,
                                            expires_at__gt=now).order_by('-created_at')
    current = request.api_session.id if request.api_session else None

    # ---- nhật ký NFC (chủ khoá thấy hết, người khác chỉ thấy của mình) ----
    nfc_logs = (NfcLog.objects.filter(device__in=services.devices_with_permission(user, 'manage_nfc'))
                .filter(Q(device__owner=user) | Q(user=user)).select_related('nfc_tag')
                .order_by('-created_at')[:SNAPSHOT_LIMITS['nfc_logs']])

    # ---- lệnh điều khiển gần đây (chủ khoá thấy hết, người khác chỉ thấy lệnh của mình) ----
    commands = (DeviceCommand.objects.filter(device__in=[d.id for d in devices])
                .filter(Q(device__owner=user) | Q(issued_by=user)).select_related('issued_by')
                .order_by('-created_at')[:SNAPSHOT_LIMITS['commands']])

    # ---- biểu đồ hoạt động 7 ngày (đếm sẵn, client chỉ vẽ) ----
    today = timezone.localdate()
    days = [today - timedelta(days=i) for i in range(6, -1, -1)]
    counts = {r['d']: r['c'] for r in
              services.visible_logs(user).filter(created_at__date__gte=days[0])
              .annotate(d=TruncDate('created_at')).values('d').annotate(c=Count('id'))}

    return {
        'meta': {'face_min_frames': services.FACE_MIN_FRAMES, 'face_max_frames': services.FACE_MAX_FRAMES},
        'user': user_json(user),
        'unread_count': Notification.objects.filter(user=user, is_read=False).count(),
        'devices': [device_json(d, user, perms[d.id], d.last_lock_state) for d in devices],
        'cards': [_card_json(c, user, owned_ids) for c in cards],
        'nfc_readers': [_reader_json(r) for r in readers],
        'pins': [_pin_json(p) for p in pins],
        'faces': [_face_json(f) for f in faces],
        'shares_out': [_share_json(a) for a in shares_out],
        'shares_in': [_share_json(a) for a in shares_in],
        'history': [event_json(e) for e in history],
        'audit': [{'id': str(l.id), 'action': l.action, 'success': l.success, 'severity': l.severity,
                   'device_id': str(l.device_id) if l.device_id else None,
                   'device': l.device.name if l.device_id else None,
                   'ip_address': l.ip_address, 'created_at': iso(l.created_at)} for l in audit],
        'notifications': [notification_json(n) for n in notes],
        'nfc_logs': [{'id': str(l.id), 'device_id': str(l.device_id) if l.device_id else None,
                      'event_type': l.event_type, 'success': l.success,
                      'card': (l.nfc_tag.name or '') if l.nfc_tag_id else '', 'created_at': iso(l.created_at)}
                     for l in nfc_logs],
        'commands': [{**command_json(c), 'by': c.issued_by.username if c.issued_by_id else ''} for c in commands],
        'activity': {'labels': [d.strftime('%d/%m') for d in days], 'values': [counts.get(d, 0) for d in days]},
        'announcements': [{'id': str(a.id), 'title': a.title, 'body': a.body, 'level': a.level,
                           'created_at': iso(a.created_at)}
                          for a in Announcement.objects.filter(is_active=True).order_by('-created_at')[:5]],
        'security': {
            'email_masked': services.mask_email(user.email),
            'two_fa_enabled': user.two_fa_enabled,
            'totp': bool(cfg and cfg.totp_confirmed),
            'email_otp': bool(cfg and cfg.email_otp_enabled),
            'preferred_method': cfg.preferred_method if cfg else '',
            'passkeys': [{'id': str(k.id), 'name': k.name, 'created_at': iso(k.created_at),
                          'last_used_at': iso(k.last_used_at)} for k in passkeys],
            'sessions': [session_json(m, current) for m in sessions],
        },
    }


@api('GET', auth='any')
def snapshot(request):
    """GET /api/app/snapshot/ - mọi dữ liệu của user đang đăng nhập trong 1 lần gọi.
    ETag tính trên nội dung (không gồm server_time) -> If-None-Match khớp thì trả 304."""
    payload = _snapshot_payload(request)
    body = json.dumps(payload, sort_keys=True, default=str, separators=(',', ':'))
    etag = '"' + hashlib.sha1(body.encode('utf-8')).hexdigest() + '"'
    if request.headers.get('If-None-Match') == etag:
        resp = HttpResponse(status=304)
        resp['ETag'] = etag
        resp['Cache-Control'] = 'no-store'
        return resp
    resp = ok({'server_time': iso(timezone.now()), **payload})
    resp['ETag'] = etag
    return resp
