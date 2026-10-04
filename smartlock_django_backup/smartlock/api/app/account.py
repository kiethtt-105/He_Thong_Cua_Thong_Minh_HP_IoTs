"""Tài khoản: hồ sơ, đổi mật khẩu, phiên đăng nhập, push token, trạng thái 2FA, bootstrap (tải 1 lần khi mở app)."""
from datetime import timedelta

from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError
from django.db.models import OuterRef, Subquery
from django.utils import timezone

from smartlock import services
from smartlock.api.common import api, ApiError, claim_fcm_token, iso, ok, read_json, s, uuid_or_404
from smartlock.models import (
    AccessCard, Announcement, AuditLog, Device, DeviceStatusLog, MobileSession, Notification,
    TwoFactorConfig,
)

from .serializers import device_json, notification_json, session_json, user_json


@api('GET', 'PATCH')
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


@api('POST')
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
    try:
        validate_password(new, user)
    except ValidationError as e:
        raise ApiError('WEAK_PASSWORD', ' '.join(e.messages), 400, field='new_password')
    user.set_password(new)
    user.save()
    others = 0
    for m in MobileSession.objects.filter(user=user, revoked_at__isnull=True).exclude(pk=request.api_session.pk):
        m.revoke()
        others += 1
    services.audit(request, 'PASSWORD_CHANGED', severity='warning', target_user=user,
                   metadata={'channel': 'mobile', 'revoked_other_sessions': others})
    services.notify(user, 'Mật khẩu đã thay đổi', 'Bạn vừa đổi mật khẩu tài khoản.', severity='warning',
                    type_='SECURITY')
    return ok({'revoked_other_sessions': others})


@api('GET')
def sessions_list(request):
    qs = MobileSession.objects.filter(user=request.user, revoked_at__isnull=True,
                                      expires_at__gt=timezone.now()).order_by('-created_at')
    return ok({'sessions': [session_json(m, request.api_session.id) for m in qs]})


@api('DELETE')
def session_revoke(request, session_id):
    m = MobileSession.objects.filter(pk=uuid_or_404(session_id), user=request.user).first()
    if not m:
        raise ApiError('NOT_FOUND', 'Không tìm thấy phiên đăng nhập.', 404)
    m.revoke()
    services.audit(request, 'MOBILE_SESSION_REVOKED', metadata={'session_id': str(m.id)})
    return ok()


@api('PUT', 'DELETE')
def push_token(request):
    session = request.api_session
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


@api('GET')
def two_factor_status(request):
    cfg = TwoFactorConfig.objects.filter(user=request.user).first()
    methods = cfg.available_methods() if cfg else []
    return ok({'enabled': request.user.two_fa_enabled, 'methods': methods,
               'usable_in_app': [m for m in methods if m in ('totp', 'email')],
               'manage_on_web': True})


@api('GET')
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
