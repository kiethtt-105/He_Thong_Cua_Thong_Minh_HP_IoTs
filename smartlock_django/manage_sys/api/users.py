# manage_sys/api/users.py
from datetime import timedelta

from django.db import transaction
from django.db.models import Count, Q
from django.shortcuts import get_object_or_404
from django.utils import timezone

from smartlock import services
from smartlock.models import AuditLog, Device, DeviceAccess, User

from .. import views as legacy
from . import serializers as S
from .common import ApiError, ok, paginate, confirm_sensitive, get_body, as_bool, require_full_power, route

audit, notify = legacy.audit, legacy.notify


def _target(request, user_id, *, modify=True):
    target = get_object_or_404(User, id=user_id)
    if modify:
        reason = legacy.modify_denied_reason(request.user, target)
        if reason:
            raise ApiError('forbidden', reason, 403)
    return target


def list_users(request):
    qs = User.objects.annotate(device_count=Count('device', distinct=True)).order_by('-created_at')
    q = (request.GET.get('q') or '').strip()
    if q:
        qs = qs.filter(Q(email__icontains=q) | Q(username__icontains=q) | Q(full_name__icontains=q)
                       | Q(phone__icontains=q))
        if not request.GET.get('page'):
            audit(request, 'MANAGE_SEARCH_USERS', metadata={'q': q[:80]})
    status, now = request.GET.get('status') or '', timezone.now()
    flt = {'active': Q(is_active=True), 'inactive': Q(is_active=False),
           'unverified': Q(is_active=False, email_verified=False), 'locked': Q(login_locked_until__gt=now),
           'admin': Q(is_admin=True) | Q(is_staff=True) | Q(is_superuser=True)}
    if status in flt:
        qs = qs.filter(flt[status])
    locked = set()

    def ser(u):
        return S.user_item(u, locked=u.pk in locked)
    # tính locked cho cả trang: lấy trang trước rồi truy vấn 1 lần
    items, meta = paginate(request, qs, lambda u: u)
    locked = set(User.objects.filter(pk__in=[u.pk for u in items], login_locked_until__gt=now)
                 .values_list('pk', flat=True))
    return ok([ser(u) for u in items], meta=meta)


def get_user(request, user_id):
    target = _target(request, user_id, modify=False)
    audit(request, 'MANAGE_VIEW_USER', target_user=target)
    now = timezone.now()
    owned = Device.objects.filter(owner=target)
    return ok({
        **S.user_full(target, is_locked=bool(target.login_locked_until and target.login_locked_until > now),
                      owned_count=owned.count()),
        'deny_reason': legacy.modify_denied_reason(request.user, target),
        'can_sensitive': legacy.has_full_power(request.user),
        'devices': [S.device_item(d) for d in owned.select_related('owner').order_by('name')],
        'accesses': [{'device': {'id': str(a.device_id), 'name': a.device.name, 'device_code': a.device.device_code},
                      'created_at': S.iso(a.created_at), 'expires_at': S.iso(a.expires_at)}
                     for a in DeviceAccess.objects.filter(user=target, is_active=True)
                     .select_related('device').order_by('-created_at')[:10]],
        'login_attempts': [S.login_attempt_item(a) for a in legacy.login_attempts_qs()
                           .filter(Q(actor_user=target) | Q(target_user=target))
                           .select_related('actor_user', 'target_user').order_by('-created_at')[:10]],
        'logs': [S.audit_item(a) for a in AuditLog.objects.filter(Q(actor_user=target) | Q(target_user=target))
                 .select_related('actor_user', 'target_user', 'device').order_by('-created_at')[:10]],
    })


def _set_active(request, user_id, active):
    target = _target(request, user_id)
    if target.is_active == active:
        return ok({'is_active': active, 'changed': False})
    with transaction.atomic():
        if not active and legacy._would_orphan_superusers(target):
            raise ApiError('conflict', 'Không thể vô hiệu hóa superuser cuối cùng của hệ thống.', 409)
        target.is_active = active
        target.save(update_fields=['is_active', 'updated_at'])
    revoked = 0 if active else legacy.revoke_mobile_sessions(target)
    audit(request, 'MANAGE_USER_ACTIVATED' if active else 'MANAGE_USER_DEACTIVATED', target_user=target,
          severity='info' if active else 'warning', metadata=None if active else {'mobile_sessions_revoked': revoked})
    return ok({'is_active': active, 'changed': True, 'mobile_sessions_revoked': revoked})


def activate(request, user_id):
    return _set_active(request, user_id, True)


def deactivate(request, user_id):
    return _set_active(request, user_id, False)


def unlock(request, user_id):
    target = _target(request, user_id)
    services.reset_lockout(target)
    audit(request, 'MANAGE_USER_UNLOCKED', target_user=target)
    notify(target, 'Tài khoản đã được mở khóa',
           'Quản trị viên đã mở khóa đăng nhập cho tài khoản của bạn.', type_='SECURITY')
    return ok({'unlocked': True})


def reset_link(request, user_id):
    """Chỉ GỬI link đặt lại mật khẩu tới email user; admin không thấy link, không đặt mật khẩu trực tiếp."""
    target = _target(request, user_id)
    body = get_body(request)
    if not target.is_active or not target.email_verified:
        raise ApiError('conflict', 'Chỉ gửi được cho tài khoản đang hoạt động và đã xác thực email.', 409)
    if not as_bool(body.get('user_requested')):
        raise ApiError('validation_error', 'Hãy xác nhận người dùng đã yêu cầu đặt lại mật khẩu.', 400,
                       {'user_requested': 'required'})
    if AuditLog.objects.filter(action='MANAGE_RESET_LINK_SENT', target_user=target,
                               created_at__gte=timezone.now() - timedelta(seconds=legacy.RESET_LINK_COOLDOWN)).exists():
        raise ApiError('rate_limited', f'Vừa gửi link cho người này. Chờ {legacy.RESET_LINK_COOLDOWN} giây rồi thử lại.', 429)
    sent = services.send_password_reset(request, target, by_admin=request.user)
    audit(request, 'MANAGE_RESET_LINK_SENT', target_user=target, success=sent, severity='warning',
          metadata=None if sent else {'error': 'send_mail_failed'})
    if not sent:
        raise ApiError('mail_failed', 'Không gửi được email. Kiểm tra cấu hình SMTP rồi thử lại.', 502)
    notify(target, 'Đã gửi liên kết đặt lại mật khẩu',
           'Quản trị viên đã gửi liên kết đặt lại mật khẩu tới email của bạn theo yêu cầu. '
           'Nếu bạn không yêu cầu, hãy bỏ qua email đó và liên hệ quản trị viên.', severity='warning', type_='SECURITY')
    return ok({'sent_to': services.mask_email(target.email)})


def grant_admin(request, user_id):
    target = _target(request, user_id)
    require_full_power(request, 'grant_admin')
    confirm_sensitive(request, get_body(request), target.email)
    if not target.is_active:
        raise ApiError('conflict', 'Hãy kích hoạt tài khoản trước khi cấp quyền quản trị.', 409)
    owned = Device.objects.filter(owner=target).count()
    if owned:
        raise ApiError('conflict', f'Tài khoản đang là chủ của {owned} khoá. Tài khoản quản trị không được làm '
                                   'chủ khoá nên hãy gỡ chủ các khoá đó trước.', 409)
    try:
        with transaction.atomic():
            target.is_admin = True
            target.save(update_fields=['is_admin', 'updated_at'])
            audit(request, 'MANAGE_ROLE_GRANTED', target_user=target, severity='critical', strict=True)
    except services.AuditWriteError:
        raise ApiError('audit_failed', legacy.AUDIT_ERROR, 500)
    notify(target, 'Bạn được cấp quyền quản trị',
           'Tài khoản của bạn vừa được cấp quyền quản trị. Nếu bạn không biết việc này, hãy liên hệ Superuser ngay.',
           severity='warning', type_='SECURITY')
    return ok({'role': S.role_of(target)})


def revoke_admin(request, user_id):
    target = _target(request, user_id)
    require_full_power(request, 'revoke_admin')
    confirm_sensitive(request, get_body(request), target.email)
    if not legacy.has_manage_role(target):
        raise ApiError('conflict', 'Tài khoản này không có quyền quản trị để thu hồi.', 409)
    try:
        with transaction.atomic():
            if legacy._would_orphan_superusers(target):
                raise ApiError('conflict', 'Không thể thu hồi quyền của superuser cuối cùng của hệ thống.', 409)
            target.is_admin = target.is_staff = target.is_superuser = False
            target.save(update_fields=['is_admin', 'is_staff', 'is_superuser', 'updated_at'])
            audit(request, 'MANAGE_ROLE_REVOKED', target_user=target, severity='critical', strict=True)
    except services.AuditWriteError:
        raise ApiError('audit_failed', legacy.AUDIT_ERROR, 500)
    revoked = legacy.revoke_mobile_sessions(target)
    notify(target, 'Quyền quản trị đã bị thu hồi', 'Tài khoản của bạn không còn quyền quản trị.',
           severity='warning', type_='SECURITY')
    return ok({'role': S.role_of(target), 'mobile_sessions_revoked': revoked})


users_view = route({'GET': list_users})
user_detail_view = route({'GET': get_user})
user_activate_view = route({'POST': activate})
user_deactivate_view = route({'POST': deactivate})
user_unlock_view = route({'POST': unlock})
user_reset_link_view = route({'POST': reset_link})
user_grant_admin_view = route({'POST': grant_admin})
user_revoke_admin_view = route({'POST': revoke_admin})
