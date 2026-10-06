# manage_sys/api/auth.py
"""Đăng nhập / đăng xuất / hồ sơ cho API quản trị. Logic đăng nhập giống hệt legacy.login_view
(1 thông báo lỗi chung, chống dò thời gian, khoá tạm, ghi AuditLog, báo IP mới)."""
from django.contrib.auth import BACKEND_SESSION_KEY, authenticate, login, logout
from django.contrib.auth.models import update_last_login
from django.middleware.csrf import get_token
from django.utils import timezone

from .. import views as legacy
from . import serializers as S
from .common import ApiError, TOKEN_MAX_AGE, TOKEN_STARTED, _session_store, _user_from_token, \
    get_body, issue_token, ok, revoke_token, route


def _me(user):
    return {**S.user_brief(user), 'role': S.role_of(user), 'is_superuser': user.is_superuser,
            'can_sensitive': legacy.has_full_power(user),
            'session_seconds': legacy.SESSION_SECONDS}


def csrf(request):
    """Web: gọi 1 lần trước khi ghi để nhận cookie csrftoken; gửi lại giá trị trong header X-CSRFToken."""
    return ok({'csrf_token': get_token(request)})


def login_api(request):
    body = get_body(request)
    identifier = str(body.get('identifier') or '').strip()
    password = str(body.get('password') or '')
    client = str(body.get('client') or 'web').lower()          # 'web' => cookie phiên; 'app' => Bearer token
    if client not in ('web', 'app'):
        raise ApiError('validation_error', "client phải là 'web' hoặc 'app'.", 400, {'client': 'invalid'})
    if not identifier or not password:
        raise ApiError('validation_error', 'Vui lòng điền đầy đủ thông tin.', 400)

    ip = legacy.client_ip(request)
    user = legacy._find_user(identifier)
    is_mgr = bool(user and legacy.has_manage_role(user))

    if is_mgr and legacy.lock_remaining_minutes(user):
        legacy.burn_password_hash(password)
        legacy.audit(request, 'MANAGE_LOGIN_LOCKED', actor=None, target_user=user, success=False,
                     severity='warning', username_attempt=identifier[:150])
        raise ApiError('login_failed', legacy.LOGIN_ERROR, 401)

    if user:
        auth_user = authenticate(request, username=user.email, password=password)
    else:
        legacy.burn_password_hash(password)
        auth_user = None

    if not (auth_user and legacy.has_manage_role(auth_user)):
        if is_mgr and not auth_user:
            legacy.register_failure(user, ip)
        legacy.audit(request, 'MANAGE_LOGIN_DENIED' if auth_user else 'MANAGE_LOGIN_FAILED', actor=None,
                     target_user=user, success=False, severity='warning', username_attempt=identifier[:150])
        raise ApiError('login_failed', legacy.LOGIN_ERROR, 401)

    new_ip = legacy.is_new_login_ip(auth_user, ip)      # tính TRƯỚC khi ghi MANAGE_LOGIN của lần này
    legacy.reset_lockout(auth_user)
    out = {'user': _me(auth_user), 'client': client}
    if client == 'app':
        token, expires = issue_token(auth_user)
        update_last_login(None, auth_user)
        request.user = auth_user                         # để audit() ghi đúng actor
        out.update(token=token, token_type='Bearer', expires_at=S.iso(expires))
    else:
        login(request, auth_user)
        request.session.set_expiry(legacy.SESSION_SECONDS)
        out['csrf_token'] = get_token(request)
    legacy.audit(request, 'MANAGE_LOGIN', actor=auth_user, metadata={'client': client})
    if new_ip:
        legacy.notify(auth_user, 'Đăng nhập quản trị từ IP mới',
                      f'Tài khoản vừa đăng nhập trang quản trị từ IP {ip} (chưa từng thấy). '
                      'Nếu không phải bạn, hãy đổi mật khẩu ngay.', severity='warning', type_='SECURITY')
    return ok(out)


def logout_api(request):
    legacy.audit(request, 'MANAGE_LOGOUT')
    if request.api_mode == 'bearer':
        revoke_token(request.api_token)
    else:
        logout(request)                                  # chỉ huỷ phiên admin, không đụng phiên user
    return ok({'logged_out': True})


def me(request):
    return ok(_me(request.user))


def refresh(request):
    """Chỉ cho Bearer: cấp token mới, huỷ token cũ. Tổng thời gian sống bị chặn bởi MANAGE_SYS_API_TOKEN_MAX_SECONDS."""
    if request.api_mode != 'bearer':
        raise ApiError('bad_request', 'Chỉ áp dụng cho Bearer token (app).', 400)
    _, store = _user_from_token(request.api_token)
    started = store.get(TOKEN_STARTED, 0) if store else 0
    if timezone.now().timestamp() - started > TOKEN_MAX_AGE:
        revoke_token(request.api_token)
        raise ApiError('unauthorized', 'Phiên đã quá thời hạn tối đa, hãy đăng nhập lại.', 401)
    user = request.user
    user.backend = store.get(BACKEND_SESSION_KEY)
    revoke_token(request.api_token)
    token, expires = issue_token(user)
    # giữ mốc bắt đầu ban đầu để trần tuyệt đối không bị "xin gia hạn mãi"
    s = _session_store(token)
    s[TOKEN_STARTED] = started
    s.save()
    return ok({'token': token, 'token_type': 'Bearer', 'expires_at': S.iso(expires)})


login_view = route({'POST': login_api}, auth=False)
csrf_view = route({'GET': csrf}, auth=False)
logout_view = route({'POST': logout_api})
me_view = route({'GET': me})
refresh_view = route({'POST': refresh})
