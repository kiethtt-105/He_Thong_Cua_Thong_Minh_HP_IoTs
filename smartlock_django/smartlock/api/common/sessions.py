"""Phiên đăng nhập dùng chung cho APP và WEB.

APP : access token (15 phút) + refresh token xoay vòng (MobileSession), challenge 2FA, FCM token.
WEB : session cookie của Django + header X-CSRFToken (đăng nhập bằng web_login).
"""
import secrets
from datetime import timedelta

from django.contrib.auth import login as django_login
from django.core import signing
from django.db import transaction
from django.middleware.csrf import CsrfViewMiddleware
from django.utils import timezone

from smartlock import services
from smartlock.models import MobileSession

from .http import ApiError, iso, s


ACCESS_TTL_SECONDS = 15 * 60


CHALLENGE_TTL_SECONDS = 5 * 60            # thời gian được phép nhập mã 2FA sau khi qua bước mật khẩu


REFRESH_RACE_GRACE_SECONDS = 15           # dùng lại refresh token cũ trong khoảng này = lỗi mạng/đua, không phải trộm


PLATFORMS = ('android', 'ios')


_ACCESS_SALT = 'smartlock.api.access.v1'


_CHALLENGE_SALT = 'smartlock.api.2fa-challenge.v1'


def issue_access_token(session) -> str:
    return signing.dumps({'sid': str(session.id), 'uid': str(session.user_id)},
                         salt=_ACCESS_SALT, compress=True)


def new_refresh_token() -> str:
    return secrets.token_urlsafe(48)


def hash_refresh(token: str) -> str:
    return services.hash_token(token)           # sha256 hex = 64 ký tự, khớp MobileSession.refresh_hash


def token_payload(session, refresh_token: str) -> dict:
    return {
        'token_type': 'Bearer',
        'access_token': issue_access_token(session),
        'expires_in': ACCESS_TTL_SECONDS,
        'refresh_token': refresh_token,
        'refresh_expires_at': iso(session.expires_at),
        'session_id': str(session.id),
    }


def make_challenge(user, info: dict) -> str:
    return signing.dumps({'uid': str(user.id), 'info': info}, salt=_CHALLENGE_SALT, compress=True)


def read_challenge(token: str):
    try:
        return signing.loads(token or '', salt=_CHALLENGE_SALT, max_age=CHALLENGE_TTL_SECONDS)
    except signing.SignatureExpired:
        raise ApiError('CHALLENGE_EXPIRED', 'Phiên xác thực 2 lớp đã hết hạn. Hãy đăng nhập lại.', 401)
    except signing.BadSignature:
        raise ApiError('CHALLENGE_INVALID', 'Phiên xác thực 2 lớp không hợp lệ.', 401)


def device_info(data: dict) -> dict:
    """Thông tin thiết bị di động client gửi kèm lúc đăng nhập."""
    platform = s(data, 'platform', 20).lower()
    return {
        'device_name': s(data, 'device_name', 100),
        'platform': platform if platform in PLATFORMS else 'android',
        'app_version': s(data, 'app_version', 30),
        'fcm_token': s(data, 'fcm_token', 512),
    }


def create_session(request, user, info: dict):
    """Tạo MobileSession + bộ token. Trả (session, payload)."""
    now = timezone.now()
    refresh = new_refresh_token()
    session = MobileSession.objects.create(
        user=user, refresh_hash=hash_refresh(refresh),
        device_name=info.get('device_name', ''), platform=info.get('platform', 'android'),
        app_version=info.get('app_version', ''), fcm_token=info.get('fcm_token', ''),
        ip_address=services.client_ip(request), last_used_at=now,
        expires_at=now + timedelta(seconds=services.user_session_seconds()),
    )
    claim_fcm_token(session, info.get('fcm_token', ''))
    return session, token_payload(session, refresh)


def claim_fcm_token(session, token: str):
    """Một FCM token chỉ thuộc 1 phiên (tránh bắn push trùng sau khi đăng xuất/đăng nhập lại)."""
    if not token:
        return
    MobileSession.objects.filter(fcm_token=token).exclude(pk=session.pk).update(fcm_token='')
    if session.fcm_token != token:
        session.fcm_token = token
        session.save(update_fields=['fcm_token'])


def _bearer(request):
    parts = (request.META.get('HTTP_AUTHORIZATION') or '').split()
    return parts[1] if len(parts) == 2 and parts[0].lower() == 'bearer' else ''


def authenticate_request(request):
    token = _bearer(request)
    if not token:
        raise ApiError('UNAUTHENTICATED', 'Thiếu access token.', 401)
    try:
        data = signing.loads(token, salt=_ACCESS_SALT, max_age=ACCESS_TTL_SECONDS)
    except signing.SignatureExpired:
        raise ApiError('TOKEN_EXPIRED', 'Access token đã hết hạn. Hãy làm mới bằng refresh token.', 401)
    except signing.BadSignature:
        raise ApiError('TOKEN_INVALID', 'Access token không hợp lệ.', 401)

    sid, uid = services.parse_uuid(data.get('sid')), services.parse_uuid(data.get('uid'))
    session = (MobileSession.objects.select_related('user').filter(pk=sid).first()) if sid else None
    if not session or not session.is_active or session.user_id != uid:
        raise ApiError('SESSION_REVOKED', 'Phiên đăng nhập đã bị thu hồi hoặc hết hạn.', 401)   # thu hồi có hiệu lực NGAY
    user = session.user
    if not user.is_active or services.is_admin(user):
        raise ApiError('ACCOUNT_DISABLED', 'Tài khoản không được phép dùng app.', 403)
    request.user = user                  # để services.audit(request, ...) tự nhận actor
    request.api_session = session
    request.client_type = 'app'


_SAFE_METHODS = ('GET', 'HEAD', 'OPTIONS', 'TRACE')


def _check_csrf(request):
    """Web dùng cookie => request ghi dữ liệu phải có header X-CSRFToken (cùng cơ chế CSRF của Django).
    Các view API đều @csrf_exempt (để Bearer của app không cần CSRF) nên ở đây kiểm tra thủ công."""
    reason = CsrfViewMiddleware(lambda r: None).process_view(request, None, (), {})
    if reason is not None:
        raise ApiError('CSRF_FAILED', 'Phiên làm việc không hợp lệ (CSRF). Hãy tải lại trang.', 403)


check_csrf = _check_csrf          # tên công khai: login/2FA của web (chưa có session) cũng phải qua CSRF


WEB_AUTH_BACKEND = 'django.contrib.auth.backends.ModelBackend'


def web_login(request, user):
    """Đăng nhập WEB bằng session cookie (giống hệt login_view/_complete của trang HTML):
    đăng nhập Django, cấp sync_key cho cache dashboard, đặt hạn phiên theo SystemSettings."""
    django_login(request, user, backend=getattr(user, 'backend', None) or WEB_AUTH_BACKEND)
    request.session['sync_key'] = secrets.token_urlsafe(32)
    request.session.set_expiry(services.user_session_seconds())


def authenticate_web_session(request):
    """Web: người dùng đã đăng nhập bằng session cookie của Django (user thường, KHÔNG phải admin)."""
    user = getattr(request, 'user', None)
    if user is None or not user.is_authenticated:
        raise ApiError('UNAUTHENTICATED', 'Bạn chưa đăng nhập.', 401)
    if not user.is_active or services.is_admin(user):
        raise ApiError('ACCOUNT_DISABLED', 'Tài khoản không được phép dùng chức năng này.', 403)
    if request.method not in _SAFE_METHODS:
        _check_csrf(request)
    request.api_session = None           # web không có MobileSession
    request.client_type = 'web'


def authenticate_any(request):
    """Có header Authorization: Bearer => app (bắt buộc hợp lệ, không rơi về cookie); không có => web (cookie)."""
    if _bearer(request):
        return authenticate_request(request)
    return authenticate_web_session(request)


def revoke_session(session, reason=''):
    session.revoke()
    return session


def revoke_all_sessions(user, exclude=None) -> int:
    """Thu hồi mọi phiên APP còn hiệu lực của user (trừ `exclude` nếu có). Trả về số phiên đã thu hồi."""
    qs = MobileSession.objects.filter(user=user, revoked_at__isnull=True)
    if exclude is not None:
        qs = qs.exclude(pk=exclude.pk)
    n = 0
    for m in qs:
        m.revoke()
        n += 1
    return n


def rotate_refresh(request, refresh_token: str, fcm_token: str = ''):
    """Đổi refresh token (xoay vòng). Trả (session, payload).
    LƯU Ý: lỗi được ném SAU khối atomic - nếu ném bên trong, việc thu hồi phiên sẽ bị rollback."""
    h = hash_refresh(refresh_token or '')
    now = timezone.now()
    error = None
    session = payload = None
    with transaction.atomic():
        session = (MobileSession.objects.select_for_update().select_related('user')
                   .filter(refresh_hash=h).first())
        if session is None:
            reused = (MobileSession.objects.select_for_update().select_related('user')
                      .filter(prev_refresh_hash=h).first()) if refresh_token else None
            if reused is not None and reused.revoked_at is None:
                if reused.last_used_at and (now - reused.last_used_at).total_seconds() <= REFRESH_RACE_GRACE_SECONDS:
                    error = ApiError('REFRESH_CONFLICT',
                                     'Refresh token vừa được đổi. Hãy dùng token mới nhất đã lưu.', 409)
                else:
                    # Token cũ bị dùng lại sau khi đã xoay: nghi bị đánh cắp -> thu hồi cả phiên.
                    reused.revoke()
                    services.audit(request, 'MOBILE_REFRESH_REUSE', actor=None, target_user=reused.user,
                                   success=False, severity='critical', metadata={'session_id': str(reused.id)})
                    services.notify(reused.user, 'Phiên đăng nhập trên app bị thu hồi',
                                    'Phát hiện refresh token bị dùng lại bất thường. Phiên trên thiết bị '
                                    f'"{reused.device_name or reused.platform}" đã bị đăng xuất. '
                                    'Nếu không phải bạn, hãy đổi mật khẩu.',
                                    severity='critical', type_='SECURITY')
            if error is None:
                error = ApiError('REFRESH_INVALID', 'Refresh token không hợp lệ. Hãy đăng nhập lại.', 401)
        elif not session.is_active:
            error = ApiError('SESSION_EXPIRED', 'Phiên đã hết hạn hoặc bị thu hồi. Hãy đăng nhập lại.', 401)
        elif not session.user.is_active or services.is_admin(session.user):
            error = ApiError('ACCOUNT_DISABLED', 'Tài khoản không được phép dùng app.', 403)
        else:
            new_refresh = new_refresh_token()
            session.prev_refresh_hash = session.refresh_hash
            session.refresh_hash = hash_refresh(new_refresh)
            session.last_used_at = now
            session.expires_at = now + timedelta(seconds=services.user_session_seconds())   # trượt theo hoạt động
            session.ip_address = services.client_ip(request)
            session.save(update_fields=['prev_refresh_hash', 'refresh_hash', 'last_used_at',
                                        'expires_at', 'ip_address'])
            payload = token_payload(session, new_refresh)
    if error is not None:
        raise error
    claim_fcm_token(session, fcm_token)
    return session, payload
