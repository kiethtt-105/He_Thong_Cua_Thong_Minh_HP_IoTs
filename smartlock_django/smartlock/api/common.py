"""Lõi dùng chung: phản hồi JSON, decorator @api, token + phiên đăng nhập, serializer, helper quyền khoá."""
import json
import logging
import secrets
from datetime import timedelta
from functools import wraps

from django.contrib.auth import login as django_login
from django.core import signing
from django.core.paginator import EmptyPage, Paginator
from django.db import transaction
from django.http import JsonResponse
from django.middleware.csrf import CsrfViewMiddleware
from django.utils import timezone
from django.views.decorators.csrf import csrf_exempt

from smartlock import services
from smartlock.models import MobileSession


# ======================================================================
# CORE: JSON, decorator @api, token, phiên đăng nhập
# ======================================================================

# ----- http: Phản hồi JSON chuẩn (ok/fail/ApiError) + đọc/kiểm tra dữ liệu vào + phân trang.
# ======================================================================

MAX_BODY_BYTES = 256 * 1024


class ApiError(Exception):
    def __init__(self, code, message, status=400, **extra):
        super().__init__(message)
        self.code, self.message, self.status, self.extra = code, message, status, extra


def ok(data=None, status=200, **extra):
    resp = JsonResponse({'ok': True, **(data or {}), **extra}, status=status)
    resp['Cache-Control'] = 'no-store'
    return resp


def fail(code, message, status=400, **extra):
    resp = JsonResponse({'ok': False, 'error': {'code': code, 'message': message, **extra}}, status=status)
    resp['Cache-Control'] = 'no-store'
    return resp


def read_json(request) -> dict:
    if len(request.body) > MAX_BODY_BYTES:
        raise ApiError('PAYLOAD_TOO_LARGE', 'Dữ liệu gửi lên quá lớn.', 413)
    if not request.body:
        return {}
    try:
        data = json.loads(request.body.decode('utf-8'))
    except (ValueError, UnicodeDecodeError):
        raise ApiError('BAD_JSON', 'Nội dung phải là JSON hợp lệ (UTF-8).', 400)
    if not isinstance(data, dict):
        raise ApiError('BAD_JSON', 'Nội dung JSON phải là một object.', 400)
    return data


def s(data, key, max_len=255, required=False) -> str:
    """Lấy chuỗi đã strip + cắt độ dài."""
    val = data.get(key)
    val = '' if val is None else str(val).strip()
    if required and not val:
        raise ApiError('MISSING_FIELD', f'Thiếu trường "{key}".', 400, field=key)
    return val[:max_len]


def uuid_or_404(value):
    u = services.parse_uuid(value)
    if not u:
        raise ApiError('NOT_FOUND', 'Không tìm thấy dữ liệu.', 404)
    return u


def parse_iso(value, field='expires_at'):
    """Chấp nhận ISO-8601 (có/không múi giờ; không múi giờ = giờ máy chủ). Rỗng -> None."""
    if value in (None, ''):
        return None
    from django.utils.dateparse import parse_datetime
    dt = parse_datetime(str(value))
    if dt is None:
        raise ApiError('BAD_DATETIME', f'"{field}" phải theo định dạng ISO-8601 (vd 2026-10-05T18:00:00+07:00).',
                       400, field=field)
    if timezone.is_naive(dt):
        dt = timezone.make_aware(dt)
    return dt


def paginate(request, queryset, serializer, default_size=20, max_size=100) -> dict:
    try:
        page = max(1, int(request.GET.get('page') or 1))
        size = max(1, min(max_size, int(request.GET.get('page_size') or default_size)))
    except ValueError:
        raise ApiError('BAD_PAGINATION', 'page / page_size phải là số nguyên.', 400)
    paginator = Paginator(queryset, size)
    try:
        pg = paginator.page(page)
    except EmptyPage:
        return {'items': [], 'page': page, 'page_size': size, 'total': paginator.count, 'has_next': False}
    return {'items': [serializer(o) for o in pg.object_list], 'page': page, 'page_size': size,
            'total': paginator.count, 'has_next': pg.has_next()}


def iso(dt):
    return dt.isoformat() if dt else None


# ======================================================================
# decorators.py - Decorator @api: kiểm tra method, xác thực, bắt ApiError -> JSON chuẩn.
# ======================================================================

logger = logging.getLogger('smartlock.api')


def api(*methods, auth=True):
    """Bọc view API: kiểm tra method, xác thực theo `auth` (True | 'any' | False), bắt ApiError -> JSON chuẩn."""
    allowed = tuple(m.upper() for m in methods)

    def deco(fn):
        @csrf_exempt
        @wraps(fn)
        def wrapper(request, *args, **kwargs):
            if request.method not in allowed:
                resp = fail('METHOD_NOT_ALLOWED', 'Phương thức không được hỗ trợ.', 405)
                resp['Allow'] = ', '.join(allowed)
                return resp
            try:
                if auth == 'any':
                    authenticate_any(request)
                elif auth:
                    authenticate_request(request)
                return fn(request, *args, **kwargs)
            except ApiError as exc:
                return fail(exc.code, exc.message, exc.status, **exc.extra)
            except Exception:
                logger.exception('API lỗi không mong đợi: %s %s', request.method, request.path)
                return fail('SERVER_ERROR', 'Lỗi máy chủ. Vui lòng thử lại sau.', 500)
        return wrapper
    return deco


# ======================================================================
# sessions.py - Phiên đăng nhập dùng chung cho APP và WEB.
# ======================================================================

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
    return qs.update(revoked_at=timezone.now(), fcm_token='')      # 1 câu UPDATE thay vì lặp từng phiên


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


# ======================================================================
# SERIALIZER + HELPER lấy khoá / kiểm tra quyền
# ======================================================================

# ======================================================================
# serializers.py - Chuyển model -> dict JSON trả về cho app.
# ======================================================================

def user_json(u) -> dict:
    return {
        'id': str(u.id), 'email': u.email, 'username': u.username, 'full_name': u.full_name or '',
        'phone': u.phone or '', 'avatar_url': u.avatar_url or '', 'email_verified': u.email_verified,
        'two_fa_enabled': u.two_fa_enabled, 'created_at': iso(u.created_at),
    }


def device_json(d, user, perms, lock_state=None) -> dict:
    is_owner = d.owner_id == user.id
    owner = d.owner if d.owner_id else None
    return {
        'id': str(d.id), 'name': d.name, 'device_code': d.device_code, 'device_mode': d.device_mode,
        'status': d.status, 'status_display': d.get_status_display(),
        'battery_level': d.battery_level, 'lock_state': lock_state or 'unknown',
        'location': d.location or '', 'firmware_version': d.firmware_version or '',
        'mac_address': d.mac_address or '', 'last_seen_at': iso(d.last_seen_at),
        'wifi_enabled': d.wifi_enabled, 'bluetooth_enabled': d.bluetooth_enabled, 'nfc_enabled': d.nfc_enabled,
        'is_owner': is_owner,
        'owner_name': (owner.full_name or owner.username) if owner else '',
        'permissions': sorted(perms), 'updated_at': iso(d.updated_at),
    }


def command_json(c) -> dict:
    return {
        'id': str(c.id), 'device_id': str(c.device_id), 'command': c.command_type, 'status': c.status,
        'created_at': iso(c.created_at), 'expires_at': iso(c.expires_at),
        'acknowledged_at': iso(c.acknowledged_at),
    }


def event_json(e) -> dict:
    return {
        'id': str(e.id), 'device_id': str(e.device_id), 'device_name': e.device.name,
        'method': e.method, 'success': e.success, 'reason': e.reason or '',
        'who': (e.user.full_name or e.user.username) if e.user_id else '',
        'confidence': e.confidence, 'snapshot_url': e.snapshot_url or '', 'created_at': iso(e.created_at),
    }


def notification_json(n) -> dict:
    return {
        'id': str(n.id), 'type': n.type, 'title': n.title, 'message': n.message, 'severity': n.severity,
        'is_read': n.is_read, 'device_id': str(n.device_id) if n.device_id else None,
        'created_at': iso(n.created_at), 'read_at': iso(n.read_at),
    }


def session_json(m, current_id) -> dict:
    return {
        'id': str(m.id), 'device_name': m.device_name, 'platform': m.platform, 'app_version': m.app_version,
        'ip_address': m.ip_address, 'created_at': iso(m.created_at), 'last_used_at': iso(m.last_used_at),
        'expires_at': iso(m.expires_at), 'push_enabled': m.push_enabled, 'has_push_token': bool(m.fcm_token),
        'is_current': m.id == current_id,
    }


def announcement_json(a) -> dict:
    return {'id': str(a.id), 'title': a.title, 'body': a.body, 'level': a.level, 'created_at': iso(a.created_at)}


# ======================================================================
# helpers.py - Hàm dùng chung: lấy khoá theo quyền (chủ / quyền được chia sẻ).
# ======================================================================

def get_device(request, device_id):
    d = (services.accessible_devices(request.user).select_related('owner')
         .filter(pk=uuid_or_404(device_id)).first())
    if not d:
        raise ApiError('DEVICE_NOT_FOUND', 'Không tìm thấy khoá.', 404)
    return d


def need_owner(request, device, action='DEVICE_ACTION'):
    if device.owner_id != request.user.id:
        services.audit(request, f'{action}_DENIED', device=device, success=False, severity='warning')
        raise ApiError('OWNER_ONLY', 'Chỉ chủ khoá mới được thực hiện thao tác này.', 403)


def _need_perm(request, device, code, action='DEVICE_ACTION'):
    if not services.has_permission(request.user, device, code):
        services.audit(request, f'{action}_DENIED', device=device, success=False, severity='warning')
        raise ApiError('FORBIDDEN', 'Bạn không có quyền thực hiện thao tác này.', 403, permission=code)


def managed_device(request, device_id, code):
    """Khoá mà user có quyền `code` (chủ luôn có). 404 nếu không thấy, 403 nếu thiếu quyền."""
    device = get_device(request, device_id)
    _need_perm(request, device, code)
    return device
