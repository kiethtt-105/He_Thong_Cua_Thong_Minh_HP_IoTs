# manage_sys/api/common.py
"""
Lớp nền của API quản trị (v1), dùng CHUNG cho web và app.

Hai kiểu xác thực:
  * Web : cookie phiên riêng `manage_sys_sessionid` (do ManageSysSessionCookieMiddleware quản lý)
          + bắt buộc header X-CSRFToken với mọi request ghi (POST/PUT/PATCH/DELETE).
  * App : header `Authorization: Bearer <token>`. Token là khoá của 1 phiên Django server-side
          (SESSION_ENGINE phải là db/cache/file, KHÔNG phải signed_cookies), có cờ riêng
          `manage_api_token` nên khoá phiên của user thường không dùng được ở đây.
          Bearer không tự động gửi bởi trình duyệt => không cần CSRF.

Mọi request đều kiểm tra lại: user còn active + còn quyền quản trị (đổi mật khẩu / bị khoá => token chết).

Định dạng phản hồi:
  thành công: {"ok": true, "data": ..., "meta": {...}}
  thất bại  : {"ok": false, "error": {"code": "...", "message": "...", "fields": {...}}}
"""
import json
import time
from functools import wraps
from importlib import import_module

from django.conf import settings
from django.contrib.auth import BACKEND_SESSION_KEY, HASH_SESSION_KEY, SESSION_KEY, load_backend
from django.core.paginator import EmptyPage, Paginator
from django.http import JsonResponse
from django.middleware.csrf import CsrfViewMiddleware
from django.utils.crypto import constant_time_compare
from django.views.decorators.csrf import csrf_exempt

from .. import views as legacy   # dùng lại phân quyền / helper của trang quản trị (một nguồn duy nhất)

TOKEN_FLAG = 'manage_api_token'
TOKEN_STARTED = 'manage_api_started'
TOKEN_SECONDS = getattr(settings, 'MANAGE_SYS_API_TOKEN_SECONDS', 2 * 3600)
TOKEN_MAX_AGE = getattr(settings, 'MANAGE_SYS_API_TOKEN_MAX_SECONDS', 7 * 24 * 3600)   # trần tuyệt đối khi refresh
MAX_PAGE_SIZE = 100
DEFAULT_PAGE_SIZE = 20


# ----------------------------------------------------------------------------- phản hồi
class ApiError(Exception):
    def __init__(self, code, message, status=400, fields=None):
        super().__init__(message)
        self.code, self.message, self.status, self.fields = code, message, status, fields


def ok(data=None, *, meta=None, status=200):
    body = {'ok': True, 'data': data}
    if meta is not None:
        body['meta'] = meta
    return JsonResponse(body, status=status, json_dumps_params={'ensure_ascii': False})


def fail(code, message, status=400, fields=None):
    err = {'code': code, 'message': message}
    if fields:
        err['fields'] = fields
    return JsonResponse({'ok': False, 'error': err}, status=status, json_dumps_params={'ensure_ascii': False})


# ----------------------------------------------------------------------------- đọc dữ liệu vào
def get_body(request):
    """Body JSON (dict). Form-encoded cũng được chấp nhận (tiện test)."""
    ctype = (request.META.get('CONTENT_TYPE') or '').split(';')[0].strip().lower()
    if ctype == 'application/json':
        try:
            data = json.loads(request.body.decode('utf-8') or '{}')
        except (ValueError, UnicodeDecodeError):
            raise ApiError('invalid_json', 'Body không phải JSON hợp lệ.', 400)
        if not isinstance(data, dict):
            raise ApiError('invalid_json', 'Body phải là một object JSON.', 400)
        return data
    return request.POST.dict()


def as_bool(value, default=False):
    if value is None or value == '':
        return default
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in ('1', 'true', 'yes', 'on')


def as_int(value, name, *, lo=None, hi=None):
    try:
        if isinstance(value, bool):
            raise ValueError
        n = int(value)
    except (TypeError, ValueError):
        raise ApiError('validation_error', f'{name} phải là số nguyên.', 400, {name: 'integer'})
    if (lo is not None and n < lo) or (hi is not None and n > hi):
        raise ApiError('validation_error', f'{name} phải trong khoảng {lo}..{hi}.', 400, {name: 'range'})
    return n


def paginate(request, qs, serializer, *, per_page=None):
    """Trả (list_dict, meta). Tham số: ?page=1&page_size=20 (tối đa 100)."""
    try:
        size = int(per_page or request.GET.get('page_size') or DEFAULT_PAGE_SIZE)
    except ValueError:
        size = DEFAULT_PAGE_SIZE
    size = max(1, min(size, MAX_PAGE_SIZE))
    paginator = Paginator(qs, size)
    try:
        page = paginator.page(request.GET.get('page') or 1)
    except (EmptyPage, ValueError, TypeError):
        page = paginator.page(paginator.num_pages) if paginator.count else paginator.page(1)
    meta = {'page': page.number, 'page_size': size, 'total': paginator.count,
            'pages': paginator.num_pages, 'has_next': page.has_next(), 'has_prev': page.has_previous()}
    return [serializer(o) for o in page.object_list], meta


# ----------------------------------------------------------------------------- token (app)
def _session_store(key=None):
    return import_module(settings.SESSION_ENGINE).SessionStore(session_key=key)


def issue_token(user):
    """Tạo phiên server-side mới cho app và trả (token, expires_at). `user` phải đi qua authenticate() (có .backend)."""
    store = _session_store()
    store[SESSION_KEY] = user._meta.pk.value_to_string(user)
    store[BACKEND_SESSION_KEY] = user.backend
    store[HASH_SESSION_KEY] = user.get_session_auth_hash()
    store[TOKEN_FLAG] = True
    store[TOKEN_STARTED] = int(time.time())
    store.set_expiry(TOKEN_SECONDS)
    store.create()
    return store.session_key, store.get_expiry_date()


def _user_from_token(token):
    if not token or len(token) > 128:
        return None, None
    store = _session_store(token)
    if not store.exists(token) or not store.get(TOKEN_FLAG):
        return None, None
    uid, backend_path = store.get(SESSION_KEY), store.get(BACKEND_SESSION_KEY)
    if uid is None or backend_path not in settings.AUTHENTICATION_BACKENDS:
        return None, None
    user = load_backend(backend_path).get_user(uid)          # None nếu user inactive
    if not user or not constant_time_compare(store.get(HASH_SESSION_KEY, ''), user.get_session_auth_hash()):
        return None, None                                     # đổi mật khẩu => token cũ chết
    return user, store


def revoke_token(token):
    store = _session_store(token)
    if store.exists(token):
        store.delete()


# ----------------------------------------------------------------------------- xác thực + CSRF
def _csrf_reason(request):
    check = CsrfViewMiddleware(lambda r: None)
    check.process_request(request)
    resp = check.process_view(request, None, (), {})
    return None if resp is None else 'CSRF token thiếu hoặc sai (gửi header X-CSRFToken).'


def authenticate_request(request):
    """Trả (user, mode, token). Raise ApiError 401/403 nếu không hợp lệ."""
    header = request.META.get('HTTP_AUTHORIZATION', '')
    if header[:7].lower() == 'bearer ':
        token = header[7:].strip()
        user, _ = _user_from_token(token)
        if not user:
            raise ApiError('unauthorized', 'Token không hợp lệ hoặc đã hết hạn.', 401)
        mode = 'bearer'
    else:
        user, token, mode = request.user, None, 'session'
        if not user.is_authenticated:
            raise ApiError('unauthorized', 'Chưa đăng nhập.', 401)
        if request.method not in ('GET', 'HEAD', 'OPTIONS'):
            reason = _csrf_reason(request)
            if reason:
                raise ApiError('csrf_failed', reason, 403)
    if not legacy.is_manager(user):
        raise ApiError('forbidden', 'Tài khoản không còn quyền quản trị.', 403)
    return user, mode, token


def route(handlers, *, auth=True):
    """route({'GET': fn, 'POST': fn2}) -> view. Handler nhận (request, *args) và trả JsonResponse (ok/fail)."""
    allowed = sorted(handlers)

    @csrf_exempt
    @wraps(next(iter(handlers.values())))
    def view(request, *args, **kwargs):
        fn = handlers.get(request.method)
        if fn is None:
            resp = fail('method_not_allowed', f'Chỉ hỗ trợ: {", ".join(allowed)}.', 405)
            resp['Allow'] = ', '.join(allowed)
            return resp
        try:
            if auth:
                request.user, request.api_mode, request.api_token = authenticate_request(request)
            resp = fn(request, *args, **kwargs)
        except ApiError as e:
            resp = fail(e.code, e.message, e.status, e.fields)
        resp['Cache-Control'] = 'no-store, private'
        return resp
    return view


# ----------------------------------------------------------------------------- xác nhận thao tác nguy hiểm
def require_full_power(request, action):
    denied = legacy.action_denied_reason(request.user, action)
    if denied:
        legacy.audit(request, 'MANAGE_ACTION_DENIED', success=False, severity='warning', metadata={'action': action})
        raise ApiError('forbidden', denied, 403)


def confirm_sensitive(request, data, expected, *, upper=False):
    """Giống legacy.confirm_sensitive nhưng đọc JSON: `confirm` (gõ lại email/mã thiết bị) + `current_password`."""
    typed, exp = str(data.get('confirm') or '').strip(), (expected or '').strip()
    if (typed.upper() != exp.upper()) if upper else (typed.lower() != exp.lower()):
        raise ApiError('confirm_mismatch', 'Nội dung xác nhận không khớp.', 400, {'confirm': 'mismatch'})
    user = request.user
    if legacy.lock_remaining_minutes(user):
        raise ApiError('reauth_failed', legacy.REAUTH_ERROR, 403)
    password = data.get('current_password') or ''
    if password and user.check_password(password):
        return
    legacy.register_failure(user, legacy.client_ip(request))
    legacy.audit(request, 'MANAGE_REAUTH_FAILED', success=False, severity='warning')
    raise ApiError('reauth_failed', legacy.REAUTH_ERROR, 403, {'current_password': 'invalid'})
