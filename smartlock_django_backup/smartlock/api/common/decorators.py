"""Decorator @api: kiểm tra method, xác thực, bắt ApiError -> JSON chuẩn.

auth=True   : chỉ app (Authorization: Bearer ...)             - mặc định, dành cho auth/phiên của app
auth='any'  : app (Bearer) HOẶC web (session cookie + X-CSRFToken) - endpoint dữ liệu dùng chung web/app
auth=False  : không cần đăng nhập

Mọi view đều @csrf_exempt; với nhánh cookie, CSRF được kiểm tra thủ công trong authenticate_web_session.
Sau khi xác thực: request.user, request.client_type ('app' | 'web').
"""
import logging
from functools import wraps

from django.views.decorators.csrf import csrf_exempt

from .http import ApiError, fail
from .sessions import authenticate_any, authenticate_request

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
