"""Decorator @api: kiểm tra method, xác thực Bearer (tuỳ chọn), bắt ApiError -> JSON chuẩn.

Không dùng cookie/session => không cần CSRF, mọi view đều @csrf_exempt.
"""
import logging
from functools import wraps

from django.views.decorators.csrf import csrf_exempt

from .http import ApiError, fail
from .sessions import authenticate_request

logger = logging.getLogger('smartlock.api')


def api(*methods, auth=True):
    """Bọc view API: kiểm tra method, xác thực Bearer (nếu auth=True), bắt ApiError -> JSON chuẩn."""
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
                if auth:
                    authenticate_request(request)
                return fn(request, *args, **kwargs)
            except ApiError as exc:
                return fail(exc.code, exc.message, exc.status, **exc.extra)
            except Exception:
                logger.exception('API lỗi không mong đợi: %s %s', request.method, request.path)
                return fail('SERVER_ERROR', 'Lỗi máy chủ. Vui lòng thử lại sau.', 500)
        return wrapper
    return deco
