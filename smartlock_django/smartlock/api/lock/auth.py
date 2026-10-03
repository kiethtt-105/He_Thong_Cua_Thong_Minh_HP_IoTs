"""Xác thực khoá bằng X-Device-Code + X-Device-Secret (giới hạn thử sai theo IP + mã khoá)."""
import hmac
from functools import wraps

from django.core.cache import cache

from smartlock import services
from smartlock.api.common import api, ApiError
from smartlock.models import Device

from .constants import AUTH_FAIL_LIMIT, AUTH_FAIL_WINDOW


def _client_key(request, code):
    return f'devapi:fail:{services.client_ip(request)}:{code[:50]}'


def authenticate_device(request) -> Device:
    code = (request.META.get('HTTP_X_DEVICE_CODE') or '').strip()
    secret = request.META.get('HTTP_X_DEVICE_SECRET') or ''
    if not code or not secret:
        raise ApiError('DEVICE_AUTH_REQUIRED', 'Thiếu X-Device-Code / X-Device-Secret.', 401)
    key = _client_key(request, code)
    fails = cache.get(key, 0)
    if fails >= AUTH_FAIL_LIMIT:
        raise ApiError('RATE_LIMITED', 'Sai thông tin quá nhiều lần. Thử lại sau ít phút.', 429,
                       retry_after_seconds=AUTH_FAIL_WINDOW)
    device = (Device.objects.select_related('owner').filter(device_code=code).first()
              or Device.objects.select_related('owner').filter(device_code=code.upper()).first())
    if not device or not hmac.compare_digest(device.provisioning_secret_hash, services.hash_token(secret)):
        cache.set(key, fails + 1, AUTH_FAIL_WINDOW)
        if fails < 5:         # chỉ ghi log vài lần đầu, tránh bị spam đầy AuditLog
            services.audit(request, 'DEVICE_API_AUTH_DENIED', actor=None, success=False, severity='warning',
                           username_attempt=code[:150])
        raise ApiError('DEVICE_AUTH_FAILED', 'Mã thiết bị hoặc secret không đúng.', 401)
    cache.delete(key)
    return device


def device_api(*methods):
    def deco(fn):
        @wraps(fn)
        def inner(request, *args, **kwargs):
            request.device = authenticate_device(request)
            return fn(request, *args, **kwargs)
        return api(*methods, auth=False)(inner)
    return deco


def need_owner(device):
    if not device.owner_id:
        raise ApiError('NO_OWNER', 'Khoá chưa được gán chủ nên chưa xử lý mở cửa.', 409)
