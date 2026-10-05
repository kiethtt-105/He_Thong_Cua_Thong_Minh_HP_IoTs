"""Xác thực webhook: header X-Webhook-Secret khớp settings.MQTT_WEBHOOK_SECRET."""
import hmac
import logging
from functools import wraps

from django.conf import settings
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_POST

logger = logging.getLogger('smartlock.api')


def webhook_authorized(request) -> bool:
    """Chưa cấu hình secret: chỉ bỏ qua kiểm tra khi DEBUG, còn lại từ chối (fail-closed)."""
    secret = getattr(settings, 'MQTT_WEBHOOK_SECRET', None)
    if not secret:
        if settings.DEBUG:
            logger.warning('MQTT_WEBHOOK_SECRET chưa được đặt: webhook MQTT không được bảo vệ (DEBUG).')
            return True
        logger.error('MQTT_WEBHOOK_SECRET chưa được đặt: từ chối mọi webhook MQTT.')
        return False
    return hmac.compare_digest(str(request.META.get('HTTP_X_WEBHOOK_SECRET', '')), str(secret))


def webhook_api(fn):
    """POST-only, miễn CSRF (server-to-server), kiểm tra X-Webhook-Secret -> 403 nếu sai."""
    @csrf_exempt
    @require_POST
    @wraps(fn)
    def inner(request, *args, **kwargs):
        if not webhook_authorized(request):
            return JsonResponse({'ok': False}, status=403)
        return fn(request, *args, **kwargs)
    return inner
