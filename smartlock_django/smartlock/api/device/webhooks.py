"""Webhook server-to-server (broker MQTT gọi vào) - /api/webhooks/"""
import hmac
import logging
from functools import wraps

from django.conf import settings
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_POST

from smartlock import services
from smartlock.models import Device


# ======================================================================
# auth.py - Xác thực webhook: header X-Webhook-Secret khớp settings.MQTT_WEBHOOK_SECRET.
# ======================================================================

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


# ======================================================================
# mqtt.py - Webhook cho plugin HTTP-auth của broker MQTT (vd. mosquitto-go-auth).
# ======================================================================

@webhook_api
def mqtt_auth(request):
    """Kiểm tra 1 thiết bị có được connect vào broker không.

    Thiết bị connect với username=device_code, password=provisioning_secret (tái dùng
    Device.provisioning_secret_hash, không lưu secret riêng cho MQTT).
    """
    username = (request.POST.get('username') or '').strip()
    password = request.POST.get('password') or ''
    if not username or not password:
        return JsonResponse({'ok': False}, status=401)

    # Tài khoản server (publisher/subscriber của Django): so với MQTT_PUBLISHER_PASSWORD.
    if username in getattr(settings, 'MQTT_TRUSTED_USERNAMES', []):
        expected = services.MQTT_PUBLISHER_PASSWORD
        if expected and hmac.compare_digest(password, expected):
            return JsonResponse({'ok': True})
        services.audit(request, 'MQTT_AUTH_DENIED', success=False, severity='warning',
                       username_attempt=username[:150])
        return JsonResponse({'ok': False}, status=401)

    device = Device.objects.filter(device_code=username).first()
    if not device or not hmac.compare_digest(device.provisioning_secret_hash, services.hash_token(password)):
        services.audit(request, 'MQTT_AUTH_DENIED', success=False, severity='warning',
                       username_attempt=username[:150])
        return JsonResponse({'ok': False}, status=401)

    return JsonResponse({'ok': True})


@webhook_api
def mqtt_acl(request):
    """ACL (mosquitto-go-auth: acc 1=read, 2=write, 3=readwrite, 4=subscribe).

    Thiết bị chỉ được đọc/subscribe smartlock/<device_code>/cmd và ghi vào
    smartlock/<device_code>/{status,ack,event}. Tài khoản tin cậy khai báo ở MQTT_TRUSTED_USERNAMES.
    """
    username = (request.POST.get('username') or '').strip()
    topic = (request.POST.get('topic') or '').strip()
    try:
        acc = int(request.POST.get('acc') or 0)
    except ValueError:
        acc = 0
    if not username or not topic:
        return JsonResponse({'ok': False}, status=403)

    if username in getattr(settings, 'MQTT_TRUSTED_USERNAMES', []):
        return JsonResponse({'ok': True})

    if not Device.objects.filter(device_code=username).exists():
        return JsonResponse({'ok': False}, status=403)

    parts = topic.split('/')
    if len(parts) != 3 or parts[0] != 'smartlock' or parts[1] != username:
        return JsonResponse({'ok': False}, status=403)
    channel = parts[2]
    can_read = acc in (1, 3, 4) and channel == 'cmd'
    can_write = acc in (2, 3) and channel in ('status', 'ack', 'event')
    if (acc in (1, 4) and can_read) or (acc == 2 and can_write):
        return JsonResponse({'ok': True})
    return JsonResponse({'ok': False}, status=403)
