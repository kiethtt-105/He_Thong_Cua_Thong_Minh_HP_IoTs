"""GET /device/config/ - cờ bật/tắt Wi-Fi/BLE/NFC, chu kỳ, OTA, giờ máy chủ."""
from django.utils import timezone

from smartlock.api.common import iso, ok

from .auth import device_api
from .helpers import build_config


@device_api('GET')
def config(request):
    now = timezone.now()
    return ok({'server_time': iso(now), 'unix_time': int(now.timestamp()), **build_config(request.device)})
