"""POST /device/heartbeat/ - trạng thái định kỳ (~60 giây), phản hồi kèm lệnh đang chờ."""
import math
from decimal import Decimal

from django.db import IntegrityError
from django.utils import timezone

from smartlock import services
from smartlock.api.common import iso, ok, read_json, s
from smartlock.models import Device, DeviceStatusLog

from .auth import device_api
from .constants import LOCK_STATES, LOG_MIN_INTERVAL, LOW_BATTERY, MAC_RE
from .events import raise_event
from .helpers import build_config, pending_commands, to_int


@device_api('POST')
def heartbeat(request):
    """Khoá gửi mỗi ~60 giây: {battery, signal, lock_state, tamper, temperature, firmware, mac}.
    Phản hồi kèm luôn lệnh đang chờ => 1 request/chu kỳ là đủ cho khoá không dùng MQTT."""
    device, data = request.device, read_json(request)
    battery = to_int(data.get('battery'), 0, 100)
    signal = to_int(data.get('signal'), -200, 100)
    lock_state = s(data, 'lock_state', 20).lower()
    lock_state = lock_state if lock_state in LOCK_STATES else 'unknown'
    tamper = data.get('tamper') is True
    firmware = s(data, 'firmware', 30) or None
    temperature = None
    try:
        if data.get('temperature') is not None:
            t = float(data['temperature'])
            if math.isfinite(t):
                temperature = Decimal(str(round(max(-99.9, min(199.9, t)), 1)))
    except (TypeError, ValueError):
        pass

    prev = DeviceStatusLog.objects.filter(device=device).order_by('-recorded_at').first()
    now = timezone.now()
    changed = (prev is None or prev.lock_state != lock_state or prev.tamper_detected != tamper
               or (now - prev.recorded_at).total_seconds() >= LOG_MIN_INTERVAL)
    if changed:
        raw = {k: v for k, v in list(data.items())[:30]
               if isinstance(v, (int, float, str, bool)) and len(str(v)) <= 100}
        DeviceStatusLog.objects.create(
            device=device, battery_level=battery if battery is not None else device.battery_level,
            signal_strength=signal, lock_state=lock_state, tamper_detected=tamper,
            temperature=temperature, raw_payload=raw or None)

    services.touch_device(device, firmware=firmware, battery=battery)

    mac = s(data, 'mac', 17).upper()
    if mac and MAC_RE.match(mac) and device.mac_address != mac:
        try:
            Device.objects.filter(pk=device.pk).update(mac_address=mac)
        except IntegrityError:
            pass

    if device.owner_id:                                  # cảnh báo khi CHUYỂN trạng thái, không lặp mỗi nhịp
        if tamper and not (prev and prev.tamper_detected):
            raise_event(device, 'TAMPER', {'source': 'heartbeat'})
        if battery is not None and battery <= LOW_BATTERY and (prev is None or prev.battery_level > LOW_BATTERY):
            raise_event(device, 'LOW_BATTERY', {'battery': battery})

    fresh = Device.objects.select_related('owner').get(pk=device.pk)
    return ok({'server_time': iso(timezone.now()), 'unix_time': int(timezone.now().timestamp()),
               'commands': pending_commands(fresh), **build_config(fresh)})
