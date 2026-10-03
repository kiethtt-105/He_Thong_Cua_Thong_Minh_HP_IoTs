"""POST /device/events/ - cảnh báo không phải mở cửa (BOOT, TAMPER, FORCED_OPEN, ...)."""
from datetime import datetime, timedelta, timezone as dt_timezone

from django.utils import timezone

from smartlock import services
from smartlock.api.common import ApiError, ok, read_json, s

from .auth import device_api
from .constants import DEVICE_EVENTS


def raise_event(device, kind, meta=None):
    level, title, audience, cooldown = DEVICE_EVENTS[kind]
    from .models import AuditLog, Notification
    AuditLog.objects.create(device=device, action=f'DEVICE_EVENT_{kind}', severity=level, metadata=meta or None)
    if not audience or not device.owner_id:
        return False
    if cooldown and Notification.objects.filter(
            device=device, type=kind,
            created_at__gte=timezone.now() - timedelta(seconds=cooldown)).exists():
        return False
    msg = f'Khoá "{device.name}": {title.lower()}.'
    if audience == 'watchers':
        services.announce_door_event(device, title, msg, severity=level, type_=kind)
    else:
        services.notify(device.owner, title, msg, severity=level, device=device, type_=kind)
    return True


@device_api('POST')
def event(request):
    """{type: BOOT|TAMPER|FORCED_OPEN|DOOR_LEFT_OPEN|LOW_BATTERY, at?: unix_giây, data?: {...}}"""
    device, data = request.device, read_json(request)
    kind = s(data, 'type', 30).upper()
    if kind not in DEVICE_EVENTS:
        raise ApiError('BAD_EVENT', 'Loại sự kiện không hợp lệ.', 400, allowed=sorted(DEVICE_EVENTS))
    meta = data.get('data') if isinstance(data.get('data'), dict) else {}
    meta = {k: v for k, v in list(meta.items())[:20] if isinstance(v, (int, float, str, bool))}
    if data.get('at') is not None:
        try:
            meta['at'] = datetime.fromtimestamp(float(data['at']), tz=dt_timezone.utc).isoformat()
        except (TypeError, ValueError, OverflowError, OSError):
            pass
    services.touch_device(device)
    notified = raise_event(device, kind, meta)
    return ok({'notified': notified})
