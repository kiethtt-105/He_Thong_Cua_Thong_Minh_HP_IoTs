"""API khoá - cấu hình, heartbeat, lệnh + ack, sự kiện."""
import hmac
import math
from datetime import datetime, timedelta, timezone as dt_timezone
from decimal import Decimal

from django.db import IntegrityError
from django.utils import timezone

from .auth import (
    build_config,
    device_api,
    DEVICE_EVENTS,
    LOCK_STATES,
    LOG_MIN_INTERVAL,
    LOW_BATTERY,
    MAC_RE,
    pending_commands,
    to_int,
)
from smartlock import services
from smartlock.api.common import ApiError, iso, ok, read_json, s
from smartlock.models import Device, DeviceCommand, DeviceStatusLog


# ======================================================================
# config.py - GET /device/config/ - cờ bật/tắt Wi-Fi/BLE/NFC, chu kỳ, OTA, giờ máy chủ.
# ======================================================================

@device_api('GET')
def config(request):
    now = timezone.now()
    return ok({'server_time': iso(now), 'unix_time': int(now.timestamp()), **build_config(request.device)})


# ======================================================================
# heartbeat.py - POST /device/heartbeat/ - trạng thái định kỳ (~60 giây), phản hồi kèm lệnh đang chờ.
# ======================================================================

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
        if battery is not None and battery <= LOW_BATTERY and (prev is None or prev.battery_level is None or prev.battery_level > LOW_BATTERY):
            raise_event(device, 'LOW_BATTERY', {'battery': battery})

    fresh = Device.objects.select_related('owner').get(pk=device.pk)
    return ok({'server_time': iso(timezone.now()), 'unix_time': int(timezone.now().timestamp()),
               'commands': pending_commands(fresh), **build_config(fresh)})


# ======================================================================
# commands.py - GET /device/commands/ (kéo lệnh) + POST /device/ack/ (báo kết quả lệnh).
# ======================================================================

@device_api('GET')
def commands(request):
    """Kéo lệnh còn hạn (đã publish MQTT hoặc đang chờ). Khoá phải khử trùng theo command_id
    (cùng 1 lệnh có thể đến cả qua MQTT lẫn HTTP) và KHÔNG thực thi lệnh có expires_in == 0."""
    services.touch_device(request.device)
    return ok({'commands': pending_commands(request.device)})


@device_api('POST')
def ack(request):
    """{command_id, token, success: bool, error?, lock_state?}  - token = giá trị server đã gửi kèm lệnh."""
    device, data = request.device, read_json(request)
    cid = services.parse_uuid(data.get('command_id'))
    cmd = DeviceCommand.objects.select_related('device', 'issued_by').filter(pk=cid, device=device).first() if cid else None
    if not cmd:
        raise ApiError('COMMAND_NOT_FOUND', 'Không tìm thấy lệnh.', 404)
    if not services.safe_eq(cmd.command_token_hash, str(data.get('token') or '')):
        services.audit(request, 'DEVICE_ACK_BAD_TOKEN', actor=None, device=device, success=False, severity='warning',
                       metadata={'command_id': str(cmd.id)})
        raise ApiError('BAD_TOKEN', 'Token lệnh không khớp.', 403)

    success = data.get('success') is not False
    services.touch_device(device)

    if cmd.status in ('acknowledged', 'failed'):                         # ack lặp (mạng chập chờn) -> idempotent
        return ok({'status': cmd.status, 'duplicate': True})
    was_expired = cmd.status == 'expired' or cmd.expires_at <= timezone.now()
    new_status = 'acknowledged' if success else 'failed'
    now = timezone.now()
    # UPDATE có điều kiện: 2 ack song song chỉ 1 cái thắng (không bắn popup / ghi log 2 lần)
    won = (DeviceCommand.objects.filter(pk=cmd.pk).exclude(status__in=('acknowledged', 'failed'))
           .update(status=new_status, acknowledged_at=now))
    if not won:
        cur = DeviceCommand.objects.filter(pk=cmd.pk).values_list('status', flat=True).first()
        return ok({'status': cur or cmd.status, 'duplicate': True})
    cmd.status, cmd.acknowledged_at = new_status, now
    lock_state = s(data, 'lock_state', 20).lower()
    if lock_state in LOCK_STATES and lock_state != 'unknown':
        DeviceStatusLog.objects.create(device=device, battery_level=device.battery_level, lock_state=lock_state)
    if not was_expired:                                                   # ack trễ: ghi nhận nhưng không bật popup
        try:
            services.announce_command_result(cmd, ok=success)
        except Exception:
            pass
    return ok({'status': cmd.status, 'duplicate': False})


# ======================================================================
# events.py - POST /device/events/ - cảnh báo không phải mở cửa (BOOT, TAMPER, FORCED_OPEN, ...).
# ======================================================================

def raise_event(device, kind, meta=None):
    level, title, audience, cooldown = DEVICE_EVENTS[kind]
    from smartlock.models import AuditLog, Notification
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
