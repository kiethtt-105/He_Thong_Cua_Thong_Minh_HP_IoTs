"""KHOÁ (firmware ESP32...) + webhook MQTT + system - /api/device/..., /api/webhooks/..., /api/system/..."""
import logging
import math
import re
from datetime import datetime, timedelta, timezone as dt_timezone
from decimal import Decimal
from functools import wraps

from django.conf import settings
from django.core.cache import cache
from django.db import connection, IntegrityError
from django.http import JsonResponse
from django.utils import timezone
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_POST

from smartlock import services
from smartlock.api.common import api, ApiError, fail, iso, ok, read_json, s
from smartlock.models import AuditLog, Device, DeviceCommand, DeviceStatusLog, NfcReader


# ======================================================================
# XÁC THỰC KHOÁ (X-Device-Code + X-Device-Secret), hằng số, helper
# ======================================================================

# ======================================================================
# constants.py - Hằng số của API khoá: chu kỳ, giới hạn thử sai, trạng thái khoá, loại sự kiện cảnh báo.
# ======================================================================

HEARTBEAT_SECONDS = 60


COMMAND_POLL_SECONDS = 3


AUTH_FAIL_LIMIT = 10


AUTH_FAIL_WINDOW = 600


LOG_MIN_INTERVAL = 300             # chỉ ghi DeviceStatusLog khi trạng thái đổi hoặc >= 5 phút (đỡ phình DB)


LOW_BATTERY = 15


MAC_RE = re.compile(r'^([0-9A-F]{2}:){5}[0-9A-F]{2}$')


LOCK_STATES = ('locked', 'unlocked', 'jammed', 'unknown')


# sự kiện không phải mở cửa -> (mức độ, tiêu đề, báo cho ai: 'watchers' | 'owner' | None, giãn cách thông báo giây)
DEVICE_EVENTS = {
    'BOOT':           ('info',     'Khoá vừa khởi động lại',          None,       0),
    'TAMPER':         ('critical', 'Cảnh báo: khoá bị tác động mạnh', 'watchers', 300),
    'FORCED_OPEN':    ('critical', 'Cảnh báo: cửa bị mở cưỡng bức',   'watchers', 300),
    'DOOR_LEFT_OPEN': ('warning',  'Cửa đang mở quá lâu',             'watchers', 600),
    'LOW_BATTERY':    ('warning',  'Pin khoá sắp hết',                'owner',    3600),
}


# ======================================================================
# auth.py - Xác thực khoá bằng X-Device-Code + X-Device-Secret (giới hạn thử sai theo IP + mã khoá).
# ======================================================================

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
    if not device or not services.safe_eq(device.provisioning_secret_hash, services.hash_token(secret)):
        try:                                   # incr nguyên tử (không mất lượt khi nhiều request song song)
            n = cache.incr(key)
        except ValueError:
            cache.set(key, 1, AUTH_FAIL_WINDOW)
            n = 1
        if n <= 5:            # chỉ ghi log vài lần đầu, tránh bị spam đầy AuditLog
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


def need_device_owner(device):
    if not device.owner_id:
        raise ApiError('NO_OWNER', 'Khoá chưa được gán chủ nên chưa xử lý mở cửa.', 409)


# ======================================================================
# helpers.py - Hàm dùng chung: lệnh đang chờ, cấu hình gửi cho khoá, OTA.
# ======================================================================

def pending_commands(device):
    now = timezone.now()
    rows = (DeviceCommand.objects.filter(device=device, status__in=('pending', 'sent'), expires_at__gt=now)
            .order_by('created_at')[:10])
    return [{'command_id': str(c.id), 'command': c.command_type, 'token': c.command_token_hash,
             'expires_in': max(0, int((c.expires_at - now).total_seconds()))} for c in rows]


def to_int(v, lo, hi, default=None):
    try:
        return max(lo, min(hi, int(float(v))))
    except (TypeError, ValueError, OverflowError):
        return default


def _ota(device):
    """Cấu hình OTA tuỳ chọn trong settings: SMARTLOCK_FIRMWARE = {'version','url','sha256'}."""
    fw = getattr(settings, 'SMARTLOCK_FIRMWARE', None) or {}
    version = str(fw.get('version') or '')
    if not version or version == (device.firmware_version or ''):
        return {'available': False}
    return {'available': True, 'version': version, 'url': fw.get('url', ''), 'sha256': fw.get('sha256', '')}


def build_config(device):
    reader = NfcReader.objects.filter(device=device, is_active=True, auto_register=True,
                                      auto_register_until__gt=timezone.now()).first()
    left = max(0, int((reader.auto_register_until - timezone.now()).total_seconds())) if reader else 0
    return {
        'status': device.status, 'has_owner': bool(device.owner_id),
        'wifi_enabled': device.wifi_enabled, 'bluetooth_enabled': device.bluetooth_enabled,
        'nfc_enabled': device.nfc_enabled,
        'nfc_auto_register': {'active': bool(reader), 'seconds_left': left},
        'locked_out': services.in_lockout(device),
        'intervals': {'heartbeat_seconds': HEARTBEAT_SECONDS, 'command_poll_seconds': COMMAND_POLL_SECONDS},
        'ticket_ttl_seconds': services.TICKET_TTL_SECONDS,
        'face': {'dim': services.FACE_DIM, 'max_threshold': services.FACE_MAX_THRESHOLD},
        'ota': _ota(device),
    }


# ======================================================================
# CONFIG · HEARTBEAT · LỆNH + ACK · SỰ KIỆN
# ======================================================================

# ======================================================================
# config.py - GET /device/config/ - cờ bật/tắt Wi-Fi/BLE/NFC, chu kỳ, OTA, giờ máy chủ.
# ======================================================================

@device_api('GET')
def dev_config(request):
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
    """{type: BOOT|TAMPER|FORCED_OPEN|DOOR_LEFT_OPEN|LOW_BATTERY, at?: unix_giây, data?: {...}}
    Hoặc gửi bù hàng đợi offline: {"events": [ {...}, ... ]} (tối đa 50)."""
    device, data = request.device, read_json(request)
    items = data.get('events') if isinstance(data.get('events'), list) else [data]
    items = [it for it in items if isinstance(it, dict)]
    if not items or len(items) > 50:
        raise ApiError('BAD_EVENTS', 'Cần 1-50 sự kiện.', 400)
    kinds = [s(it, 'type', 30).upper() for it in items]
    if any(k not in DEVICE_EVENTS for k in kinds):             # kiểm tra TRƯỚC khi ghi: tránh ghi dở rồi khoá gửi lại -> trùng
        raise ApiError('BAD_EVENT', 'Loại sự kiện không hợp lệ.', 400, allowed=sorted(DEVICE_EVENTS))
    notified = False
    for it, kind in zip(items, kinds):
        meta = it.get('data') if isinstance(it.get('data'), dict) else {}
        meta = {k: v for k, v in list(meta.items())[:20] if isinstance(v, (int, float, str, bool))}
        if it.get('at') is not None:
            try:
                meta['at'] = datetime.fromtimestamp(float(it['at']), tz=dt_timezone.utc).isoformat()
            except (TypeError, ValueError, OverflowError, OSError):
                pass
        notified = raise_event(device, kind, meta) or notified
    services.touch_device(device)
    return ok({'notified': notified, 'count': len(items)})



# ======================================================================
# QUẸT THẺ / PIN / KHUÔN MẶT / ĐIỆN THOẠI: server phán quyết
# ======================================================================

# ======================================================================
# access.py - POST /device/access/* - quẹt thẻ / PIN / khuôn mặt / điện thoại: server phán quyết, khoá CHỈ mở khi granted == true.
# ======================================================================

def _verdict(event, device):
    return ok({'granted': bool(event.success), 'reason': event.reason or None,
               'locked_out': services.in_lockout(device), 'event_id': str(event.id)})


@device_api('POST')
def access_rfid(request):
    device, data = request.device, read_json(request)
    need_device_owner(device)
    uid = services.normalize_uid(s(data, 'uid', 64))
    if len(uid) < 4:
        raise ApiError('BAD_UID', 'UID thẻ không hợp lệ.', 400, field='uid')
    if not device.nfc_enabled:
        return ok({'granted': False, 'reason': 'NFC_DISABLED', 'locked_out': services.in_lockout(device)})
    services.touch_device(device)
    return _verdict(services.verify_rfid_tap(device, uid, ip_address=services.client_ip(request)), device)


@device_api('POST')
def access_pin(request):
    device, data = request.device, read_json(request)
    need_device_owner(device)
    pin = re.sub(r'\D', '', s(data, 'pin', 16))
    if not (4 <= len(pin) <= 8):
        raise ApiError('BAD_PIN', 'PIN phải gồm 4-8 chữ số.', 400, field='pin')
    services.touch_device(device)
    return _verdict(services.verify_door_pin(device, pin, ip_address=services.client_ip(request)), device)


@device_api('POST')
def access_face(request):
    """{embedding: [128 số], snapshot_url?} - khoá/camera tự trích embedding, server chỉ so khớp."""
    device, data = request.device, read_json(request)
    need_device_owner(device)
    emb = data.get('embedding')
    if not isinstance(emb, list) or len(emb) != services.FACE_DIM:
        raise ApiError('BAD_EMBEDDING', f'embedding phải là mảng {services.FACE_DIM} số.', 400, field='embedding')
    try:
        emb = [float(x) for x in emb]
    except (TypeError, ValueError):
        raise ApiError('BAD_EMBEDDING', 'embedding phải là mảng số.', 400, field='embedding')
    if not all(math.isfinite(x) for x in emb):
        raise ApiError('BAD_EMBEDDING', 'embedding chứa giá trị không hợp lệ.', 400, field='embedding')
    services.touch_device(device)
    event = services.verify_face(device, emb, snapshot_url=s(data, 'snapshot_url', 512),
                                 ip_address=services.client_ip(request))
    return _verdict(event, device)


@device_api('POST')
def access_phone(request):
    """Khoá TỰ kiểm vé BLE/NFC offline rồi báo log về sau. Một sự kiện hoặc {"events": [...]} (tối đa 50):
        {channel: 'ble'|'nfc', ticket, ok: bool, reason?, at?: unix_giây}
    Server xác minh lại chữ ký/hạn/quyền của vé trước khi ghi nhận thành công."""
    device, data = request.device, read_json(request)
    need_device_owner(device)
    items = data.get('events') if isinstance(data.get('events'), list) else [data]
    if not items or len(items) > 50:
        raise ApiError('BAD_EVENTS', 'Cần 1-50 sự kiện.', 400)
    items = [it for it in items if isinstance(it, dict)]
    if not items or any(str(it.get('channel') or '').lower() not in services.PHONE_CHANNELS for it in items):
        # kiểm tra TRƯỚC khi ghi bất kỳ sự kiện nào: tránh xử lý dở dang rồi khoá gửi lại -> ghi trùng
        raise ApiError('BAD_CHANNEL', 'channel phải là "ble" hoặc "nfc".', 400)
    results = []
    for it in items:
        channel = str(it.get('channel') or '').lower()
        recorder = services.record_ble_unlock if channel == 'ble' else services.record_nfc_phone_unlock
        event = recorder(device, ticket=str(it.get('ticket') or '')[:200], ok=it.get('ok') is not False,
                         reason=str(it.get('reason') or '')[:100] or None, at=it.get('at'))
        results.append({'channel': channel, 'accepted': bool(event.success), 'reason': event.reason or None,
                        'event_id': str(event.id)})
    services.touch_device(device)
    return ok({'results': results})


@device_api('POST')
def ota_report(request):
    """Khoá báo kết quả OTA: {status: 'started'|'success'|'failed', version, error?}. Thành công -> cập nhật firmware_version."""
    device, data = request.device, read_json(request)
    status = s(data, 'status', 10).lower()
    if status not in ('started', 'success', 'failed'):
        raise ApiError('BAD_STATUS', 'status phải là started | success | failed.', 400, field='status')
    version = s(data, 'version', 30)
    meta = {'version': version, 'error': s(data, 'error', 200)}
    services.touch_device(device, firmware=version if status == 'success' and version else None)
    AuditLog.objects.create(device=device, action=f'DEVICE_OTA_{status.upper()}', success=status != 'failed',
                            severity='warning' if status == 'failed' else 'info', metadata=meta)
    if status == 'failed' and device.owner_id:
        services.notify(device.owner, 'Cập nhật firmware thất bại', f'Khoá "{device.name}" không cập nhật được lên {version or "bản mới"}.',
                        severity='warning', device=device, type_='OTA')
    return ok({'recorded': True, 'ota': build_config(device)['ota']})


# ======================================================================
# SYSTEM: health · config công khai
# ======================================================================

# ======================================================================
# views.py - GET /system/health/ và GET /system/config/ - công khai, chỉ đọc.
# ======================================================================

@api('GET', auth=False)
def health(request):
    """200 khi web + DB sống, 503 khi DB lỗi. Dùng cho load balancer / uptime monitor."""
    try:
        with connection.cursor() as cur:
            cur.execute('SELECT 1')
    except Exception:
        return fail('DB_UNAVAILABLE', 'Cơ sở dữ liệu chưa sẵn sàng.', 503)
    return ok({'status': 'up', 'server_time': iso(timezone.now())})


@api('GET', auth=False)
def system_config(request):
    """Cấu hình công khai cho app trước khi đăng nhập (ẩn/hiện nút Đăng ký...)."""
    cfg = services.system_settings()
    return ok({'server_time': iso(timezone.now()),
               'registration_enabled': bool(cfg.registration_enabled)})


# ======================================================================
# WEBHOOK: broker MQTT gọi vào (auth / acl)
# ======================================================================

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
    return services.safe_eq(request.META.get('HTTP_X_WEBHOOK_SECRET', ''), secret)


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
        if services.safe_eq(password, expected):
            return JsonResponse({'ok': True})
        services.audit(request, 'MQTT_AUTH_DENIED', success=False, severity='warning',
                       username_attempt=username[:150])
        return JsonResponse({'ok': False}, status=401)

    device = Device.objects.filter(device_code=username).first()
    if not device or not services.safe_eq(device.provisioning_secret_hash, services.hash_token(password)):
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
