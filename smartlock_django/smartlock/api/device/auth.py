"""Xác thực thiết bị (X-Device-Code + X-Device-Secret), hằng số và helper dùng chung cho API khoá."""
import hmac
import re
from functools import wraps

from django.conf import settings
from django.core.cache import cache
from django.utils import timezone

from smartlock import services
from smartlock.api.common import api, ApiError
from smartlock.models import Device, DeviceCommand, NfcReader


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
