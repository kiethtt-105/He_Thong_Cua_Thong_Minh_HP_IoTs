"""Hàm dùng chung: lệnh đang chờ, cấu hình gửi cho khoá, OTA."""
from django.conf import settings
from django.utils import timezone

from smartlock import services
from smartlock.models import DeviceCommand, NfcReader

from .constants import COMMAND_POLL_SECONDS, HEARTBEAT_SECONDS


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
