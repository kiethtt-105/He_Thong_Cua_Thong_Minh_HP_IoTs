"""GET /device/commands/ (kéo lệnh) + POST /device/ack/ (báo kết quả lệnh)."""
import hmac

from django.utils import timezone

from smartlock import services
from smartlock.api.common import ApiError, ok, read_json, s
from smartlock.models import DeviceCommand, DeviceStatusLog

from .auth import device_api
from .constants import LOCK_STATES
from .helpers import pending_commands


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
    if not hmac.compare_digest(cmd.command_token_hash, str(data.get('token') or '')):
        services.audit(request, 'DEVICE_ACK_BAD_TOKEN', actor=None, device=device, success=False, severity='warning',
                       metadata={'command_id': str(cmd.id)})
        raise ApiError('BAD_TOKEN', 'Token lệnh không khớp.', 403)

    success = data.get('success') is not False
    services.touch_device(device)
    lock_state = s(data, 'lock_state', 20).lower()
    if lock_state in LOCK_STATES and lock_state != 'unknown':
        DeviceStatusLog.objects.create(device=device, battery_level=device.battery_level, lock_state=lock_state)

    if cmd.status in ('acknowledged', 'failed'):                         # ack lặp (mạng chập chờn) -> idempotent
        return ok({'status': cmd.status, 'duplicate': True})
    was_expired = cmd.status == 'expired' or cmd.expires_at <= timezone.now()
    cmd.status = 'acknowledged' if success else 'failed'
    cmd.acknowledged_at = timezone.now()
    cmd.save(update_fields=['status', 'acknowledged_at'])
    if not was_expired:                                                   # ack trễ: ghi nhận nhưng không bật popup
        try:
            services.announce_command_result(cmd, ok=success)
        except Exception:
            pass
    return ok({'status': cmd.status, 'duplicate': False})
