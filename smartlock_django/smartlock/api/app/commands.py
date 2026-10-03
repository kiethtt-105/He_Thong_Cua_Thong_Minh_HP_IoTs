"""Lệnh điều khiển (LOCK / UNLOCK / REBOOT) + vé mở cửa offline BLE / NFC."""
from datetime import timedelta

from django.utils import timezone

from smartlock import services, views as web
from smartlock.api.common import api, ApiError, ok, paginate, read_json, s, uuid_or_404
from smartlock.models import DeviceCommand

from .helpers import get_device
from .serializers import command_json


@api('POST')
def device_command(request, device_id):
    device = get_device(request, device_id)
    user = request.user
    command = s(read_json(request), 'command', 20).upper()
    if command not in web.ALLOWED_COMMANDS:
        services.audit(request, 'CMD_INVALID', device=device, success=False, severity='warning',
                       metadata={'command': command[:30]})
        raise ApiError('BAD_COMMAND', 'Lệnh không hợp lệ.', 400, allowed=sorted(web.ALLOWED_COMMANDS))

    needed = web.ALLOWED_COMMANDS[command]
    allowed = (device.owner_id == user.id) if needed is None else services.has_permission(user, device, needed)
    if not allowed:
        services.audit(request, f'CMD_{command}_DENIED', device=device, success=False, severity='warning')
        raise ApiError('FORBIDDEN', 'Bạn không có quyền thực hiện lệnh này.', 403)
    if not device.wifi_enabled:
        raise ApiError('WIFI_DISABLED', 'Wi-Fi của khoá đang tắt nên không điều khiển từ xa được.', 409)
    if device.status != 'online':
        services.audit(request, f'CMD_{command}_FAILED', device=device, success=False,
                       metadata={'reason': 'device_not_online', 'status': device.status})
        raise ApiError('DEVICE_OFFLINE', 'Thiết bị đang không online.', 409)

    now = timezone.now()
    DeviceCommand.objects.filter(device=device, status__in=('pending', 'sent'),
                                 expires_at__lte=now).update(status='expired')
    if DeviceCommand.objects.filter(device=device, status__in=('pending', 'sent'), command_type=command,
                                    created_at__gte=now - timedelta(seconds=10)).exists():
        services.audit(request, f'CMD_{command}_FAILED', device=device, success=False,
                       metadata={'reason': 'duplicate_pending'})
        raise ApiError('DUPLICATE', 'Lệnh này vừa được gửi, vui lòng chờ vài giây.', 429)

    cmd = services.dispatch_command(device, command, source='app', issued_by=user, ttl=web.COMMAND_TTL_SECONDS)
    if cmd.status != 'sent':
        services.audit(request, f'CMD_{command}_FAILED', device=device, success=False,
                       metadata={'reason': 'mqtt_publish_failed', 'error': getattr(cmd, 'publish_error', '')})
        raise ApiError('PUBLISH_FAILED', 'Không kết nối được tới thiết bị. Vui lòng thử lại.', 502)
    services.audit(request, f'CMD_{command}', device=device, metadata={'command_id': str(cmd.id), 'channel': 'mobile'})
    return ok({'command': command_json(cmd),
               'message': f'Đã gửi lệnh {web.COMMAND_LABELS.get(command, command)} tới "{device.name}".'}, 202)


@api('GET')
def device_commands_list(request, device_id):
    device = get_device(request, device_id)
    qs = DeviceCommand.objects.filter(device=device).order_by('-created_at')
    if device.owner_id != request.user.id:
        qs = qs.filter(issued_by=request.user)
    return ok(paginate(request, qs, command_json))


@api('GET')
def command_status(request, command_id):
    """App poll tới khi status = acknowledged | failed | expired."""
    cmd = DeviceCommand.objects.select_related('device').filter(pk=uuid_or_404(command_id)).first()
    if cmd:
        if not services.accessible_devices(request.user).filter(pk=cmd.device_id).exists():
            cmd = None
        elif cmd.device.owner_id != request.user.id and cmd.issued_by_id != request.user.id:
            cmd = None
    if not cmd:
        raise ApiError('NOT_FOUND', 'Không tìm thấy lệnh.', 404)
    if cmd.status in ('pending', 'sent') and cmd.expires_at <= timezone.now():
        DeviceCommand.objects.filter(pk=cmd.pk, status__in=('pending', 'sent')).update(status='expired')
        cmd.status = 'expired'
    return ok({'command': command_json(cmd)})


def _ticket(request, device_id, kind):
    cfg = services.PHONE_CHANNELS[kind]
    device = get_device(request, device_id)
    if not getattr(device, cfg['flag']) or device.status not in ('online', 'offline'):
        raise ApiError('CHANNEL_UNAVAILABLE', f"Thiết bị không dùng được {cfg['name']} lúc này.", 409)
    if not services.has_permission(request.user, device, cfg['permission']):
        services.audit(request, f"{cfg['prefix']}_TICKET_DENIED", device=device, success=False, severity='warning')
        raise ApiError('FORBIDDEN', f"Bạn không có quyền mở khóa bằng {cfg['name']}.", 403,
                       permission=cfg['permission'])
    ticket, exp = services.issue_phone_ticket(device, request.user, kind)
    services.audit(request, f"{cfg['prefix']}_TICKET_ISSUED", device=device, metadata={'expires_at': exp})
    from datetime import datetime, timezone as dtz
    return ok({'ticket': ticket, 'channel': kind, 'device_code': device.device_code, 'expires_at': exp,
               'expires_at_iso': datetime.fromtimestamp(exp, tz=dtz.utc).isoformat(),
               'ttl_seconds': services.TICKET_TTL_SECONDS})


@api('POST')
def device_ble_ticket(request, device_id):
    return _ticket(request, device_id, 'ble')


@api('POST')
def device_nfc_ticket(request, device_id):
    return _ticket(request, device_id, 'nfc')
