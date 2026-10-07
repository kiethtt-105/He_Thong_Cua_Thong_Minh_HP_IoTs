"""Khoá + lệnh điều khiển - /api/app/devices/..., /api/app/commands/..."""
from datetime import timedelta

from django.db.models import OuterRef, Subquery
from django.utils import timezone

from .serializers import command_json, device_json, event_json, get_device, need_owner
from smartlock import services
from smartlock.api.common import api, ApiError, iso, ok, paginate, read_json, s, uuid_or_404
from smartlock.constants import ALLOWED_COMMANDS, COMMAND_LABELS, COMMAND_TTL_SECONDS
from smartlock.models import AccessEvent, Device, DeviceCommand, DeviceStatusLog


# ======================================================================
# devices.py - Khoá: danh sách, chi tiết, trạng thái trực tiếp, thêm khoá bằng code + secret.
# ======================================================================

@api('GET', auth='any')
def devices_list(request):
    user = request.user
    latest = (DeviceStatusLog.objects.filter(device=OuterRef('pk')).order_by('-recorded_at').values('lock_state')[:1])
    devices = list(services.accessible_devices(user).select_related('owner')
                   .annotate(last_lock_state=Subquery(latest)).order_by('name'))
    perms = services.permission_map(user, devices)
    return ok({'devices': [device_json(d, user, perms[d.id], d.last_lock_state) for d in devices]})


@api('GET', 'PATCH', auth='any')
def device_detail(request, device_id):
    device = get_device(request, device_id)
    user = request.user
    if request.method == 'PATCH':
        need_owner(request, device, 'DEVICE_UPDATE')
        data = read_json(request)
        fields = ('name', 'location', 'wifi_enabled', 'bluetooth_enabled', 'nfc_enabled')
        before = {f: getattr(device, f) for f in fields}
        if 'name' in data:
            name = s(data, 'name', 100)
            if not name:
                raise ApiError('MISSING_FIELD', 'Tên thiết bị không được để trống.', 400, field='name')
            device.name = name
        if 'location' in data:
            device.location = s(data, 'location', 255) or None
        for flag in ('wifi_enabled', 'bluetooth_enabled', 'nfc_enabled'):
            if flag in data:
                if not isinstance(data[flag], bool):
                    raise ApiError('BAD_FIELD', f'"{flag}" phải là true/false.', 400, field=flag)
                setattr(device, flag, data[flag])
        device.save(update_fields=[f for f in fields if before[f] != getattr(device, f)] + ['updated_at'])
        changes = {f: [before[f], getattr(device, f)] for f in fields if before[f] != getattr(device, f)}
        services.audit(request, 'DEVICE_UPDATED', device=device, metadata={'changes': changes} if changes else None)

    last = DeviceStatusLog.objects.filter(device=device).order_by('-recorded_at').first()
    perms = services.permission_codes(user, device)
    body = device_json(device, user, perms, last.lock_state if last else None)
    cmds = DeviceCommand.objects.filter(device=device)
    if device.owner_id != user.id:
        cmds = cmds.filter(issued_by=user)
    return ok({
        'device': body,
        'capabilities': services.capabilities(user, device),
        'last_status': {
            'lock_state': last.lock_state, 'battery_level': last.battery_level,
            'signal_strength': last.signal_strength, 'tamper_detected': last.tamper_detected,
            'temperature': float(last.temperature) if last.temperature is not None else None,
            'recorded_at': iso(last.recorded_at)} if last else None,
        'recent_commands': [command_json(c) for c in cmds.order_by('-created_at')[:6]],
    })


@api('GET', auth='any')
def device_live(request, device_id):
    """Trạng thái trực tiếp - app poll 2-3 giây/lần khi đang mở màn hình điều khiển."""
    device = get_device(request, device_id)
    user = request.user
    # .using('default'): đọc thẳng DB chính, tránh trễ của bản sao local (~2s) - trang live poll 2s/lần
    log = DeviceStatusLog.objects.using('default').filter(device=device).order_by('-recorded_at').first()
    link = services.link_status(device)
    out = {
        'now': iso(timezone.now()), 'name': device.name, 'code': device.device_code,
        'connected': link['connected'], 'seconds_ago': link['seconds_ago'],
        'lock_state': log.lock_state if log else 'unknown', 'tamper': bool(log and log.tamper_detected),
        'battery': device.battery_level, 'firmware': device.firmware_version or '',
        'locked_out': services.in_lockout(device),
    }
    if services.has_permission(user, device, 'view_history'):
        events = (AccessEvent.objects.using('default').filter(device=device).select_related('user', 'device')
                  .order_by('-created_at')[:8])
        out['events'] = [event_json(e) for e in events]
    cmds = DeviceCommand.objects.filter(device=device)
    if device.owner_id != user.id:
        cmds = cmds.filter(issued_by=user)
    out['commands'] = [command_json(c) for c in cmds.order_by('-created_at')[:5]]
    return ok(out)


_CLAIM_STATUS = {'BAD_CREDENTIALS': 400, 'RATE_LIMITED': 429}


@api('POST', auth='any')
def device_claim(request):
    data = read_json(request)
    code = s(data, 'device_code', 50, required=True)
    secret = str(data.get('secret') or '')
    try:
        device = services.user_claim_device(request.user, code, secret, request)
    except services.ClaimError as exc:
        services.audit(request, 'DEVICE_CLAIM_FAILED', success=False, severity='warning',
                       metadata={'device_code_input': code.upper(), 'code': exc.code, 'channel': request.client_type})
        raise ApiError(exc.code, exc.message, _CLAIM_STATUS.get(exc.code, 409))
    services.audit(request, 'DEVICE_CLAIMED', device=device, target_user=request.user, severity='warning',
                   metadata={'by': 'user', 'channel': request.client_type})
    services.notify(request.user, 'Đã thêm khoá vào tài khoản',
                    f'Khoá "{device.name}" ({device.device_code}) đã được gán cho bạn.', device=device, type_='DEVICE')
    device = Device.objects.select_related('owner').get(pk=device.pk)
    return ok({'device': device_json(device, request.user, services.permission_codes(request.user, device))}, 201)


# ======================================================================
# commands.py - Lệnh điều khiển (LOCK / UNLOCK / REBOOT) + vé mở cửa offline BLE / NFC.
# ======================================================================

@api('POST', auth='any')
def device_command(request, device_id):
    device = get_device(request, device_id)
    user = request.user
    command = s(read_json(request), 'command', 20).upper()
    if command not in ALLOWED_COMMANDS:
        services.audit(request, 'CMD_INVALID', device=device, success=False, severity='warning',
                       metadata={'command': command[:30]})
        raise ApiError('BAD_COMMAND', 'Lệnh không hợp lệ.', 400, allowed=sorted(ALLOWED_COMMANDS))

    needed = ALLOWED_COMMANDS[command]
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

    cmd = services.dispatch_command(device, command, source=request.client_type, issued_by=user, ttl=COMMAND_TTL_SECONDS)
    if cmd.status != 'sent':
        services.audit(request, f'CMD_{command}_FAILED', device=device, success=False,
                       metadata={'reason': 'mqtt_publish_failed', 'error': getattr(cmd, 'publish_error', '')})
        raise ApiError('PUBLISH_FAILED', 'Không kết nối được tới thiết bị. Vui lòng thử lại.', 502)
    services.audit(request, f'CMD_{command}', device=device, metadata={'command_id': str(cmd.id), 'channel': request.client_type})
    return ok({'command': command_json(cmd),
               'message': f'Đã gửi lệnh {COMMAND_LABELS.get(command, command)} tới "{device.name}".'}, 202)


@api('GET', auth='any')
def device_commands_list(request, device_id):
    device = get_device(request, device_id)
    qs = DeviceCommand.objects.filter(device=device).order_by('-created_at')
    if device.owner_id != request.user.id:
        qs = qs.filter(issued_by=request.user)
    return ok(paginate(request, qs, command_json))


@api('GET', auth='any')
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
    ttl = None
    if device.owner_id != request.user.id:                 # vé không được sống lâu hơn thời hạn chia sẻ
        share = (services._live_access(request.user, timezone.now())
                 .filter(device=device, permissions__code=cfg['permission']).first())
        if share and share.expires_at:
            ttl = max(1, min(services.TICKET_TTL_SECONDS, int((share.expires_at - timezone.now()).total_seconds())))
    ticket, exp = services.issue_phone_ticket(device, request.user, kind, ttl)
    services.audit(request, f"{cfg['prefix']}_TICKET_ISSUED", device=device, metadata={'expires_at': exp})
    from datetime import datetime, timezone as dtz
    return ok({'ticket': ticket, 'channel': kind, 'device_code': device.device_code, 'expires_at': exp,
               'expires_at_iso': datetime.fromtimestamp(exp, tz=dtz.utc).isoformat(),
               'ttl_seconds': services.TICKET_TTL_SECONDS})


@api('POST', auth='any')
def device_ble_ticket(request, device_id):
    return _ticket(request, device_id, 'ble')


@api('POST', auth='any')
def device_nfc_ticket(request, device_id):
    return _ticket(request, device_id, 'nfc')
