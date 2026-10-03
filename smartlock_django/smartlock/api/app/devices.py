"""Khoá: danh sách, chi tiết, trạng thái trực tiếp, thêm khoá bằng code + secret."""
from django.db.models import OuterRef, Subquery
from django.utils import timezone

from smartlock import services
from smartlock.api.common import api, ApiError, iso, ok, read_json, s
from smartlock.models import AccessEvent, Device, DeviceCommand, DeviceStatusLog

from .helpers import get_device, need_owner
from .serializers import command_json, device_json, event_json


@api('GET')
def devices_list(request):
    user = request.user
    latest = (DeviceStatusLog.objects.filter(device=OuterRef('pk')).order_by('-recorded_at').values('lock_state')[:1])
    devices = list(services.accessible_devices(user).select_related('owner')
                   .annotate(last_lock_state=Subquery(latest)).order_by('name'))
    perms = services.permission_map(user, devices)
    return ok({'devices': [device_json(d, user, perms[d.id], d.last_lock_state) for d in devices]})


@api('GET', 'PATCH')
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
        device.save()
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


@api('GET')
def device_live(request, device_id):
    """Trạng thái trực tiếp - app poll 2-3 giây/lần khi đang mở màn hình điều khiển."""
    device = get_device(request, device_id)
    user = request.user
    log = DeviceStatusLog.objects.filter(device=device).order_by('-recorded_at').first()
    link = services.link_status(device)
    out = {
        'now': iso(timezone.now()), 'name': device.name, 'code': device.device_code,
        'connected': link['connected'], 'seconds_ago': link['seconds_ago'],
        'lock_state': log.lock_state if log else 'unknown', 'tamper': bool(log and log.tamper_detected),
        'battery': device.battery_level, 'firmware': device.firmware_version or '',
        'locked_out': services.in_lockout(device),
    }
    if services.has_permission(user, device, 'view_history'):
        events = (AccessEvent.objects.filter(device=device).select_related('user', 'device')
                  .order_by('-created_at')[:8])
        out['events'] = [event_json(e) for e in events]
    cmds = DeviceCommand.objects.filter(device=device)
    if device.owner_id != user.id:
        cmds = cmds.filter(issued_by=user)
    out['commands'] = [command_json(c) for c in cmds.order_by('-created_at')[:5]]
    return ok(out)


_CLAIM_STATUS = {'BAD_CREDENTIALS': 400, 'RATE_LIMITED': 429}


@api('POST')
def device_claim(request):
    data = read_json(request)
    code = s(data, 'device_code', 50, required=True)
    secret = str(data.get('secret') or '')
    try:
        device = services.user_claim_device(request.user, code, secret, request)
    except services.ClaimError as exc:
        services.audit(request, 'DEVICE_CLAIM_FAILED', success=False, severity='warning',
                       metadata={'device_code_input': code.upper(), 'code': exc.code, 'channel': 'mobile'})
        raise ApiError(exc.code, exc.message, _CLAIM_STATUS.get(exc.code, 409))
    services.audit(request, 'DEVICE_CLAIMED', device=device, target_user=request.user, severity='warning',
                   metadata={'by': 'user', 'channel': 'mobile'})
    services.notify(request.user, 'Đã thêm khoá vào tài khoản',
                    f'Khoá "{device.name}" ({device.device_code}) đã được gán cho bạn.', device=device, type_='DEVICE')
    device = Device.objects.select_related('owner').get(pk=device.pk)
    return ok({'device': device_json(device, request.user, services.permission_codes(request.user, device))}, 201)
