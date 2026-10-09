"""KHOÁ CỦA NGƯỜI DÙNG (app + web): thiết bị, lệnh, PIN/thẻ/mặt, chia sẻ, lịch sử, snapshot - /api/app/..."""
import hashlib
import json
from datetime import timedelta

from django.db import IntegrityError, transaction
from django.db.models import Count, OuterRef, Q, Subquery
from django.db.models.functions import TruncDate
from django.http import HttpResponse
from django.utils import timezone

from smartlock import services
from smartlock.api.common import (
    announcement_json,
    api,
    ApiError,
    command_json,
    device_json,
    event_json,
    get_device,
    iso,
    managed_device,
    need_owner,
    notification_json,
    ok,
    paginate,
    parse_iso,
    read_json,
    s,
    session_json,
    user_json,
    uuid_or_404,
)
from smartlock.services import (
    ALLOWED_COMMANDS,
    COMMAND_LABELS,
    COMMAND_TTL_SECONDS,
    EVENTS_BATCH,
    EVENTS_MAX_BACKLOG_SECONDS,
)
from smartlock.models import (
    AccessCard,
    AccessEvent,
    Announcement,
    AuditLog,
    CardDeviceAccess,
    Device,
    DeviceAccess,
    DeviceCommand,
    DeviceStatusLog,
    DoorPinCode,
    FaceProfile,
    Fido2Credential,
    MobileSession,
    NfcLog,
    NfcReader,
    Notification,
    Permission,
    TwoFactorConfig,
)


# ======================================================================
# KHOÁ CỦA TÔI: danh sách · chi tiết · live · gỡ khoá · lịch sử trạng thái · lệnh · vé BLE/NFC
# ======================================================================

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


def _release(request, device):
    """Chủ gỡ khoá khỏi tài khoản (factory reset + thu hồi mọi quyền/thẻ/PIN/khuôn mặt). Phải gõ lại mã khoá để xác nhận."""
    need_owner(request, device, 'DEVICE_RELEASE')
    if s(read_json(request), 'device_code', 50).upper() != device.device_code.upper():
        raise ApiError('CONFIRM_REQUIRED', 'Hãy nhập lại đúng mã khoá để xác nhận gỡ.', 400, field='device_code')
    sharers = list(DeviceAccess.objects.filter(device=device, is_active=True).select_related('user'))
    try:
        dev, _prev, counts = services.release_device(device.id)
    except services.ClaimError as exc:
        raise ApiError(exc.code, exc.message, 409)
    services.audit(request, 'DEVICE_RELEASED', device=dev, severity='warning',
                   metadata={'by': 'owner', 'channel': request.client_type, 'revoked': counts})
    for a in sharers:
        services.notify(a.user, 'Khoá không còn được chia sẻ', f'Chủ khoá đã gỡ \"{dev.name}\" nên quyền của bạn không còn hiệu lực.',
                        severity='warning', type_='SHARE')
    return ok({'released': True, 'revoked': counts})


@api('GET', 'PATCH', 'DELETE', auth='any')
def device_detail(request, device_id):
    """GET chi tiết · PATCH đổi tên/vị trí/bật-tắt kênh (chủ) · DELETE gỡ khoá khỏi tài khoản (chủ, body {device_code})."""
    device = get_device(request, device_id)
    user = request.user
    if request.method == 'DELETE':
        return _release(request, device)
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


@api('GET', auth='any')
def device_status_history(request, device_id):
    """Lịch sử trạng thái khoá (khoá/mở, pin, tín hiệu, tamper, nhiệt độ). ?hours=24 (tối đa 168). Cần quyền view_history."""
    device = managed_device(request, device_id, 'view_history')
    try:
        hours = max(1, min(168, int(request.GET.get('hours') or 24)))
    except ValueError:
        raise ApiError('BAD_PAGINATION', 'hours phải là số nguyên.', 400)
    qs = (DeviceStatusLog.objects.filter(device=device, recorded_at__gte=timezone.now() - timedelta(hours=hours))
          .order_by('-recorded_at'))
    return ok(paginate(request, qs, lambda l: {
        'lock_state': l.lock_state, 'battery_level': l.battery_level, 'signal_strength': l.signal_strength,
        'tamper_detected': l.tamper_detected,
        'temperature': float(l.temperature) if l.temperature is not None else None,
        'recorded_at': iso(l.recorded_at)}, default_size=50))


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


# ======================================================================
# QUYỀN VÀO CỬA: PIN khách · thẻ NFC · đầu đọc · khuôn mặt · chia sẻ
# ======================================================================

# ======================================================================
# pins.py - Mã PIN cho khách.
# ======================================================================

def _pin_json(p) -> dict:
    return {
        'id': str(p.id), 'device_id': str(p.device_id), 'label': p.label or '', 'valid_from': iso(p.valid_from),
        'expires_at': iso(p.expires_at), 'max_uses': p.max_uses, 'use_count': p.use_count,
        'is_revoked': p.is_revoked, 'is_valid_now': p.is_valid_now(), 'created_at': iso(p.created_at),
        'created_by': ((p.created_by.full_name or p.created_by.username) if p.created_by_id else ''),
    }


@api('GET', 'POST', auth='any')
def device_pins(request, device_id):
    device = managed_device(request, device_id, 'manage_pins')
    user = request.user
    if request.method == 'POST':
        data = read_json(request)
        try:
            ttl = max(1, min(int(data.get('ttl_minutes') or 1440), 43200))        # tối đa 30 ngày
            max_uses = max(0, int(data.get('max_uses') if data.get('max_uses') is not None else 1))
        except (TypeError, ValueError):
            raise ApiError('BAD_FIELD', 'Thời hạn hoặc số lần dùng không hợp lệ.', 400)
        label = s(data, 'label', 100)
        try:
            pin, plain = services.issue_unique_door_pin(device=device, created_by=user, ttl_minutes=ttl,
                                                        label=label, max_uses=max_uses)
        except RuntimeError as exc:
            raise ApiError('PIN_POOL_FULL', str(exc), 409)
        services.audit(request, 'DOOR_PIN_CREATED', device=device, metadata={'pin_id': str(pin.id), 'label': label})
        # plain_pin CHỈ trả đúng 1 lần ở đây, server không lưu dạng thô.
        return ok({'pin': _pin_json(pin), 'plain_pin': plain,
                   'message': f'Khách bấm mã này trên bàn phím của khoá (hết hạn sau {ttl} phút).'}, 201)
    qs = DoorPinCode.objects.filter(device=device).select_related('created_by')
    if device.owner_id != user.id:
        qs = qs.filter(created_by=user)
    return ok({'pins': [_pin_json(p) for p in qs.order_by('-created_at')[:50]]})


@api('PATCH', 'DELETE', auth='any')
def pin_revoke(request, pin_id):
    """DELETE: thu hồi PIN. PATCH {label?, ttl_minutes?}: đổi nhãn / gia hạn (tính từ bây giờ, tối đa 30 ngày)."""
    pin = DoorPinCode.objects.select_related('device').filter(pk=uuid_or_404(pin_id)).first()
    if pin and not (services.accessible_devices(request.user).filter(pk=pin.device_id).exists()
                    and services.has_permission(request.user, pin.device, 'manage_pins')):
        pin = None
    if pin and pin.device.owner_id != request.user.id and pin.created_by_id != request.user.id:
        pin = None
    if not pin:
        raise ApiError('NOT_FOUND', 'Không tìm thấy mã PIN.', 404)
    if request.method == 'PATCH':
        if pin.is_revoked:
            raise ApiError('PIN_REVOKED', 'Mã PIN đã bị thu hồi.', 409)
        data = read_json(request)
        if 'label' in data:
            pin.label = s(data, 'label', 100) or None
        if 'ttl_minutes' in data:
            try:
                pin.expires_at = timezone.now() + timedelta(minutes=max(1, min(int(data['ttl_minutes']), 43200)))
            except (TypeError, ValueError):
                raise ApiError('BAD_FIELD', 'ttl_minutes không hợp lệ.', 400, field='ttl_minutes')
        pin.save(update_fields=['label', 'expires_at'])
        services.audit(request, 'DOOR_PIN_UPDATED', device=pin.device, metadata={'pin_id': str(pin.id)})
        return ok({'pin': _pin_json(pin)})
    pin.revoke()
    services.audit(request, 'DOOR_PIN_REVOKED', device=pin.device, metadata={'pin_id': str(pin.id)})
    return ok()


# ======================================================================
# cards.py - Thẻ NFC / RFID của người dùng.
# ======================================================================

def _card_json(c, user, owned_ids) -> dict:
    mine = c.user_id == user.id
    links = [l for l in c.carddeviceaccess_set.all() if mine or l.device_id in owned_ids]
    return {
        'id': str(c.id), 'name': c.name or '', 'is_active': c.is_active, 'is_mine': mine,
        'owner': '' if mine else c.user.username, 'created_at': iso(c.created_at),
        'devices': [{'device_id': str(l.device_id), 'device_name': l.device.name, 'is_active': l.is_active}
                    for l in links],
    }


@api('GET', auth='any')
def cards_list(request):
    user = request.user
    managed = list(services.devices_with_permission(user, 'manage_nfc').values_list('id', 'owner_id'))
    owned_ids = {i for i, o in managed if o == user.id}
    cards = (AccessCard.objects.filter(Q(user=user) | Q(carddeviceaccess__device_id__in=owned_ids)).distinct()
             .select_related('user').prefetch_related('carddeviceaccess_set__device').order_by('-created_at'))
    return ok({'cards': [_card_json(c, user, owned_ids) for c in cards]})


@api('PATCH', 'DELETE', auth='any')
def card_detail(request, card_id):
    card = AccessCard.objects.filter(pk=uuid_or_404(card_id), user=request.user).first()   # chỉ thẻ CỦA MÌNH
    if not card:
        services.audit(request, 'CARD_ACTION_DENIED', success=False, severity='warning',
                       metadata={'card_id': str(card_id)[:64]})
        raise ApiError('NOT_FOUND', 'Không tìm thấy thẻ của bạn.', 404)
    if request.method == 'DELETE':
        info = {'card_id': str(card.id), 'name': card.name,
                'devices': [str(d) for d in card.carddeviceaccess_set.values_list('device_id', flat=True)]}
        card.delete()
        services.audit(request, 'CARD_DELETED', metadata=info)
        return ok()
    data = read_json(request)
    if 'name' in data:
        old = card.name
        card.name = s(data, 'name', 100) or None
        services.audit(request, 'CARD_RENAMED', metadata={'card_id': str(card.id), 'from': old, 'to': card.name})
    if 'is_active' in data:
        if not isinstance(data['is_active'], bool):
            raise ApiError('BAD_FIELD', '"is_active" phải là true/false.', 400)
        card.is_active = data['is_active']
        services.audit(request, 'CARD_ENABLED' if card.is_active else 'CARD_DISABLED',
                       metadata={'card_id': str(card.id), 'name': card.name})
    card.save()
    return ok({'card': {'id': str(card.id), 'name': card.name or '', 'is_active': card.is_active}})


@api('PATCH', auth='any')
def card_link(request, card_id, device_id):
    """Bật/tắt thẻ trên MỘT khoá. Chủ khoá: thẻ của bất kỳ ai; người khác: chỉ thẻ của mình (cần manage_nfc)."""
    user = request.user
    link = (CardDeviceAccess.objects.select_related('device', 'access_card')
            .filter(access_card_id=uuid_or_404(card_id), device_id=uuid_or_404(device_id)).first())
    allowed = False
    if link:
        is_owner = link.device.owner_id == user.id
        mine = link.access_card.user_id == user.id
        allowed = is_owner or (mine and services.has_permission(user, link.device, 'manage_nfc'))
    if not allowed:
        services.audit(request, 'CARD_LINK_DENIED', success=False, severity='warning')
        raise ApiError('FORBIDDEN', 'Bạn không có quyền quản lý thẻ trên khoá này.', 403)
    data = read_json(request)
    if not isinstance(data.get('is_active'), bool):
        raise ApiError('BAD_FIELD', 'Cần "is_active": true/false.', 400)
    if data['is_active'] and link.device.owner_id != user.id:
        # người được chia sẻ chỉ được TẮT thẻ của mình, không tự bật lại thẻ mà chủ khoá đã tắt
        raise ApiError('OWNER_ONLY', 'Chỉ chủ khoá mới được bật lại thẻ trên khoá này.', 403)
    link.is_active = data['is_active']
    link.save(update_fields=['is_active'])
    services.audit(request, 'CARD_LINK_ENABLED' if link.is_active else 'CARD_LINK_DISABLED', device=link.device,
                   target_user=link.access_card.user, metadata={'card_id': str(link.access_card_id)})
    return ok({'is_active': link.is_active})


@api('POST', auth='any')
def card_register(request, device_id):
    """Đăng ký thẻ bằng UID (app đọc UID qua NFC của điện thoại hoặc người dùng nhập)."""
    device = managed_device(request, device_id, 'manage_nfc')
    user = request.user
    if not device.nfc_enabled:
        raise ApiError('NFC_DISABLED', 'NFC của khoá đang tắt.', 409)
    data = read_json(request)
    uid = services.normalize_uid(s(data, 'uid', 64))
    name = s(data, 'name', 100) or None
    if len(uid) < 4:
        raise ApiError('BAD_UID', 'UID thẻ không hợp lệ.', 400, field='uid')
    try:
        with transaction.atomic():
            if AccessCard.objects.filter(card_uid_hash=services.hash_token(uid)).exists():
                raise IntegrityError('legacy hash exists')
            card = AccessCard.objects.create(card_uid_hash=services.hash_card_uid(uid), user=user, name=name,
                                             is_active=True)
            CardDeviceAccess.objects.create(access_card=card, device=device)
    except IntegrityError:
        services.audit(request, 'CARD_REGISTER_FAILED', device=device, success=False, severity='warning',
                       metadata={'reason': 'duplicate'})
        raise ApiError('CARD_EXISTS', 'Thẻ này đã được đăng ký.', 409)
    reader = NfcReader.objects.filter(device=device, is_active=True).first()
    NfcLog.objects.create(reader=reader, nfc_tag=card, device=device, user=user, event_type='CARD_REGISTER',
                          ip_address=services.client_ip(request), user_agent=services.user_agent(request))
    services.audit(request, 'CARD_REGISTERED', device=device, metadata={'card_id': str(card.id), 'name': name})
    if device.owner_id != user.id:
        services.notify(device.owner, 'Có thẻ NFC mới trên khoá của bạn',
                        f'{user.username} vừa đăng ký thẻ "{name or "không tên"}" cho "{device.name}".',
                        device=device, type_='CARD')
    return ok({'card': {'id': str(card.id), 'name': card.name or '', 'is_active': True}}, 201)


# ======================================================================
# readers.py - Đầu đọc NFC gắn với khoá (kể cả cửa sổ quẹt-để-đăng-ký).
# ======================================================================

def _reader_json(r) -> dict:
    left = max(0, int((r.auto_register_until - timezone.now()).total_seconds())) if r.auto_register_active else 0
    return {'id': str(r.id), 'device_id': str(r.device_id), 'name': r.name or '', 'reader_mode': r.reader_mode,
            'is_active': r.is_active, 'auto_register': r.auto_register_active,
            'auto_register_seconds_left': left, 'last_seen_at': iso(r.last_seen_at)}


@api('GET', 'POST', auth='any')
def device_readers(request, device_id):
    device = managed_device(request, device_id, 'manage_nfc')
    if request.method == 'POST':
        need_owner(request, device, 'NFC_READER')
        if not device.nfc_enabled:
            raise ApiError('NFC_DISABLED', 'NFC của khoá đang tắt.', 409)
        name = s(read_json(request), 'name', 100) or 'Đầu đọc mô phỏng'
        with transaction.atomic():
            reader = NfcReader.objects.create(device=device, reader_mode='simulated', name=name, is_active=True)
            NfcLog.objects.create(reader=reader, device=device, user=request.user, event_type='READER_CONNECTED',
                                  ip_address=services.client_ip(request), user_agent=services.user_agent(request))
        services.audit(request, 'NFC_READER_ADDED', device=device, metadata={'reader_id': str(reader.id)})
        return ok({'reader': _reader_json(reader)}, 201)
    return ok({'readers': [_reader_json(r) for r in NfcReader.objects.filter(device=device).order_by('-created_at')]})


@api('PATCH', auth='any')
def reader_detail(request, reader_id):
    reader = NfcReader.objects.select_related('device').filter(pk=uuid_or_404(reader_id)).first()
    if not reader or not services.accessible_devices(request.user).filter(pk=reader.device_id).exists():
        raise ApiError('NOT_FOUND', 'Không tìm thấy đầu đọc.', 404)
    need_owner(request, reader.device, 'NFC_READER')
    if not reader.device.nfc_enabled:
        raise ApiError('NFC_DISABLED', 'NFC của khoá đang tắt.', 409)
    data = read_json(request)
    for flag in ('is_active', 'auto_register'):          # bool("false") == True -> phải kiểm kiểu thật
        if flag in data and not isinstance(data[flag], bool):
            raise ApiError('BAD_FIELD', f'"{flag}" phải là true/false.', 400, field=flag)
    audit_action = None
    if 'is_active' in data:
        reader.is_active = bool(data['is_active'])
        audit_action = 'NFC_READER_ENABLED' if reader.is_active else 'NFC_READER_DISABLED'
        event = 'READER_CONNECTED' if reader.is_active else 'READER_DISCONNECTED'
    if 'auto_register' in data:
        reader.auto_register = bool(data['auto_register'])
        if reader.auto_register:
            reader.auto_register_until = None          # để signal mở lại cửa sổ 60 giây
        audit_action = 'NFC_AUTO_REGISTER_ON' if reader.auto_register else 'NFC_AUTO_REGISTER_OFF'
        event = 'CONFIG_UPDATED'
    if audit_action is None:
        raise ApiError('MISSING_FIELD', 'Cần "is_active" hoặc "auto_register".', 400)
    reader.save()
    NfcLog.objects.create(reader=reader, device=reader.device, user=request.user, event_type=event,
                          ip_address=services.client_ip(request), user_agent=services.user_agent(request))
    services.audit(request, audit_action, device=reader.device, metadata={'reader_id': str(reader.id)})
    return ok({'reader': _reader_json(reader)})


# ======================================================================
# faces.py - Khuôn mặt (app gửi vector đặc trưng, không gửi ảnh).
# ======================================================================

def _face_json(f) -> dict:
    return {'id': str(f.id), 'device_id': str(f.device_id), 'name': f.name or '', 'user': f.user.username,
            'is_active': f.is_active, 'consent_confirmed': f.consent_confirmed, 'created_at': iso(f.created_at)}


@api('GET', 'POST', auth='any')
def device_faces(request, device_id):
    device = managed_device(request, device_id, 'manage_face_profiles')
    user = request.user
    if request.method == 'POST':
        if len(request.body) > 64 * 1024:
            raise ApiError('PAYLOAD_TOO_LARGE', 'Dữ liệu quá lớn.', 413)
        data = read_json(request)
        if data.get('consent_confirmed') is not True:
            raise ApiError('CONSENT_REQUIRED',
                           'Cần xác nhận người được đăng ký đã đồng ý thu thập dữ liệu khuôn mặt.', 400)
        name = s(data, 'name', 100) or (user.full_name or user.username)[:100]
        try:
            profile = services.enroll_face(device, user, data.get('embeddings'), name=name, request=request)
        except services.FaceEnrollError as exc:
            services.audit(request, 'FACE_PROFILE_ENROLL_FAILED', device=device, success=False, severity='warning',
                           metadata={'code': exc.code})
            raise ApiError(exc.code, exc.message, 422)
        if device.owner_id != user.id:
            services.notify(device.owner, 'Có khuôn mặt mới trên khoá của bạn',
                            f'{user.username} vừa đăng ký khuôn mặt cho "{device.name}".', device=device, type_='FACE')
        return ok({'profile': _face_json(profile), 'message': 'Đã đăng ký khuôn mặt.'}, 201)
    qs = FaceProfile.objects.filter(device=device).select_related('user')
    if device.owner_id != user.id:
        qs = qs.filter(user=user)
    return ok({'profiles': [_face_json(f) for f in qs.order_by('-created_at')]})


def _own_profile_or_404(request, profile_id):
    """Chủ khoá thao tác được mọi hồ sơ của khoá; người khác chỉ hồ sơ của chính mình."""
    profile = FaceProfile.objects.select_related('device', 'user').filter(pk=uuid_or_404(profile_id)).first()
    if profile and profile.user_id != request.user.id and profile.device.owner_id != request.user.id:
        profile = None
    return profile


@api('PATCH', 'DELETE', auth='any')
def face_delete(request, profile_id):
    """DELETE: xoá hẳn hồ sơ (dữ liệu sinh trắc). PATCH {"is_active": bool}: bật/tắt hồ sơ."""
    profile = _own_profile_or_404(request, profile_id)
    if not profile:
        services.audit(request, 'FACE_PROFILE_DELETE_DENIED' if request.method == 'DELETE' else 'FACE_PROFILE_TOGGLE_DENIED',
                       success=False, severity='warning', metadata={'profile_id': str(profile_id)[:64]})
        raise ApiError('NOT_FOUND', 'Không tìm thấy hồ sơ khuôn mặt.', 404)
    device, owner_of_profile = profile.device, profile.user

    if request.method == 'PATCH':
        data = read_json(request)
        if not isinstance(data.get('is_active'), bool):
            raise ApiError('BAD_FIELD', '"is_active" phải là true/false.', 400, field='is_active')
        if data['is_active'] and device.owner_id != request.user.id:
            raise ApiError('OWNER_ONLY', 'Chỉ chủ khoá mới được bật lại hồ sơ khuôn mặt.', 403)
        profile.is_active = data['is_active']
        profile.save(update_fields=['is_active', 'updated_at'])
        services.audit(request, 'FACE_PROFILE_TOGGLED', device=device, target_user=owner_of_profile,
                       metadata={'face_profile_id': str(profile.id), 'is_active': profile.is_active})
        return ok({'profile': _face_json(profile), 'message': 'Đã cập nhật trạng thái.'})

    info = {'face_profile_id': str(profile.id)}
    profile.delete()
    services.audit(request, 'FACE_PROFILE_DELETED', device=device, target_user=owner_of_profile,
                   severity='warning', metadata=info)
    return ok({'message': 'Đã xoá hồ sơ khuôn mặt.'})


# ======================================================================
# shares.py - Chia sẻ khoá: danh mục quyền, chia sẻ / thu hồi / tự rời.
# ======================================================================

def _share_json(a) -> dict:
    return {
        'id': str(a.id), 'device_id': str(a.device_id), 'device_name': a.device.name,
        'user': {'id': str(a.user_id), 'username': a.user.username, 'full_name': a.user.full_name or ''},
        'shared_by': (a.created_by.full_name or a.created_by.username) if a.created_by_id else '',
        'permissions': sorted(p.code for p in a.permissions.all()),
        'valid_from': iso(a.valid_from), 'expires_at': iso(a.expires_at), 'created_at': iso(a.created_at),
    }


def _wanted_permissions(data):
    services.ensure_default_permissions()
    preset = s(data, 'preset', 30)
    if preset:
        codes = services.preset_codes(preset)
        if codes is None:
            raise ApiError('BAD_PRESET', 'Vai trò mẫu không hợp lệ.', 400, presets=sorted(services.ROLE_PRESETS))
    else:
        raw = data.get('permissions')
        if not isinstance(raw, list):
            raise ApiError('MISSING_FIELD', 'Cần "preset" hoặc "permissions" (mảng mã quyền).', 400)
        codes = [str(c) for c in raw]
        bad = [c for c in codes if c not in services.PERMISSION_CODES]
        if bad:
            raise ApiError('BAD_PERMISSION', f'Mã quyền không hợp lệ: {", ".join(bad[:5])}', 400)
    perms = list(Permission.objects.filter(code__in=codes))
    if not perms:
        raise ApiError('NO_PERMISSION', 'Hãy chọn ít nhất một quyền để chia sẻ.', 400)
    return perms


@api('GET', auth='any')
def permissions_catalog(request):
    services.ensure_default_permissions()
    ctx = services.permission_form_context()
    return ok({
        'groups': [{'key': g['key'], 'name': g['name'], 'description': g['description'],
                    'items': [{k: v for k, v in i.items() if k != 'id'} for i in g['items']]}
                   for g in ctx['permission_groups']],
        'role_presets': ctx['role_presets'],
        'owner_only_actions': ctx['owner_only_actions'],
    })


@api('GET', 'POST', auth='any')
def device_shares(request, device_id):
    device = get_device(request, device_id)
    need_owner(request, device, 'ACCESS_MANAGE')
    user = request.user
    if request.method == 'POST':
        data = read_json(request)
        identifier = s(data, 'identifier', 150, required=True)
        expires = parse_iso(data.get('expires_at'))
        perms = _wanted_permissions(data)
        target = services.find_user(identifier)
        if not target or not target.is_active:
            services.audit(request, 'ACCESS_GRANT_FAILED', device=device, success=False,
                           username_attempt=identifier[:150], metadata={'reason': 'user_not_found'})
            raise ApiError('USER_NOT_FOUND', 'Không tìm thấy người dùng (email hoặc username).', 404)
        if target.id == user.id:
            raise ApiError('SELF_SHARE', 'Bạn đã là chủ thiết bị này.', 400)
        if expires and expires <= timezone.now():
            raise ApiError('BAD_DATETIME', 'Thời điểm hết hạn phải ở tương lai.', 400, field='expires_at')
        access, created = services.grant_access(device, user, target, perms, expires)
        codes = sorted(p.code for p in perms)
        services.audit(request, 'ACCESS_GRANTED' if created else 'ACCESS_UPDATED', device=device, target_user=target,
                       metadata={'access_id': str(access.id), 'permissions': codes,
                                 'expires_at': expires.isoformat() if expires else None, 'channel': request.client_type})
        emailed = services.notify_access_shared(request, access, created)
        access = (DeviceAccess.objects.select_related('device', 'user', 'created_by')
                  .prefetch_related('permissions').get(pk=access.pk))
        return ok({'share': _share_json(access), 'created': created, 'emailed': emailed}, 201 if created else 200)
    qs = (DeviceAccess.objects.filter(device=device, is_active=True)
          .select_related('device', 'user', 'created_by').prefetch_related('permissions').order_by('-created_at'))
    return ok({'shares': [_share_json(a) for a in qs]})


@api('GET', auth='any')
def shares_incoming(request):
    now = timezone.now()
    qs = (DeviceAccess.objects.filter(user=request.user, is_active=True)
          .filter(Q(expires_at__isnull=True) | Q(expires_at__gt=now))
          .select_related('device', 'user', 'created_by').prefetch_related('permissions').order_by('-created_at'))
    return ok({'shares': [_share_json(a) for a in qs]})


@api('PATCH', 'DELETE', auth='any')
def share_detail(request, share_id):
    access = (DeviceAccess.objects.select_related('device', 'user', 'created_by')
              .filter(pk=uuid_or_404(share_id), is_active=True).first())
    if not access or access.device.owner_id != request.user.id:
        raise ApiError('NOT_FOUND', 'Không tìm thấy quyền truy cập.', 404)
    device = access.device
    if request.method == 'PATCH':
        data = read_json(request)                        # đổi quyền (preset|permissions) và/hoặc gia hạn (expires_at)
        meta = {'access_id': str(access.id)}
        if 'expires_at' in data:
            exp = parse_iso(data.get('expires_at'))
            if exp and exp <= timezone.now():
                raise ApiError('BAD_DATETIME', 'Thời điểm hết hạn phải ở tương lai.', 400, field='expires_at')
            meta['expires_at'] = [iso(access.expires_at), iso(exp)]
            access.expires_at = exp
            access.save(update_fields=['expires_at'])
        if 'preset' in data or 'permissions' in data or 'expires_at' not in data:
            perms = _wanted_permissions(data)
            meta['from'] = sorted(p.code for p in access.permissions.all())
            access.permissions.set(perms)
            meta['to'] = sorted(p.code for p in perms)
        services.audit(request, 'ACCESS_UPDATED', device=device, target_user=access.user, metadata=meta)
        services.notify_access_shared(request, access, created=False)
        access = (DeviceAccess.objects.select_related('device', 'user', 'created_by')
                  .prefetch_related('permissions').get(pk=access.pk))
        return ok({'share': _share_json(access)})
    access.is_active = False
    access.revoked_at = timezone.now()
    access.save(update_fields=['is_active', 'revoked_at'])
    cancelled = DeviceCommand.objects.filter(device=device, issued_by=access.user, status='pending').update(status='failed')
    creds = services.revoke_user_credentials(device, access.user)     # thẻ / khuôn mặt / PIN của người đó mất hiệu lực
    services.audit(request, 'ACCESS_REVOKED', device=device, target_user=access.user, severity='warning',
                   metadata={'access_id': str(access.id), 'cancelled_commands': cancelled,
                             'revoked_credentials': creds})
    services.notify(access.user, 'Quyền truy cập bị thu hồi', f'Quyền của bạn trên "{device.name}" đã bị thu hồi.',
                    severity='warning', device=device, type_='SHARE')
    return ok()


@api('POST', auth='any')
def share_leave(request, share_id):
    access = (DeviceAccess.objects.select_related('device', 'device__owner')
              .filter(pk=uuid_or_404(share_id), user=request.user, is_active=True).first())
    if not access:
        raise ApiError('NOT_FOUND', 'Không tìm thấy quyền truy cập.', 404)
    access.is_active = False
    access.revoked_at = timezone.now()
    access.save(update_fields=['is_active', 'revoked_at'])
    creds = services.revoke_user_credentials(access.device, request.user)
    services.audit(request, 'ACCESS_LEFT', device=access.device, target_user=access.device.owner,
                   metadata={'access_id': str(access.id), 'revoked_credentials': creds})
    if access.device.owner_id:
        services.notify(access.device.owner, 'Người dùng đã rời khỏi khoá được chia sẻ',
                        f'{request.user.username} không còn dùng khoá "{access.device.name}" nữa.',
                        device=access.device, type_='SHARE')
    return ok()


# ======================================================================
# LỊCH SỬ · NHẬT KÝ · THÔNG BÁO · POLL SỰ KIỆN
# ======================================================================

# ======================================================================
# history.py - Lịch sử ra vào + nhật ký hệ thống (audit).
# ======================================================================

@api('GET', auth='any')
def access_history(request):
    user = request.user
    devices = services.devices_with_permission(user, 'view_history')
    qs = AccessEvent.objects.filter(device__in=devices).select_related('device', 'user').order_by('-created_at')
    dev = request.GET.get('device')
    if dev:
        qs = qs.filter(device_id=uuid_or_404(dev))
    method = request.GET.get('method')
    if method in dict(AccessEvent.METHOD_CHOICES):
        qs = qs.filter(method=method)
    if request.GET.get('success') in ('0', '1'):
        qs = qs.filter(success=request.GET['success'] == '1')
    return ok(paginate(request, qs, event_json))


@api('GET', auth='any')
def audit_logs(request):
    qs = services.visible_logs(request.user).select_related('device').order_by('-created_at')
    dev = request.GET.get('device')
    if dev:
        qs = qs.filter(device_id=uuid_or_404(dev))
    return ok(paginate(request, qs, lambda l: {
        'id': str(l.id), 'action': l.action, 'success': l.success, 'severity': l.severity,
        'device_id': str(l.device_id) if l.device_id else None, 'device': l.device.name if l.device_id else None,
        'ip_address': l.ip_address, 'created_at': iso(l.created_at)}))


# ======================================================================
# notifications.py - Thông báo + poll sự kiện khi app đang mở.
# ======================================================================

@api('GET', 'DELETE', auth='any')
def notifications(request):
    user = request.user
    if request.method == 'DELETE':
        deleted, _ = Notification.objects.filter(user=user, is_read=True).delete()
        return ok({'deleted': deleted})
    qs = Notification.objects.filter(user=user).select_related('device').order_by('-created_at')
    if request.GET.get('unread') == '1':
        qs = qs.filter(is_read=False)
    data = paginate(request, qs, notification_json)
    data['unread_count'] = Notification.objects.filter(user=user, is_read=False).count()
    return ok(data)


@api('POST', auth='any')
def notifications_read(request):
    data = read_json(request)
    qs = Notification.objects.filter(user=request.user, is_read=False)
    if data.get('all') is True:
        pass
    else:
        raw_ids = data.get('ids')
        if not isinstance(raw_ids, list):
            raise ApiError('MISSING_FIELD', 'Cần "ids" (mảng UUID) hoặc "all": true.', 400)
        ids = [services.parse_uuid(i) for i in raw_ids if services.parse_uuid(i)]
        if not ids:
            raise ApiError('MISSING_FIELD', 'Cần "ids" (mảng UUID) hoặc "all": true.', 400)
        qs = qs.filter(id__in=ids[:200])
    n = qs.update(is_read=True, read_at=timezone.now())
    return ok({'updated': n, 'unread_count': Notification.objects.filter(user=request.user, is_read=False).count()})


@api('DELETE', auth='any')
def notification_delete(request, notification_id):
    n, _ = Notification.objects.filter(user=request.user, pk=uuid_or_404(notification_id)).delete()
    if not n:
        raise ApiError('NOT_FOUND', 'Không tìm thấy thông báo.', 404)
    return ok()


@api('GET', auth='any')
def events_poll(request):
    """Poll nhẹ khi app đang mở (khi nền thì dùng push FCM). ?cursor=<iso> (lần đầu bỏ trống)."""
    user, now = request.user, timezone.now()
    since = parse_iso(request.GET.get('cursor'), 'cursor')
    unread = Notification.objects.filter(user=user, is_read=False).count()
    if since is None:
        return ok({'events': [], 'cursor': iso(now), 'unread_count': unread})
    since = max(since, now - timedelta(seconds=EVENTS_MAX_BACKLOG_SECONDS))
    rows = list(Notification.objects.filter(user=user, created_at__gt=since).order_by('created_at')[:EVENTS_BATCH])
    cursor = rows[-1].created_at if rows else since
    return ok({'events': [notification_json(n) for n in rows], 'cursor': iso(cursor), 'unread_count': unread})


# ======================================================================
# announcements.py - GET /announcements/ - thông báo hệ thống đang bật (quản trị đăng ở manage_sys).
# ======================================================================

@api('GET', auth='any')
def announcements(request):
    qs = Announcement.objects.filter(is_active=True).order_by('-created_at')
    return ok(paginate(request, qs, announcement_json))


# ======================================================================
# BOOTSTRAP + SNAPSHOT: toàn bộ dữ liệu của user (ETag/304) - web poll 2-5s, app dùng chung
# ======================================================================

@api('GET', auth='any')
def bootstrap(request):
    user = request.user
    latest = (DeviceStatusLog.objects.filter(device=OuterRef('pk')).order_by('-recorded_at').values('lock_state')[:1])
    devices = list(services.accessible_devices(user).select_related('owner')
                   .annotate(last_lock_state=Subquery(latest)).order_by('name'))
    perms = services.permission_map(user, devices)
    notes = Notification.objects.filter(user=user).order_by('-created_at')[:20]
    return ok({
        'server_time': iso(timezone.now()),
        'user': user_json(user),
        'unread_count': Notification.objects.filter(user=user, is_read=False).count(),
        'devices': [device_json(d, user, perms[d.id], d.last_lock_state) for d in devices],
        'notifications': [notification_json(n) for n in notes],
        'announcements': [{'id': str(a.id), 'title': a.title, 'body': a.body, 'level': a.level,
                           'created_at': iso(a.created_at)}
                          for a in Announcement.objects.filter(is_active=True).order_by('-created_at')[:5]],
    })


# ====================== SNAPSHOT: TOÀN BỘ dữ liệu của CHÍNH user này (client cache + làm mới 2-5s) ======================
# Mỗi section lọc theo quyền của user giống hệt endpoint riêng của nó (chủ khoá thấy hết, người được chia sẻ chỉ thấy
# phần được phép). Trả kèm ETag: client gửi If-None-Match, không đổi gì -> 304 rỗng (nhẹ băng thông, không vẽ lại UI).
SNAPSHOT_LIMITS = {'notifications': 50, 'history': 50, 'audit': 50, 'pins': 200, 'commands': 50, 'nfc_logs': 30}


def _snapshot_payload(request) -> dict:
    user = request.user
    now = timezone.now()
    latest = (DeviceStatusLog.objects.filter(device=OuterRef('pk')).order_by('-recorded_at').values('lock_state')[:1])
    devices = list(services.accessible_devices(user).select_related('owner')
                   .annotate(last_lock_state=Subquery(latest)).order_by('name'))
    perms = services.permission_map(user, devices)

    # ---- thẻ NFC (cùng logic cards_list) ----
    nfc_managed = list(services.devices_with_permission(user, 'manage_nfc').values_list('id', 'owner_id'))
    owned_ids = {i for i, o in nfc_managed if o == user.id}
    cards = (AccessCard.objects.filter(Q(user=user) | Q(carddeviceaccess__device_id__in=owned_ids)).distinct()
             .select_related('user').prefetch_related('carddeviceaccess_set__device').order_by('-created_at'))

    # ---- đầu đọc / PIN / khuôn mặt: gộp theo thiết bị, client nhóm lại bằng device_id ----
    readers = NfcReader.objects.filter(device__in=services.devices_with_permission(user, 'manage_nfc')) \
        .order_by('-created_at')
    pins = (DoorPinCode.objects.filter(device__in=services.devices_with_permission(user, 'manage_pins'))
            .filter(Q(device__owner=user) | Q(created_by=user))          # không phải chủ: chỉ thấy mã mình tạo
            .select_related('created_by').order_by('-created_at')[:SNAPSHOT_LIMITS['pins']])
    faces = (FaceProfile.objects.filter(device__in=services.devices_with_permission(user, 'manage_face_profiles'))
             .filter(Q(device__owner=user) | Q(user=user))                # không phải chủ: chỉ hồ sơ của mình
             .select_related('user').order_by('-created_at'))

    # ---- chia sẻ: mình chia sẻ cho người khác (chủ khoá) + được chia sẻ cho mình ----
    share_qs = DeviceAccess.objects.select_related('device', 'user', 'created_by').prefetch_related('permissions')
    shares_out = share_qs.filter(device__owner=user, is_active=True).order_by('-created_at')
    shares_in = (share_qs.filter(user=user, is_active=True)
                 .filter(Q(expires_at__isnull=True) | Q(expires_at__gt=now)).order_by('-created_at'))

    # ---- lịch sử ra vào + nhật ký + thông báo ----
    history = (AccessEvent.objects.filter(device__in=services.devices_with_permission(user, 'view_history'))
               .select_related('device', 'user').order_by('-created_at')[:SNAPSHOT_LIMITS['history']])
    audit = services.visible_logs(user).select_related('device').order_by('-created_at')[:SNAPSHOT_LIMITS['audit']]
    notes = Notification.objects.filter(user=user).order_by('-created_at')[:SNAPSHOT_LIMITS['notifications']]

    # ---- bảo mật tài khoản (không có bí mật TOTP, không có khoá công khai) ----
    cfg = TwoFactorConfig.objects.filter(user=user).first()
    passkeys = Fido2Credential.objects.filter(user=user).order_by('created_at')
    rp_here = services.webauthn_rp(request)[0]
    sessions = MobileSession.objects.filter(user=user, revoked_at__isnull=True,
                                            expires_at__gt=now).order_by('-created_at')
    current = request.api_session.id if request.api_session else None

    # ---- nhật ký NFC (chủ khoá thấy hết, người khác chỉ thấy của mình) ----
    nfc_logs = (NfcLog.objects.filter(device__in=services.devices_with_permission(user, 'manage_nfc'))
                .filter(Q(device__owner=user) | Q(user=user)).select_related('nfc_tag')
                .order_by('-created_at')[:SNAPSHOT_LIMITS['nfc_logs']])

    # ---- lệnh điều khiển gần đây (chủ khoá thấy hết, người khác chỉ thấy lệnh của mình) ----
    commands = (DeviceCommand.objects.filter(device__in=[d.id for d in devices])
                .filter(Q(device__owner=user) | Q(issued_by=user)).select_related('issued_by')
                .order_by('-created_at')[:SNAPSHOT_LIMITS['commands']])

    # ---- biểu đồ hoạt động 7 ngày (đếm sẵn, client chỉ vẽ) ----
    today = timezone.localdate()
    days = [today - timedelta(days=i) for i in range(6, -1, -1)]
    counts = {r['d']: r['c'] for r in
              services.visible_logs(user).filter(created_at__date__gte=days[0])
              .annotate(d=TruncDate('created_at')).values('d').annotate(c=Count('id'))}

    return {
        'meta': {'face_min_frames': services.FACE_MIN_FRAMES, 'face_max_frames': services.FACE_MAX_FRAMES},
        'user': user_json(user),
        'unread_count': Notification.objects.filter(user=user, is_read=False).count(),
        'devices': [device_json(d, user, perms[d.id], d.last_lock_state) for d in devices],
        'cards': [_card_json(c, user, owned_ids) for c in cards],
        'nfc_readers': [_reader_json(r) for r in readers],
        'pins': [_pin_json(p) for p in pins],
        'faces': [_face_json(f) for f in faces],
        'shares_out': [_share_json(a) for a in shares_out],
        'shares_in': [_share_json(a) for a in shares_in],
        'history': [event_json(e) for e in history],
        'audit': [{'id': str(l.id), 'action': l.action, 'success': l.success, 'severity': l.severity,
                   'device_id': str(l.device_id) if l.device_id else None,
                   'device': l.device.name if l.device_id else None,
                   'ip_address': l.ip_address, 'created_at': iso(l.created_at)} for l in audit],
        'notifications': [notification_json(n) for n in notes],
        'nfc_logs': [{'id': str(l.id), 'device_id': str(l.device_id) if l.device_id else None,
                      'event_type': l.event_type, 'success': l.success,
                      'card': (l.nfc_tag.name or '') if l.nfc_tag_id else '', 'created_at': iso(l.created_at)}
                     for l in nfc_logs],
        'commands': [{**command_json(c), 'by': c.issued_by.username if c.issued_by_id else ''} for c in commands],
        'activity': {'labels': [d.strftime('%d/%m') for d in days], 'values': [counts.get(d, 0) for d in days]},
        'announcements': [{'id': str(a.id), 'title': a.title, 'body': a.body, 'level': a.level,
                           'created_at': iso(a.created_at)}
                          for a in Announcement.objects.filter(is_active=True).order_by('-created_at')[:5]],
        'security': {
            'email_masked': services.mask_email(user.email),
            'two_fa_enabled': user.two_fa_enabled,
            'totp': bool(cfg and cfg.totp_confirmed),
            'email_otp': bool(cfg and cfg.email_otp_enabled),
            'preferred_method': cfg.preferred_method if cfg else '',
            'passkeys': [{'id': str(k.id), 'name': k.name, 'created_at': iso(k.created_at),
                          'last_used_at': iso(k.last_used_at), 'rp_id': k.rp_id or '',
                          'usable_here': (not k.rp_id) or k.rp_id == rp_here} for k in passkeys],
            'sessions': [session_json(m, current) for m in sessions],
        },
    }


@api('GET', auth='any')
def snapshot(request):
    """GET /api/app/snapshot/ - mọi dữ liệu của user đang đăng nhập trong 1 lần gọi.
    ETag tính trên nội dung (không gồm server_time) -> If-None-Match khớp thì trả 304."""
    payload = _snapshot_payload(request)
    body = json.dumps(payload, sort_keys=True, default=str, separators=(',', ':'))
    etag = '"' + hashlib.sha1(body.encode('utf-8')).hexdigest() + '"'
    if request.headers.get('If-None-Match') == etag:
        resp = HttpResponse(status=304)
        resp['ETag'] = etag
        resp['Cache-Control'] = 'no-store'
        return resp
    resp = ok({'server_time': iso(timezone.now()), **payload})
    resp['ETag'] = etag
    return resp


# ======================================================================
# CHỦ KHOÁ: xoay secret · gỡ khoá tạm (lockout) · nhật ký NFC · xuất dữ liệu cá nhân
# ======================================================================

@api('POST', auth='any')
def device_rotate_secret(request, device_id):
    """Chủ khoá xoay secret (nhập lại mật khẩu). Secret mới CHỈ trả 1 lần; khoá phải nạp lại, vé BLE cũ mất hiệu lực."""
    device = get_device(request, device_id)
    need_owner(request, device, 'DEVICE_SECRET_ROTATE')
    if not request.user.check_password(str(read_json(request).get('password') or '')):
        services.audit(request, 'DEVICE_SECRET_ROTATE_DENIED', device=device, success=False, severity='warning',
                       metadata={'reason': 'wrong_password'})
        raise ApiError('WRONG_PASSWORD', 'Mật khẩu không đúng.', 400, field='password')
    device, secret = services.rotate_secret(device.id)
    services.audit(request, 'DEVICE_SECRET_ROTATED', device=device, severity='warning', metadata={'channel': request.client_type})
    return ok({'secret': secret, 'message': 'Hãy nạp secret mới vào khoá. Secret này sẽ không hiển thị lại.'})


@api('POST', auth='any')
def device_clear_lockout(request, device_id):
    """Chủ khoá gỡ khoá tạm do nhập sai nhiều lần (giữ nguyên log để bậc khoá luỹ tiến vẫn được tính)."""
    device = get_device(request, device_id)
    need_owner(request, device, 'LOCKOUT_CLEAR')
    if not services.in_lockout(device):
        raise ApiError('NOT_LOCKED', 'Khoá hiện không bị khoá tạm.', 409)
    last = (AuditLog.objects.filter(device=device, action=services.LOCKOUT_ACTION).order_by('-created_at').first())
    last.metadata = {**(last.metadata or {}), 'lockout_seconds': 0, 'cleared_by': str(request.user.id)}
    last.save(update_fields=['metadata'])
    services.audit(request, 'LOCKOUT_CLEARED', device=device, severity='warning', metadata={'channel': request.client_type})
    return ok({'locked_out': services.in_lockout(device)})


@api('GET', auth='any')
def nfc_logs(request):
    """Nhật ký NFC có phân trang (chủ khoá thấy hết, người khác chỉ thấy của mình). ?device=<id>."""
    qs = (NfcLog.objects.filter(device__in=services.devices_with_permission(request.user, 'manage_nfc'))
          .filter(Q(device__owner=request.user) | Q(user=request.user)).select_related('nfc_tag').order_by('-created_at'))
    if request.GET.get('device'):
        qs = qs.filter(device_id=uuid_or_404(request.GET['device']))
    return ok(paginate(request, qs, lambda l: {
        'id': str(l.id), 'device_id': str(l.device_id) if l.device_id else None, 'event_type': l.event_type,
        'success': l.success, 'card': (l.nfc_tag.name or '') if l.nfc_tag_id else '', 'created_at': iso(l.created_at)}))


@api('GET', auth='any')
def me_export(request):
    """Xuất toàn bộ dữ liệu của chính mình (quyền của chủ thể dữ liệu, NĐ 13/2023) - tải về dạng JSON."""
    body = json.dumps({'exported_at': iso(timezone.now()), **_snapshot_payload(request)}, ensure_ascii=False,
                      indent=2, default=str)
    resp = HttpResponse(body, content_type='application/json; charset=utf-8')
    resp['Content-Disposition'] = 'attachment; filename="smartlock-du-lieu-cua-toi.json"'
    resp['Cache-Control'] = 'no-store'
    services.audit(request, 'DATA_EXPORTED', target_user=request.user, metadata={'channel': request.client_type})
    return resp
