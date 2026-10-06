# manage_sys/api/devices.py
import secrets

from django.db import transaction
from django.db.models import Q
from django.shortcuts import get_object_or_404

from smartlock import services
from smartlock.models import (AccessEvent, AuditLog, CardDeviceAccess, Device, DeviceAccess, DeviceCommand,
                              DeviceStatusLog, DoorPinCode, FaceProfile, NfcReader)

from .. import views as legacy
from . import serializers as S
from .common import ApiError, ok, paginate, confirm_sensitive, get_body, as_bool, require_full_power, route

audit, notify = legacy.audit, legacy.notify


def _device(device_id):
    return get_object_or_404(Device.objects.select_related('owner'), id=device_id)


def _secret_response(device, secret, *, rotated, status=200):
    """Secret chỉ có trong ĐÚNG response này (DB chỉ lưu hash). Không cache, có audit REVEALED (không ghi giá trị)."""
    return {'device': S.device_item(device), 'secret': secret, 'rotated': rotated,
            'mqtt': {'username': device.device_code, 'cmd_topic': f'smartlock/{device.device_code}/cmd',
                     'publish_topics': [f'smartlock/{device.device_code}/{c}' for c in ('status', 'ack', 'event')]},
            'note': 'Secret chỉ hiển thị một lần. Nếu chưa chép kịp, hãy xoay secret để tạo mới.'}


def list_devices(request):
    qs = Device.objects.select_related('owner').order_by('name')
    q = (request.GET.get('q') or '').strip()
    if q:
        qs = qs.filter(Q(name__icontains=q) | Q(device_code__icontains=q) | Q(mac_address__icontains=q)
                       | Q(owner__email__icontains=q) | Q(owner__username__icontains=q))
        if not request.GET.get('page'):
            audit(request, 'MANAGE_SEARCH_DEVICES', metadata={'q': q[:80]})
    status = request.GET.get('status') or ''
    if status in dict(Device._meta.get_field('status').choices):
        qs = qs.filter(status=status)
    mode = request.GET.get('mode') or ''
    if mode in ('physical', 'simulated'):
        qs = qs.filter(device_mode=mode)
    items, meta = paginate(request, qs, S.device_item)
    return ok(items, meta=meta)


def create_device(request):
    """Tạo thiết bị mới ở trạng thái 'provisioning' (chưa chủ). `owner` (tuỳ chọn) chỉ để kiểm tra + ghi log;
    việc gán chủ làm sau bằng /claim/ khi khoá đã kết nối."""
    body = get_body(request)
    code = str(body.get('device_code') or '').strip().upper()
    name = str(body.get('name') or '').strip()
    mode = str(body.get('device_mode') or 'physical').strip()
    mac = str(body.get('mac_address') or '').strip().upper().replace('-', ':')
    owner_ref = str(body.get('owner') or '').strip()
    owner = legacy._find_user(owner_ref) if owner_ref else None

    if not legacy._DEVICE_CODE_RE.match(code):
        raise ApiError('validation_error', 'Mã thiết bị 3-50 ký tự (A-Z, 0-9, _ hoặc -).', 400, {'device_code': 'invalid'})
    if not name:
        raise ApiError('validation_error', 'Vui lòng nhập tên thiết bị.', 400, {'name': 'required'})
    if mode not in ('physical', 'simulated'):
        raise ApiError('validation_error', 'Loại thiết bị không hợp lệ.', 400, {'device_mode': 'invalid'})
    if mac and not legacy._MAC_RE.match(mac):
        raise ApiError('validation_error', 'Địa chỉ MAC không hợp lệ (AA:BB:CC:DD:EE:FF).', 400, {'mac_address': 'invalid'})
    if owner_ref and not owner:
        raise ApiError('validation_error', 'Không tìm thấy người dùng với email/username này.', 400, {'owner': 'not_found'})
    if owner and not owner.is_active:
        raise ApiError('validation_error', 'Tài khoản chủ sở hữu đang bị vô hiệu hóa.', 400, {'owner': 'inactive'})
    if owner and legacy.has_manage_role(owner):
        raise ApiError('validation_error', legacy.ADMIN_OWNER_ERROR, 400, {'owner': 'admin_not_allowed'})
    if Device.objects.filter(device_code=code).exists():
        raise ApiError('conflict', 'Mã thiết bị đã tồn tại.', 409, {'device_code': 'duplicate'})

    secret = secrets.token_urlsafe(24)
    device = Device.objects.create(device_code=code, name=name[:100], device_mode=mode, mac_address=mac or None,
                                   owner=None, status='provisioning',
                                   provisioning_secret_hash=services.hash_token(secret))
    audit(request, 'MANAGE_DEVICE_CREATED', device=device, severity='warning',
          metadata={'device_code': code, 'mode': mode, 'pending_owner': owner.email if owner else None})
    audit(request, 'MANAGE_DEVICE_SECRET_REVEALED', device=device, severity='warning')
    data = _secret_response(device, secret, rotated=False)
    data['pending_owner'] = S.user_brief(owner) if owner else None
    return ok(data, status=201)


def get_device(request, device_id):
    device = _device(device_id)
    audit(request, 'MANAGE_VIEW_DEVICE', device=device, target_user=device.owner)
    link = services.link_status(device)
    last = DeviceStatusLog.objects.filter(device=device).order_by('-recorded_at').first()
    return ok({
        **S.device_item(device),
        'link': _link(link),
        'setup': {'mqtt_username': device.device_code, 'secret_fingerprint': (device.provisioning_secret_hash or '')[:8],
                  'cmd_topic': f'smartlock/{device.device_code}/cmd',
                  'publish_topics': [f'smartlock/{device.device_code}/{c}' for c in ('status', 'ack', 'event')]},
        'admin_can_claim': (not device.owner_id) and device.status == 'provisioning',
        'user_must_claim': (not device.owner_id) and device.status == 'revoked',
        'can_sensitive': legacy.has_full_power(request.user),
        'last_status': None if not last else {
            'battery_level': last.battery_level, 'signal_strength': last.signal_strength,
            'lock_state': last.lock_state, 'tamper_detected': last.tamper_detected,
            'temperature': float(last.temperature) if last.temperature is not None else None,
            'recorded_at': S.iso(last.recorded_at)},
        'commands': [S.command_item(c) for c in DeviceCommand.objects.filter(device=device)
                     .select_related('issued_by').order_by('-created_at')[:10]],
        'accesses': [S.access_item(a) for a in DeviceAccess.objects.filter(device=device, is_active=True)
                     .select_related('user').prefetch_related('permissions').order_by('-created_at')],
        'readers': [S.reader_item(r) for r in NfcReader.objects.filter(device=device).order_by('-created_at')],
        'logs': [S.audit_item(a) for a in AuditLog.objects.filter(device=device)
                 .select_related('actor_user', 'target_user', 'device').order_by('-created_at')[:10]],
        # Chỉ METADATA: không bao giờ trả hash PIN / UID thẻ / embedding / ảnh.
        'cards': [{'id': str(c.id), 'name': c.access_card.name, 'owner_email': c.access_card.user.email,
                   'is_active': c.is_active and c.access_card.is_active, 'created_at': S.iso(c.created_at)}
                  for c in CardDeviceAccess.objects.filter(device=device)
                  .select_related('access_card', 'access_card__user').order_by('-created_at')],
        'pins': [{'id': str(p.id), 'label': p.label, 'valid_from': S.iso(p.valid_from),
                  'expires_at': S.iso(p.expires_at), 'max_uses': p.max_uses, 'use_count': p.use_count,
                  'is_revoked': p.is_revoked, 'created_by': p.created_by.email, 'created_at': S.iso(p.created_at)}
                 for p in DoorPinCode.objects.filter(device=device).select_related('created_by')
                 .order_by('-created_at')[:50]],
        'faces': [{'id': str(f.id), 'name': f.name, 'user_email': f.user.email, 'is_active': f.is_active,
                   'consent_confirmed': f.consent_confirmed, 'created_at': S.iso(f.created_at)}
                  for f in FaceProfile.objects.filter(device=device).select_related('user').order_by('-created_at')],
        'access_events': [{'id': str(e.id), 'method': e.method, 'success': e.success, 'reason': e.reason,
                           'user_email': e.user.email if e.user_id else None, 'created_at': S.iso(e.created_at)}
                          for e in AccessEvent.objects.filter(device=device).select_related('user')
                          .order_by('-created_at')[:30]],
    })


def _link(st):
    return {'connected': st['connected'], 'seconds_ago': st['seconds_ago'], 'last_seen_at': S.iso(st['last_seen_at']),
            'firmware': st['firmware'], 'battery': st['battery'], 'status': st['status'],
            'has_owner': st['has_owner'], 'ping_status': st['ping_status'], 'ping_at': S.iso(st['ping_at'])}


def link_status(request, device_id):
    """Dùng để poll chỉ báo 'đã kết nối?' (web gọi lặp mỗi vài giây, app tuỳ ý). Chỉ đọc, không ghi audit."""
    return ok(_link(services.link_status(_device(device_id))))


def maintenance(request, device_id):
    device = _device(device_id)
    on = as_bool(get_body(request).get('on'))
    if not device.owner_id:
        raise ApiError('conflict', 'Thiết bị chưa có chủ sở hữu nên không thể đổi trạng thái.', 409)
    if on and device.status != 'maintenance':
        device.status, log = 'maintenance', 'MANAGE_DEVICE_MAINTENANCE_ON'
        title, msg = 'Thiết bị vào chế độ bảo trì', f'Thiết bị "{device.name}" đang được quản trị viên đặt ở chế độ bảo trì.'
    elif not on and device.status == 'maintenance':
        device.status, log = 'offline', 'MANAGE_DEVICE_MAINTENANCE_OFF'
        title, msg = 'Thiết bị hết bảo trì', f'Thiết bị "{device.name}" đã kết thúc chế độ bảo trì.'
    else:
        return ok({'status': device.status, 'changed': False})
    device.save(update_fields=['status', 'updated_at'])
    audit(request, log, device=device, target_user=device.owner, severity='warning')
    notify(device.owner, title, msg, severity='warning', device=device, type_='DEVICE')
    return ok({'status': device.status, 'changed': True})


def ping(request, device_id):
    device = _device(device_id)
    cmd = services.ping_device(device, issued_by=request.user)
    sent = cmd.status == 'sent'
    audit(request, 'MANAGE_DEVICE_PING', device=device, success=sent,
          metadata={'command_id': str(cmd.id), 'error': getattr(cmd, 'publish_error', '') or None})
    if not sent:
        raise ApiError('broker_error', 'Không gửi được PING tới broker MQTT.', 502)
    return ok({'command_id': str(cmd.id), 'status': cmd.status})


def claim(request, device_id):
    device = _device(device_id)
    owner = legacy._find_user(get_body(request).get('owner'))
    if not owner:
        raise ApiError('validation_error', 'Không tìm thấy người dùng để gán làm chủ.', 400, {'owner': 'not_found'})
    try:
        with transaction.atomic():
            services.claim_device(device.id, owner, by_admin=True)
            audit(request, 'MANAGE_DEVICE_CLAIMED', device=device, target_user=owner, severity='critical',
                  metadata={'owner_email': owner.email}, strict=True)
    except services.ClaimError as exc:
        audit(request, 'MANAGE_DEVICE_CLAIM_FAILED', device=device, target_user=owner, success=False,
              severity='warning', metadata={'code': exc.code})
        raise ApiError(f'claim_{exc.code}', exc.message, 409)
    except services.AuditWriteError:
        raise ApiError('audit_failed', legacy.AUDIT_ERROR, 500)
    notify(owner, 'Bạn đã trở thành chủ khoá', f'Quản trị viên đã gán khoá "{device.name}" cho tài khoản của bạn.',
           device=device, type_='DEVICE')
    device.refresh_from_db()
    return ok(S.device_item(Device.objects.select_related('owner').get(pk=device.pk)))


def remove_owner(request, device_id):
    device = _device(device_id)
    require_full_power(request, 'remove_owner')
    confirm_sensitive(request, get_body(request), device.device_code, upper=True)
    try:
        with transaction.atomic():
            _dev, previous, counts = services.release_device(device.id)
            audit(request, 'MANAGE_DEVICE_OWNER_REMOVED', device=device, target_user=previous, severity='critical',
                  metadata={'previous_owner': previous.email, 'revoked': counts}, strict=True)
    except services.ClaimError as exc:
        raise ApiError(f'claim_{exc.code}', exc.message, 409)
    except services.AuditWriteError:
        raise ApiError('audit_failed', legacy.AUDIT_ERROR, 500)
    notify(previous, 'Khoá đã bị gỡ khỏi tài khoản của bạn',
           f'Quản trị viên đã gỡ chủ sở hữu khoá "{device.name}". Mọi quyền truy cập, thẻ, mã PIN và khuôn mặt của '
           'khoá đã bị vô hiệu hoá. Bạn có thể tự thêm lại bằng mã thiết bị + secret.',
           severity='critical', device=device, type_='DEVICE')
    return ok({'revoked': counts, 'status': 'revoked'})


def rotate_secret(request, device_id):
    device = _device(device_id)
    require_full_power(request, 'rotate_secret')
    confirm_sensitive(request, get_body(request), device.device_code, upper=True)
    try:
        with transaction.atomic():
            dev, secret = services.rotate_secret(device.id)
            audit(request, 'MANAGE_DEVICE_SECRET_ROTATED', device=dev, target_user=dev.owner, severity='critical',
                  strict=True)
    except services.AuditWriteError:
        raise ApiError('audit_failed', legacy.AUDIT_ERROR, 500)
    audit(request, 'MANAGE_DEVICE_SECRET_REVEALED', device=dev, severity='warning')
    if dev.owner_id:
        notify(dev.owner, 'Secret thiết bị đã được đổi',
               f'Quản trị viên đã đổi secret kết nối của "{dev.name}". Thiết bị cần được nạp lại secret mới.',
               severity='warning', device=dev, type_='DEVICE')
    return ok(_secret_response(dev, secret, rotated=True))


devices_view = route({'GET': list_devices, 'POST': create_device})
device_detail_view = route({'GET': get_device})
device_link_view = route({'GET': link_status})
device_maintenance_view = route({'POST': maintenance})
device_ping_view = route({'POST': ping})
device_claim_view = route({'POST': claim})
device_remove_owner_view = route({'POST': remove_owner})
device_rotate_secret_view = route({'POST': rotate_secret})
