"""Quyền vào cửa - PIN khách, thẻ NFC, đầu đọc, khuôn mặt, chia sẻ khoá."""
from django.db import IntegrityError, transaction
from django.db.models import Q
from django.utils import timezone

from .serializers import get_device, managed_device, need_owner
from smartlock import services
from smartlock.api.common import api, ApiError, iso, ok, parse_iso, read_json, s, uuid_or_404
from smartlock.models import (
    AccessCard,
    CardDeviceAccess,
    DeviceAccess,
    DeviceCommand,
    DoorPinCode,
    FaceProfile,
    NfcLog,
    NfcReader,
    Permission,
)


# ======================================================================
# pins.py - Mã PIN cho khách.
# ======================================================================

def _pin_json(p, owner_view=False) -> dict:
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


@api('DELETE', auth='any')
def pin_revoke(request, pin_id):
    pin = DoorPinCode.objects.select_related('device').filter(pk=uuid_or_404(pin_id)).first()
    if pin and not (services.accessible_devices(request.user).filter(pk=pin.device_id).exists()
                    and services.has_permission(request.user, pin.device, 'manage_pins')):
        pin = None
    if pin and pin.device.owner_id != request.user.id and pin.created_by_id != request.user.id:
        pin = None
    if not pin:
        raise ApiError('NOT_FOUND', 'Không tìm thấy mã PIN.', 404)
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
        perms = _wanted_permissions(read_json(request))
        old = sorted(p.code for p in access.permissions.all())
        access.permissions.set(perms)
        services.audit(request, 'ACCESS_UPDATED', device=device, target_user=access.user,
                       metadata={'access_id': str(access.id), 'from': old, 'to': sorted(p.code for p in perms)})
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
