"""Thẻ NFC / RFID của người dùng."""
from django.db import IntegrityError, transaction
from django.db.models import Q

from smartlock import services
from smartlock.api.common import api, ApiError, iso, ok, read_json, s, uuid_or_404
from smartlock.models import AccessCard, CardDeviceAccess, NfcLog, NfcReader

from .helpers import managed_device


def _card_json(c, user, owned_ids) -> dict:
    mine = c.user_id == user.id
    links = [l for l in c.carddeviceaccess_set.all() if mine or l.device_id in owned_ids]
    return {
        'id': str(c.id), 'name': c.name or '', 'is_active': c.is_active, 'is_mine': mine,
        'owner': '' if mine else c.user.username, 'created_at': iso(c.created_at),
        'devices': [{'device_id': str(l.device_id), 'device_name': l.device.name, 'is_active': l.is_active}
                    for l in links],
    }


@api('GET')
def cards_list(request):
    user = request.user
    managed = list(services.devices_with_permission(user, 'manage_nfc').values_list('id', 'owner_id'))
    owned_ids = {i for i, o in managed if o == user.id}
    cards = (AccessCard.objects.filter(Q(user=user) | Q(carddeviceaccess__device_id__in=owned_ids)).distinct()
             .select_related('user').prefetch_related('carddeviceaccess_set__device').order_by('-created_at'))
    return ok({'cards': [_card_json(c, user, owned_ids) for c in cards]})


@api('PATCH', 'DELETE')
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


@api('PATCH')
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
    link.is_active = data['is_active']
    link.save(update_fields=['is_active'])
    services.audit(request, 'CARD_LINK_ENABLED' if link.is_active else 'CARD_LINK_DISABLED', device=link.device,
                   target_user=link.access_card.user, metadata={'card_id': str(link.access_card_id)})
    return ok({'is_active': link.is_active})


@api('POST')
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
