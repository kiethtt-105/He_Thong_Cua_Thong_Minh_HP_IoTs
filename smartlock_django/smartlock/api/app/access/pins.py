"""Mã PIN cho khách."""
from smartlock import services
from smartlock.api.common import api, ApiError, iso, ok, read_json, s, uuid_or_404
from smartlock.models import DoorPinCode

from ..helpers import managed_device


def _pin_json(p, owner_view=False) -> dict:
    return {
        'id': str(p.id), 'device_id': str(p.device_id), 'label': p.label or '', 'valid_from': iso(p.valid_from),
        'expires_at': iso(p.expires_at), 'max_uses': p.max_uses, 'use_count': p.use_count,
        'is_revoked': p.is_revoked, 'is_valid_now': p.is_valid_now(), 'created_at': iso(p.created_at),
        'created_by': (p.created_by.full_name or p.created_by.username),
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
