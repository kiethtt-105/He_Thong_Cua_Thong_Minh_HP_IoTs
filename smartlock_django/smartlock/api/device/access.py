"""API khoá - quẹt thẻ / PIN / khuôn mặt / điện thoại."""
import math
import re

from .auth import device_api, need_owner
from smartlock import services
from smartlock.api.common import ApiError, ok, read_json, s


# ======================================================================
# access.py - POST /device/access/* - quẹt thẻ / PIN / khuôn mặt / điện thoại: server phán quyết, khoá CHỈ mở khi granted == true.
# ======================================================================

def _verdict(event, device):
    return ok({'granted': bool(event.success), 'reason': event.reason or None,
               'locked_out': services.in_lockout(device), 'event_id': str(event.id)})


@device_api('POST')
def access_rfid(request):
    device, data = request.device, read_json(request)
    need_owner(device)
    uid = services.normalize_uid(s(data, 'uid', 64))
    if len(uid) < 4:
        raise ApiError('BAD_UID', 'UID thẻ không hợp lệ.', 400, field='uid')
    if not device.nfc_enabled:
        return ok({'granted': False, 'reason': 'NFC_DISABLED', 'locked_out': services.in_lockout(device)})
    services.touch_device(device)
    return _verdict(services.verify_rfid_tap(device, uid, ip_address=services.client_ip(request)), device)


@device_api('POST')
def access_pin(request):
    device, data = request.device, read_json(request)
    need_owner(device)
    pin = re.sub(r'\D', '', s(data, 'pin', 16))
    if not (4 <= len(pin) <= 8):
        raise ApiError('BAD_PIN', 'PIN phải gồm 4-8 chữ số.', 400, field='pin')
    services.touch_device(device)
    return _verdict(services.verify_door_pin(device, pin, ip_address=services.client_ip(request)), device)


@device_api('POST')
def access_face(request):
    """{embedding: [128 số], snapshot_url?} - khoá/camera tự trích embedding, server chỉ so khớp."""
    device, data = request.device, read_json(request)
    need_owner(device)
    emb = data.get('embedding')
    if not isinstance(emb, list) or not (1 <= len(emb) <= 512):
        raise ApiError('BAD_EMBEDDING', 'embedding phải là mảng số.', 400, field='embedding')
    try:
        emb = [float(x) for x in emb]
    except (TypeError, ValueError):
        raise ApiError('BAD_EMBEDDING', 'embedding phải là mảng số.', 400, field='embedding')
    if not all(math.isfinite(x) for x in emb):
        raise ApiError('BAD_EMBEDDING', 'embedding chứa giá trị không hợp lệ.', 400, field='embedding')
    services.touch_device(device)
    event = services.verify_face(device, emb, snapshot_url=s(data, 'snapshot_url', 512),
                                 ip_address=services.client_ip(request))
    return _verdict(event, device)


@device_api('POST')
def access_phone(request):
    """Khoá TỰ kiểm vé BLE/NFC offline rồi báo log về sau. Một sự kiện hoặc {"events": [...]} (tối đa 50):
        {channel: 'ble'|'nfc', ticket, ok: bool, reason?, at?: unix_giây}
    Server xác minh lại chữ ký/hạn/quyền của vé trước khi ghi nhận thành công."""
    device, data = request.device, read_json(request)
    need_owner(device)
    items = data.get('events') if isinstance(data.get('events'), list) else [data]
    if not items or len(items) > 50:
        raise ApiError('BAD_EVENTS', 'Cần 1-50 sự kiện.', 400)
    results = []
    for it in items:
        if not isinstance(it, dict):
            continue
        channel = str(it.get('channel') or '').lower()
        if channel not in services.PHONE_CHANNELS:
            raise ApiError('BAD_CHANNEL', 'channel phải là "ble" hoặc "nfc".', 400)
        recorder = services.record_ble_unlock if channel == 'ble' else services.record_nfc_phone_unlock
        event = recorder(device, ticket=str(it.get('ticket') or '')[:200], ok=it.get('ok') is not False,
                         reason=str(it.get('reason') or '')[:100] or None, at=it.get('at'))
        results.append({'channel': channel, 'accepted': bool(event.success), 'reason': event.reason or None,
                        'event_id': str(event.id)})
    services.touch_device(device)
    return ok({'results': results})
