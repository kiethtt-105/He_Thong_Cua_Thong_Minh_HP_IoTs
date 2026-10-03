"""Đầu đọc NFC gắn với khoá (kể cả cửa sổ quẹt-để-đăng-ký)."""
from django.db import transaction
from django.utils import timezone

from smartlock import services
from smartlock.api.common import api, ApiError, iso, ok, read_json, s, uuid_or_404
from smartlock.models import NfcLog, NfcReader

from .helpers import managed_device, need_owner


def _reader_json(r) -> dict:
    left = max(0, int((r.auto_register_until - timezone.now()).total_seconds())) if r.auto_register_active else 0
    return {'id': str(r.id), 'device_id': str(r.device_id), 'name': r.name or '', 'reader_mode': r.reader_mode,
            'is_active': r.is_active, 'auto_register': r.auto_register_active,
            'auto_register_seconds_left': left, 'last_seen_at': iso(r.last_seen_at)}


@api('GET', 'POST')
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


@api('PATCH')
def reader_detail(request, reader_id):
    reader = NfcReader.objects.select_related('device').filter(pk=uuid_or_404(reader_id)).first()
    if not reader or not services.accessible_devices(request.user).filter(pk=reader.device_id).exists():
        raise ApiError('NOT_FOUND', 'Không tìm thấy đầu đọc.', 404)
    need_owner(request, reader.device, 'NFC_READER')
    if not reader.device.nfc_enabled:
        raise ApiError('NFC_DISABLED', 'NFC của khoá đang tắt.', 409)
    data = read_json(request)
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
