# smartlock/access_control.py


import hashlib
import logging
import math
import secrets
from datetime import timedelta

from django.db import transaction
from django.utils import timezone

from .models import (
    AccessCard, AccessEvent, AuditLog, Device, DeviceCommand, DoorPinCode,
    FaceProfile, Notification, User,
)
from .mqtt_client import publish_command, MqttPublishError

logger = logging.getLogger('smartlock.access_control')

# Ngưỡng tự khoá tạm sau nhiều lần thất bại liên tiếp trên CÙNG một thiết bị, bất kể
# kênh nào (RFID/PIN/khuôn mặt) - khớp với kịch bản demo bắt buộc #2 của A2:
# "Quẹt thẻ lạ 3 lần -> khoá tạm 60 giây, còi kêu, gửi cảnh báo cho chủ nhà".
BURST_FAIL_THRESHOLD = 3
BURST_FAIL_WINDOW_SECONDS = 60
BURST_LOCKOUT_SECONDS = 60


def _hash(value: str) -> str:
    return hashlib.sha256(str(value).encode()).hexdigest()


def _send_unlock_command(device: Device, source: str, extra: dict) -> bool:
    """Tạo DeviceCommand + publish MQTT lệnh UNLOCK. Trả True nếu publish thành công.
    Nếu MQTT publish lỗi, KHÔNG coi là 'mở cửa thành công' - view/subscriber gọi hàm
    này phải tự quyết định có báo lỗi cho người dùng hay không."""
    cmd = DeviceCommand.objects.create(
        device=device, issued_by=device.owner, command_type='UNLOCK', status='pending',
        command_token_hash=_hash(secrets.token_urlsafe(32)),
        expires_at=timezone.now() + timedelta(seconds=30),
    )
    try:
        publish_command(device.device_code, {
            'command_id': str(cmd.id), 'command': 'UNLOCK',
            'token': cmd.command_token_hash, 'source': source, **extra,
        })
        cmd.status = 'sent'
        cmd.save(update_fields=['status'])
        return True
    except MqttPublishError as e:
        cmd.status = 'failed'
        cmd.save(update_fields=['status'])
        logger.warning('access_control: publish UNLOCK thất bại cho %s: %s', device.device_code, e)
        return False


def _recent_fail_count(device: Device) -> int:
    since = timezone.now() - timedelta(seconds=BURST_FAIL_WINDOW_SECONDS)
    return AccessEvent.objects.filter(device=device, success=False, created_at__gte=since).count()


def _is_in_burst_lockout(device: Device) -> bool:
    """True nếu thiết bị đang trong thời gian khoá tạm do quẹt/nhập sai liên tiếp."""
    since = timezone.now() - timedelta(seconds=BURST_LOCKOUT_SECONDS)
    last_trip = (
        AuditLog.objects.filter(device=device, action='ACCESS_BURST_LOCKOUT', created_at__gte=since)
        .order_by('-created_at').first()
    )
    return last_trip is not None


def _handle_burst_if_needed(device: Device):
    """Sau mỗi lần thất bại: nếu vượt ngưỡng trong cửa sổ thời gian thì khoá tạm +
    báo còi (qua lệnh MQTT riêng cho firmware) + thông báo cho chủ nhà."""
    if _recent_fail_count(device) < BURST_FAIL_THRESHOLD:
        return
    AuditLog.objects.create(
        device=device, action='ACCESS_BURST_LOCKOUT', severity='critical', success=False,
        metadata={'threshold': BURST_FAIL_THRESHOLD, 'window_seconds': BURST_FAIL_WINDOW_SECONDS},
    )
    try:
        publish_command(device.device_code, {'command': 'BUZZER_ALERT', 'reason': 'ACCESS_BURST'})
    except MqttPublishError:
        pass  # còi là phụ trợ; không được để lỗi MQTT làm hỏng luồng khoá tạm
    if device.owner_id:
        Notification.objects.create(
            user=device.owner, device=device, type='ACCESS_BURST', severity='critical',
            title='Cảnh báo: nhiều lần mở cửa sai liên tiếp'[:150],
            message=(f'Thiết bị "{device.name}" bị {BURST_FAIL_THRESHOLD}+ lần quẹt thẻ/nhập PIN/'
                     f'nhận diện sai trong {BURST_FAIL_WINDOW_SECONDS}s. Đã khoá tạm {BURST_LOCKOUT_SECONDS}s.'),
        )


def _log_event(**kwargs) -> AccessEvent:
    event = AccessEvent.objects.create(**kwargs)
    if not event.success:
        _handle_burst_if_needed(event.device)
    return event


# ==================== RFID ====================
def verify_rfid_tap(device: Device, raw_uid: str, ip_address=None) -> AccessEvent:
    """Thiết bị đọc UID thẻ qua RC522 (SPI, tại biên) và publish UID lên MQTT event
    topic; server chỉ có nhiệm vụ SO KHỚP UID (đã hash) với DB và ra lệnh mở."""
    with transaction.atomic():
        if _is_in_burst_lockout(device):
            return _log_event(device=device, method=AccessEvent.METHOD_RFID, success=False,
                               reason='DEVICE_LOCKED_OUT', ip_address=ip_address)

        uid_hash = _hash(raw_uid.strip().upper())
        card = AccessCard.objects.filter(
            card_uid_hash=uid_hash, is_active=True, carddeviceaccess__device=device,
            carddeviceaccess__is_active=True,
        ).first()
        if not card:
            return _log_event(device=device, method=AccessEvent.METHOD_RFID, success=False,
                               reason='UNKNOWN_CARD', ip_address=ip_address)

    ok = _send_unlock_command(device, source='rfid', extra={'card_id': str(card.id)})
    return _log_event(device=device, method=AccessEvent.METHOD_RFID, success=ok,
                       reason=None if ok else 'MQTT_PUBLISH_FAILED', user=card.user,
                       access_card=card, ip_address=ip_address)


# ==================== PIN ====================
def verify_door_pin(device: Device, raw_pin: str, ip_address=None) -> AccessEvent:
    """Khách gõ PIN trên bàn phím ma trận -> firmware publish PIN (qua MQTT/TLS) ->
    server tra hash, kiểm tra hạn dùng/số lần dùng còn lại rồi mới ra lệnh mở."""
    with transaction.atomic():
        if _is_in_burst_lockout(device):
            return _log_event(device=device, method=AccessEvent.METHOD_PIN, success=False,
                               reason='DEVICE_LOCKED_OUT', ip_address=ip_address)

        candidates = DoorPinCode.objects.filter(
            device=device, is_revoked=False, valid_from__lte=timezone.now(), expires_at__gt=timezone.now(),
        ).select_for_update()
        matched = next((p for p in candidates if p.check_pin(raw_pin) and p.is_valid_now()), None)
        if not matched:
            return _log_event(device=device, method=AccessEvent.METHOD_PIN, success=False,
                               reason='INVALID_OR_EXPIRED_PIN', ip_address=ip_address)
        matched.register_use()

    ok = _send_unlock_command(device, source='pin', extra={'pin_id': str(matched.id)})
    return _log_event(device=device, method=AccessEvent.METHOD_PIN, success=ok,
                       reason=None if ok else 'MQTT_PUBLISH_FAILED',
                       door_pin=matched, user=matched.created_by, ip_address=ip_address)


def issue_door_pin(device: Device, created_by: User, plain_pin: str, ttl_minutes: int,
                    label: str = '', max_uses: int = 1) -> DoorPinCode:
    """Chủ nhà cấp 1 mã PIN mới cho khách. plain_pin do view sinh (vd 6 chữ số ngẫu
    nhiên) và CHỈ hiển thị 1 lần cho chủ nhà để gửi cho khách - không lưu dạng thô."""
    pin = DoorPinCode(device=device, created_by=created_by, label=label,
                       expires_at=timezone.now() + timedelta(minutes=ttl_minutes), max_uses=max_uses)
    pin.set_pin(plain_pin)
    pin.save()
    AuditLog.objects.create(actor_user=created_by, device=device, action='DOOR_PIN_ISSUED',
                             metadata={'pin_id': str(pin.id), 'ttl_minutes': ttl_minutes, 'label': label})
    return pin


# ==================== KHUÔN MẶT ====================
def _euclidean_distance(a, b) -> float:
    if len(a) != len(b) or not a:
        return math.inf
    return math.sqrt(sum((x - y) ** 2 for x, y in zip(a, b)))


def verify_face(device: Device, embedding: list, snapshot_url: str = '', ip_address=None) -> AccessEvent:
    """
    embedding: vector đặc trưng do thiết bị biên (ESP32-CAM) hoặc dịch vụ suy luận
    trung gian tính sẵn rồi gửi lên - server KHÔNG chạy mô hình nhận diện, chỉ so khớp
    khoảng cách Euclid với các FaceProfile đang active của device này (đúng tinh thần
    "nhận diện khuôn mặt tại biên" của đề bài, tách khỏi phần suy luận nặng).
    """
    if _is_in_burst_lockout(device):
        return _log_event(device=device, method=AccessEvent.METHOD_FACE, success=False,
                           reason='DEVICE_LOCKED_OUT', snapshot_url=snapshot_url, ip_address=ip_address)

    best_profile, best_distance = None, math.inf
    for profile in FaceProfile.objects.filter(device=device, is_active=True):
        d = _euclidean_distance(embedding, profile.get_embedding())
        if d < best_distance:
            best_profile, best_distance = profile, d

    if not best_profile or best_distance > best_profile.threshold:
        return _log_event(device=device, method=AccessEvent.METHOD_FACE, success=False,
                           reason='NO_MATCH', confidence=None, snapshot_url=snapshot_url,
                           ip_address=ip_address)

    confidence = max(0.0, 1 - (best_distance / best_profile.threshold))
    ok = _send_unlock_command(device, source='face', extra={'face_profile_id': str(best_profile.id)})
    return _log_event(device=device, method=AccessEvent.METHOD_FACE, success=ok,
                       reason=None if ok else 'MQTT_PUBLISH_FAILED', user=best_profile.user,
                       face_profile=best_profile, confidence=round(confidence, 4),
                       snapshot_url=snapshot_url, ip_address=ip_address)


def register_face(device: Device, user: User, embedding: list, name: str = '',
                   consent_confirmed: bool = False) -> FaceProfile:
    profile, _created = FaceProfile.objects.update_or_create(
        user=user, device=device,
        defaults={'name': name, 'consent_confirmed': consent_confirmed, 'is_active': True},
    )
    profile.set_embedding(embedding)
    profile.save()
    AuditLog.objects.create(actor_user=user, device=device, action='FACE_PROFILE_REGISTERED',
                             metadata={'face_profile_id': str(profile.id)})
    return profile