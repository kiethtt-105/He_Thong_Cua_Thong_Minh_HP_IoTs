# smartlock/services.py
"""

Mục lục
  1. Helper chung (hash, IP, audit, quyền, đăng nhập sai, gửi mail xác thực)
  2. Email (render HTML + bản text tự sinh)
  3. MQTT + gửi lệnh xuống thiết bị
  4. Mở khoá: RFID / PIN / khuôn mặt / Bluetooth + khoá tạm khi sai liên tiếp
  5. Rule engine (luật cảnh báo do user cấu hình)
  6. Push FCM tới app Android
"""
import hashlib
import hmac
import ipaddress
import json
import logging
import math
import os
import re
import secrets
import time
import uuid
from datetime import datetime, timedelta, timezone as dt_timezone
from decimal import Decimal
from email.utils import parseaddr
from typing import Optional

from django.conf import settings
from django.core.mail import send_mail as _django_send_mail
from django.db import transaction
from django.db.models import F, Q
from django.db.models.signals import post_save
from django.template.loader import render_to_string
from django.urls import reverse
from django.utils import timezone
from django.utils.html import linebreaks, strip_tags, urlize

from .models import (
    AccessCard, AccessEvent, AuditLog, AutomationRule, AutomationRuleLog, Device, DeviceAccess,
    DeviceCommand, DeviceStatusLog, DoorPinCode, FaceProfile, Notification, OneTimeCode,
    SystemSettings, User, hash_card_uid,
)

logger = logging.getLogger('smartlock.services')


# ============================================================================
# 1. HELPER CHUNG
# ============================================================================
MAX_FAILED_ATTEMPTS = 5          # đăng nhập sai bao nhiêu lần thì khoá tài khoản tạm


def send_mail(subject, plain, html, to, log_body=True) -> bool:
    # log_body=False: không ghi nội dung mail vào log (dùng cho mail chứa mã OTP)
    logger.info('send_mail: to=%s subject=%r plain_preview=%r', to, subject,
                plain[:200] if log_body else '<ẩn nội dung>')
    try:
        n = _django_send_mail(subject, plain, None, [to], html_message=html)
        logger.info('send_mail: OK (%s mail) -> %s', n, to)
        return True
    except Exception:
        logger.exception('send_mail: THẤT BẠI -> %s', to)
        return False


def hash_token(token) -> str:
    return hashlib.sha256(str(token).encode()).hexdigest()


def valid_ip(value):
    try:
        return str(ipaddress.ip_address((value or '').strip()))
    except ValueError:
        return None


def client_ip(request) -> str:
    """Chỉ tin X-Forwarded-For khi settings.TRUST_PROXY_HEADERS = True (đứng sau proxy).
    Phần tử ĐẦU của XFF do client tự đặt được -> lấy IP do proxy TIN CẬY ghi, tức phần tử thứ
    TRUST_PROXY_COUNT tính từ cuối (mặc định 1 = proxy ngay phía trước).
    Luôn trả về IP hợp lệ để không làm hỏng ghi log / GenericIPAddressField."""
    ip = None
    if getattr(settings, 'TRUST_PROXY_HEADERS', False):
        parts = [p.strip() for p in (request.META.get('HTTP_X_FORWARDED_FOR') or '').split(',') if p.strip()]
        n = max(1, int(getattr(settings, 'TRUST_PROXY_COUNT', 1) or 1))
        if parts:
            ip = valid_ip(parts[-n] if len(parts) >= n else parts[0])
    return ip or valid_ip(request.META.get('REMOTE_ADDR')) or '0.0.0.0'


def user_agent(request) -> str:
    return (request.META.get('HTTP_USER_AGENT') or '')[:500]


def system_settings() -> SystemSettings:
    return SystemSettings.objects.get_or_create(pk=1)[0]


def is_admin(user) -> bool:
    return bool(user.is_staff or user.is_superuser or user.is_admin)


def admins():
    """Tài khoản quản trị (đang active) để gửi email thông báo cho admin."""
    return User.objects.filter(Q(is_staff=True) | Q(is_superuser=True) | Q(is_admin=True),
                               is_active=True).exclude(email='')


def parse_uuid(value) -> Optional[uuid.UUID]:
    try:
        return uuid.UUID(str(value))
    except (ValueError, AttributeError, TypeError):
        return None


def parse_dt(value):
    if not value:
        return None
    try:
        return timezone.make_aware(datetime.strptime(value, '%Y-%m-%dT%H:%M'))
    except ValueError:
        return None


def find_user(identifier):
    identifier = (identifier or '').strip()
    if not identifier:
        return None
    return User.objects.filter(Q(email__iexact=identifier) | Q(username__iexact=identifier)).first()


def audit(request, action, *, device=None, target_user=None, success=True,
          severity='info', metadata=None, actor='auto', username_attempt=None):
    if actor == 'auto':
        actor = request.user if request.user.is_authenticated else None
    try:
        with transaction.atomic():  # savepoint: lỗi ghi log không làm hỏng transaction bên ngoài
            AuditLog.objects.create(
                actor_user=actor, target_user=target_user, device=device, action=action[:50],
                username_attempt=username_attempt, severity=severity, success=success,
                ip_address=client_ip(request), user_agent=user_agent(request), metadata=metadata,
            )
    except Exception:
        logger.exception('audit: không ghi được log %s', action)


def notify(user, title, message, severity='info', device=None, type_='SYSTEM'):
    Notification.objects.create(
        user=user, device=device, type=type_, title=title[:150], message=message, severity=severity,
    )


def ip_blacklisted(ip) -> bool:
    lines = [l.strip() for l in (system_settings().ip_blacklist or '').splitlines()]
    return ip in [l for l in lines if l]


def accessible_devices(user):
    now = timezone.now()
    shared_ids = (
        DeviceAccess.objects.filter(user=user, is_active=True, accepted=True, valid_from__lte=now)
        .filter(Q(expires_at__isnull=True) | Q(expires_at__gt=now))
        .values('device_id')
    )
    return Device.objects.filter(Q(owner=user) | Q(id__in=shared_ids))


def has_permission(user, device, code) -> bool:
    if device.owner_id == user.id:
        return True
    now = timezone.now()
    return DeviceAccess.objects.filter(
        device=device, user=user, is_active=True, accepted=True,
        valid_from__lte=now, permissions__code=code,
    ).filter(Q(expires_at__isnull=True) | Q(expires_at__gt=now)).exists()


def pick_device(queryset, raw_id, strict=False):
    """strict=True (dùng cho POST): id gửi lên phải khớp đúng thiết bị,
    không được âm thầm rơi về thiết bị đầu tiên (thao tác nhầm thiết bị)."""
    dev_id = parse_uuid(raw_id)
    if strict:
        return queryset.filter(id=dev_id).first() if dev_id else None
    device = queryset.filter(id=dev_id).first() if dev_id else None
    return device or queryset.first()


def register_failure(user, ip):
    """Ghi 1 lần đăng nhập sai. Trả về số phút bị khoá nếu vừa kích hoạt khoá, ngược lại None."""
    stages = system_settings().login_lockout_stage_minutes or [5, 10, 30]
    now = timezone.now()
    locked_minutes = None
    with transaction.atomic():
        lock = User.objects.select_for_update().get(pk=user.pk)
        lock.login_failed_attempts += 1
        lock.login_last_failed_at = now
        lock.login_last_failed_ip = ip
        if lock.login_failed_attempts >= MAX_FAILED_ATTEMPTS:
            locked_minutes = stages[min(lock.login_lock_stage, len(stages) - 1)]
            lock.login_locked_until = now + timedelta(minutes=locked_minutes)
            lock.login_lock_stage += 1
            lock.login_failed_attempts = 0
        lock.save(update_fields=['login_failed_attempts', 'login_last_failed_at', 'login_last_failed_ip',
                                 'login_locked_until', 'login_lock_stage', 'updated_at'])
    if locked_minutes:
        notify(user, 'Tài khoản bị khóa tạm thời',
               f'Đăng nhập sai nhiều lần từ IP {ip}. Tài khoản bị khóa {locked_minutes} phút.',
               severity='critical', type_='LOGIN_LOCKOUT')
    return locked_minutes


def reset_lockout(user):
    User.objects.filter(pk=user.pk).update(
        login_failed_attempts=0, login_lock_stage=0, login_locked_until=None,
    )


def send_verification(request, user) -> bool:
    minutes = system_settings().verification_token_expiry_minutes
    OneTimeCode.objects.filter(
        user=user, purpose='EMAIL_VERIFY', is_used=False,
    ).update(is_used=True, used_at=timezone.now())

    token = uuid.uuid4()
    OneTimeCode.objects.create(
        user=user, purpose='EMAIL_VERIFY', token_hash=hash_token(token),
        expires_at=timezone.now() + timedelta(minutes=minutes),
    )
    link = request.build_absolute_uri(reverse('smartlock:verify_email', args=[token]))
    subject, html, plain = render_email('user_verification.html', {
        'full_name': user.full_name or user.username,
        'username': user.username,
        'verification_link': link,
        'expiry_minutes': minutes,
    })
    return send_mail(subject, plain, html, user.email)


# ============================================================================
# 2. EMAIL
# ============================================================================
BRAND_NAME = 'Smart Lock'

# Chỉ giữ tiêu đề. Nội dung HTML nằm ở templates/emails/<tên>; bản text tự sinh từ HTML.
EMAIL_SUBJECTS = {
    'user_verification.html': 'Xác thực tài khoản Smart Lock',
    'password_reset.html': 'Đặt lại mật khẩu Smart Lock',
    'device_added.html': 'Thiết bị mới đã được thêm vào tài khoản của bạn',
    'share_code_notification.html': 'Bạn đã nhận được mã chia sẻ khóa',
    'admin_nfc_approval.html': 'Yêu cầu kích hoạt thẻ NFC mới',
    'admin_device_approval.html': 'Thiết bị mới cần kích hoạt',
    'recovery_notification.html': 'Thông báo khôi phục thiết bị',
    'two_factor_code.html': 'Mã xác thực 2 lớp Smart Lock',
    'system_announcement.html': 'Thông báo hệ thống',
}


def _email_context(context: dict, template_name: str) -> dict:
    ctx = dict(context)
    if template_name == 'system_announcement.html' and not ctx.get('title'):
        ctx['title'] = 'Thông báo hệ thống'
    # views truyền 'reset_link'; template dùng 'password_reset_link'
    if not ctx.get('password_reset_link') and ctx.get('reset_link'):
        ctx['password_reset_link'] = ctx['reset_link']
    ctx.setdefault('brand_name', BRAND_NAME)
    ctx.setdefault('year', timezone.now().year)
    if 'support_email' not in ctx:
        ctx['support_email'] = parseaddr(getattr(settings, 'DEFAULT_FROM_EMAIL', '') or '')[1]
    return ctx


def _html_to_text(html: str) -> str:
    html = re.sub(r'(?is)<(head|style|script).*?</\1>', '', html)
    html = re.sub(r'(?is)<div style="display:none.*?</div>', '', html)   # dòng preheader ẩn
    html = re.sub(r'(?i)<br\s*/?>|</p>|</tr>|</h1>|</div>', '\n', html)
    text = strip_tags(html)
    text = re.sub(r'[ \t\xa0]+', ' ', text)
    text = re.sub(r'\n\s*\n+', '\n\n', text)
    return text.strip()


def render_email(template_name: str, context: dict) -> tuple:
    """Trả về (subject, html, plain_text)."""
    subject = EMAIL_SUBJECTS.get(template_name) or template_name.replace('.html', '').replace('_', ' ').title()
    ctx = _email_context(context, template_name)
    try:
        html = render_to_string(f'emails/{template_name}', ctx)
        plain = _html_to_text(html)
        if ctx.get('action_url'):
            plain += f"\n\nTruy cập: {ctx['action_url']}"
    except Exception:
        logger.exception('render_email: lỗi khi render emails/%s', template_name)
        keys = ('verification_link', 'password_reset_link', 'otp_code', 'share_code', 'action_url')
        plain = '\n'.join(str(ctx[k]) for k in keys if ctx.get(k)) or subject
        html = linebreaks(urlize(plain, autoescape=True))
    return subject, html, plain


# ============================================================================
# 3. MQTT + GỬI LỆNH
# ============================================================================
# Chấp nhận cả MQTT_BROKER_* lẫn MQTT_HOST/MQTT_PORT để .env đặt tên nào cũng có tác dụng.
MQTT_BROKER_HOST = os.environ.get('MQTT_BROKER_HOST') or os.environ.get('MQTT_HOST') or 'localhost'
try:
    MQTT_BROKER_PORT = int(os.environ.get('MQTT_BROKER_PORT') or os.environ.get('MQTT_PORT') or '1883')
except ValueError:
    MQTT_BROKER_PORT = 1883
MQTT_USE_TLS = os.environ.get('MQTT_BROKER_USE_TLS', '').lower() in ('1', 'true', 'yes')
MQTT_PUBLISHER_USERNAME = os.environ.get('MQTT_PUBLISHER_USERNAME', '')
MQTT_PUBLISHER_PASSWORD = os.environ.get('MQTT_PUBLISHER_PASSWORD', '')


class MqttPublishError(Exception):
    """Không publish được lệnh xuống thiết bị (broker down, timeout...)."""


def cmd_topic(device_code: str) -> str:
    return f'smartlock/{device_code}/cmd'


STATUS_TOPIC = 'smartlock/+/status'
EVENT_TOPIC = 'smartlock/+/event'
ACK_TOPIC = 'smartlock/+/ack'


def publish_command(device_code: str, payload: dict) -> None:
    """Publish 1 lệnh xuống thiết bị (QoS 1), kiểu connect ngắn hạn - publish - disconnect
    để an toàn khi chạy nhiều worker. Raise MqttPublishError nếu không publish được."""
    try:
        import paho.mqtt.publish as mqtt_publish
    except ImportError as e:
        raise MqttPublishError('Chưa cài paho-mqtt (pip install "paho-mqtt<2").') from e

    auth = None
    if MQTT_PUBLISHER_USERNAME:
        auth = {'username': MQTT_PUBLISHER_USERNAME, 'password': MQTT_PUBLISHER_PASSWORD}
    try:
        mqtt_publish.single(
            topic=cmd_topic(device_code),
            payload=json.dumps(payload, ensure_ascii=False),
            qos=1, retain=False,
            hostname=MQTT_BROKER_HOST, port=MQTT_BROKER_PORT, auth=auth,
            tls={'ca_certs': None} if MQTT_USE_TLS else None,
            client_id=f'django-pub-{uuid.uuid4().hex[:16]}',  # unique mỗi lần: tránh broker đá kết nối trùng
        )
    except Exception as e:
        logger.warning('MQTT publish thất bại tới %s: %s', device_code, e)
        raise MqttPublishError(str(e)) from e


def dispatch_command(device, command, *, source, issued_by=None, ttl=30, extra=None) -> DeviceCommand:
    """Tạo DeviceCommand + publish MQTT. Trả về DeviceCommand; status == 'sent' nghĩa là
    publish thành công, 'failed' nghĩa là lỗi (lý do nằm ở cmd.publish_error).
    Thiết bị phải có owner (hoặc truyền issued_by), nếu không raise ValueError."""
    issuer = issued_by or device.owner
    if issuer is None:
        raise ValueError(f'Thiết bị {device.device_code} chưa có chủ sở hữu, không thể gửi lệnh.')
    cmd = DeviceCommand.objects.create(
        device=device, issued_by=issuer, command_type=command, status='pending',
        command_token_hash=hash_token(secrets.token_urlsafe(32)),
        expires_at=timezone.now() + timedelta(seconds=ttl),
    )
    cmd.publish_error = ''
    try:
        publish_command(device.device_code, {
            'command_id': str(cmd.id), 'command': command,
            'token': cmd.command_token_hash,     # thiết bị gửi lại đúng hash này khi ack
            'source': source, **(extra or {}),
        })
        cmd.status = 'sent'
    except MqttPublishError as e:
        cmd.status = 'failed'
        cmd.publish_error = str(e)[:200]
        logger.warning('dispatch_command: publish %s thất bại cho %s: %s', command, device.device_code, e)
    cmd.save(update_fields=['status'])
    return cmd


# ============================================================================
# 4. MỞ KHOÁ: RFID / PIN / KHUÔN MẶT / BLUETOOTH
# ============================================================================
# Khoá tạm sau nhiều lần thất bại liên tiếp trên CÙNG một thiết bị, bất kể kênh nào
# (kịch bản demo: quẹt thẻ lạ 3 lần -> khoá tạm 60 giây, còi kêu, báo cho chủ nhà).
BURST_FAIL_THRESHOLD = 3
BURST_FAIL_WINDOW_SECONDS = 60
BURST_LOCKOUT_SECONDS = 60                 # mức khoá đầu tiên (giữ tên cũ cho tương thích)
BURST_LOCKOUT_STAGES = (60, 300, 1800)     # luỹ tiến: lần 1 -> 1 phút, lần 2 -> 5 phút, từ lần 3 -> 30 phút
BURST_STAGE_WINDOW_SECONDS = 24 * 3600     # số lần khoá trong 24h quyết định mức khoá
BURST_NOTIFY_COOLDOWN_SECONDS = 600        # tối đa 1 thông báo ACCESS_BURST / 10 phút / thiết bị
LOCKOUT_ACTION = 'ACCESS_BURST_LOCKOUT'
# Không tính vào bộ đếm: bị chặn do đang khoá (nếu tính sẽ tự gia hạn khoá mãi) và lỗi MQTT.
NON_COUNTED_REASONS = ('DEVICE_LOCKED_OUT', 'MQTT_PUBLISH_FAILED')


def normalize_uid(raw_uid: str) -> str:
    """Chuẩn hoá UID thẻ (bỏ khoảng trắng, ':' và '-', viết hoa) - giống lúc đăng ký thẻ."""
    return re.sub(r'[\s:\-]', '', raw_uid or '').upper()


def count_recent_failures(device, window_seconds) -> int:
    """Đếm duy nhất 1 chỗ: số lần mở cửa thất bại gần đây (bỏ qua lý do không tính)."""
    since = timezone.now() - timedelta(seconds=window_seconds)
    return (AccessEvent.objects.filter(device=device, success=False, created_at__gte=since)
            .exclude(reason__in=NON_COUNTED_REASONS).count())


def in_lockout(device) -> bool:
    """Đang bị khoá? Chỉ lần khoá GẦN NHẤT quyết định; thời lượng nằm trong metadata của log."""
    now = timezone.now()
    since = now - timedelta(seconds=max(BURST_LOCKOUT_STAGES))
    last = (AuditLog.objects.filter(device=device, action=LOCKOUT_ACTION, created_at__gte=since)
            .order_by('-created_at').first())
    if not last:
        return False
    secs = (last.metadata or {}).get('lockout_seconds', BURST_LOCKOUT_SECONDS)
    return last.created_at + timedelta(seconds=secs) > now


def start_lockout(device, metadata=None):
    AuditLog.objects.create(device=device, action=LOCKOUT_ACTION, severity='critical',
                            success=False, metadata=metadata)


def _handle_burst_if_needed(device):
    """Sau mỗi lần thất bại: vượt ngưỡng trong cửa sổ thời gian thì khoá tạm LUỸ TIẾN + báo còi
    (lệnh MQTT riêng cho firmware) + thông báo cho chủ nhà (có giới hạn tần suất)."""
    if in_lockout(device):
        return
    if count_recent_failures(device, BURST_FAIL_WINDOW_SECONDS) < BURST_FAIL_THRESHOLD:
        return
    now = timezone.now()
    stage = AuditLog.objects.filter(
        device=device, action=LOCKOUT_ACTION,
        created_at__gte=now - timedelta(seconds=BURST_STAGE_WINDOW_SECONDS)).count()
    lockout_seconds = BURST_LOCKOUT_STAGES[min(stage, len(BURST_LOCKOUT_STAGES) - 1)]
    start_lockout(device, {'threshold': BURST_FAIL_THRESHOLD, 'window_seconds': BURST_FAIL_WINDOW_SECONDS,
                           'lockout_seconds': lockout_seconds, 'stage': stage + 1})
    try:
        publish_command(device.device_code, {'command': 'BUZZER_ALERT', 'reason': 'ACCESS_BURST'})
    except MqttPublishError:
        pass  # còi là phụ trợ; lỗi MQTT không được làm hỏng luồng khoá tạm
    if device.owner_id and not Notification.objects.filter(
            device=device, type='ACCESS_BURST',
            created_at__gte=now - timedelta(seconds=BURST_NOTIFY_COOLDOWN_SECONDS)).exists():
        Notification.objects.create(
            user=device.owner, device=device, type='ACCESS_BURST', severity='critical',
            title='Cảnh báo: nhiều lần mở cửa sai liên tiếp'[:150],
            message=(f'Thiết bị "{device.name}" bị {BURST_FAIL_THRESHOLD}+ lần mở cửa sai '
                     f'trong {BURST_FAIL_WINDOW_SECONDS}s. Đã khoá tạm {lockout_seconds}s '
                     f'(lần khoá thứ {stage + 1} trong 24 giờ).'),
        )


def _log_event(occurred_at=None, **kwargs) -> AccessEvent:
    event = AccessEvent.objects.create(**kwargs)
    if occurred_at:  # sự kiện offline đến trễ: đặt lại đúng giờ xảy ra
        AccessEvent.objects.filter(pk=event.pk).update(created_at=occurred_at)
        event.created_at = occurred_at
    if not event.success and event.reason not in NON_COUNTED_REASONS:
        _handle_burst_if_needed(event.device)
    return event


# ---------------------------------------------------------------- RFID
def verify_rfid_tap(device, raw_uid: str, ip_address=None) -> AccessEvent:
    """ESP32 đọc UID thẻ (RC522) và publish lên MQTT; server chỉ so khớp UID (đã hash) rồi ra lệnh mở."""
    with transaction.atomic():
        if in_lockout(device):
            return _log_event(device=device, method=AccessEvent.METHOD_RFID, success=False,
                              reason='DEVICE_LOCKED_OUT', ip_address=ip_address)
        card = AccessCard.objects.filter(
            card_uid_hash__in=[hash_card_uid(normalize_uid(raw_uid)),
                               hash_token(normalize_uid(raw_uid))],   # hash cũ (SHA-256 trần) còn dùng được
            is_active=True,
            carddeviceaccess__device=device, carddeviceaccess__is_active=True,
        ).first()
        if not card:
            return _log_event(device=device, method=AccessEvent.METHOD_RFID, success=False,
                              reason='UNKNOWN_CARD', ip_address=ip_address)

    cmd = dispatch_command(device, 'UNLOCK', source='rfid', extra={'card_id': str(card.id)})
    ok = cmd.status == 'sent'
    return _log_event(device=device, method=AccessEvent.METHOD_RFID, success=ok,
                      reason=None if ok else 'MQTT_PUBLISH_FAILED', user=card.user,
                      access_card=card, ip_address=ip_address)


# ---------------------------------------------------------------- PIN (bàn phím)
def verify_door_pin(device, raw_pin: str, ip_address=None) -> AccessEvent:
    with transaction.atomic():
        if in_lockout(device):
            return _log_event(device=device, method=AccessEvent.METHOD_PIN, success=False,
                              reason='DEVICE_LOCKED_OUT', ip_address=ip_address)
        now = timezone.now()
        candidates = DoorPinCode.objects.filter(
            device=device, is_revoked=False, valid_from__lte=now, expires_at__gt=now,
        ).select_for_update()
        matched = next((p for p in candidates if p.check_pin(raw_pin) and p.is_valid_now()), None)
        if not matched:
            return _log_event(device=device, method=AccessEvent.METHOD_PIN, success=False,
                              reason='INVALID_OR_EXPIRED_PIN', ip_address=ip_address)
        matched.register_use()

    cmd = dispatch_command(device, 'UNLOCK', source='pin', extra={'pin_id': str(matched.id)})
    ok = cmd.status == 'sent'
    if not ok:
        # Cửa chưa mở -> hoàn lại lượt dùng để PIN dùng-một-lần không bị "cháy" oan.
        DoorPinCode.objects.filter(pk=matched.pk, use_count__gt=0).update(use_count=F('use_count') - 1)
    return _log_event(device=device, method=AccessEvent.METHOD_PIN, success=ok,
                      reason=None if ok else 'MQTT_PUBLISH_FAILED',
                      door_pin=matched, user=matched.created_by, ip_address=ip_address)


def generate_unique_pin(device, digits: int = 6, attempts: int = 20) -> str:
    """Sinh PIN ngẫu nhiên không trùng PIN đang hiệu lực của cùng thiết bị."""
    active = list(DoorPinCode.objects.filter(device=device, is_revoked=False, expires_at__gt=timezone.now()))
    for _ in range(attempts):
        pin = ''.join(secrets.choice('0123456789') for _ in range(digits))
        if not any(p.check_pin(pin) for p in active):
            return pin
    raise RuntimeError('Không sinh được PIN không trùng, hãy thu hồi bớt PIN cũ.')


def issue_door_pin(device, created_by, plain_pin: str, ttl_minutes: int,
                   label: str = '', max_uses: int = 1) -> DoorPinCode:
    """Chủ nhà cấp PIN mới cho khách. plain_pin chỉ hiển thị 1 lần, không lưu dạng thô."""
    pin = DoorPinCode(device=device, created_by=created_by, label=label,
                      expires_at=timezone.now() + timedelta(minutes=ttl_minutes), max_uses=max_uses)
    pin.set_pin(plain_pin)
    pin.save()
    AuditLog.objects.create(actor_user=created_by, device=device, action='DOOR_PIN_ISSUED',
                            metadata={'pin_id': str(pin.id), 'ttl_minutes': ttl_minutes, 'label': label})
    return pin


def issue_unique_door_pin(device, created_by, ttl_minutes: int, label: str = '', max_uses: int = 1,
                          digits: int = 6):
    """Sinh + lưu PIN trong 1 transaction, khoá dòng Device để 2 người cấp PIN cùng lúc không sinh trùng.
    Trả về (DoorPinCode, plain_pin)."""
    with transaction.atomic():
        Device.objects.select_for_update().get(pk=device.pk)
        plain_pin = generate_unique_pin(device, digits=digits)
        pin = issue_door_pin(device=device, created_by=created_by, plain_pin=plain_pin,
                             ttl_minutes=ttl_minutes, label=label, max_uses=max_uses)
    return pin, plain_pin


# ---------------------------------------------------------------- Khuôn mặt (camera)
def _euclidean_distance(a, b) -> float:
    if len(a) != len(b) or not a:
        return math.inf
    return math.sqrt(sum((x - y) ** 2 for x, y in zip(a, b)))


FACE_MAX_THRESHOLD = 0.6   # trần phía server: FaceProfile.threshold cao hơn cũng bị kẹp về mức này


def verify_face(device, embedding: list, snapshot_url: str = '', ip_address=None) -> AccessEvent:
    """embedding do thiết bị biên/dịch vụ suy luận tính sẵn; server chỉ so khoảng cách Euclid
    với các FaceProfile đang active VÀ đã có xác nhận đồng ý của device này."""
    if in_lockout(device):
        return _log_event(device=device, method=AccessEvent.METHOD_FACE, success=False,
                          reason='DEVICE_LOCKED_OUT', snapshot_url=snapshot_url, ip_address=ip_address)

    best_profile, best_distance = None, math.inf
    for profile in FaceProfile.objects.filter(device=device, is_active=True, consent_confirmed=True):
        d = _euclidean_distance(embedding, profile.get_embedding())
        if d < best_distance:
            best_profile, best_distance = profile, d

    limit = min(float(best_profile.threshold), FACE_MAX_THRESHOLD) if best_profile else 0.0
    if not best_profile or best_distance > limit:
        return _log_event(device=device, method=AccessEvent.METHOD_FACE, success=False,
                          reason='NO_MATCH', snapshot_url=snapshot_url, ip_address=ip_address)

    confidence = max(0.0, 1 - (best_distance / limit))
    cmd = dispatch_command(device, 'UNLOCK', source='face', extra={'face_profile_id': str(best_profile.id)})
    ok = cmd.status == 'sent'
    return _log_event(device=device, method=AccessEvent.METHOD_FACE, success=ok,
                      reason=None if ok else 'MQTT_PUBLISH_FAILED', user=best_profile.user,
                      face_profile=best_profile, confidence=round(confidence, 4),
                      snapshot_url=snapshot_url, ip_address=ip_address)


def register_face(device, user, embedding: list, name: str = '', consent_confirmed: bool = False) -> FaceProfile:
    profile, _created = FaceProfile.objects.update_or_create(
        user=user, device=device,
        defaults={'name': name, 'consent_confirmed': consent_confirmed, 'is_active': True},
    )
    profile.set_embedding(embedding)
    profile.save()
    AuditLog.objects.create(actor_user=user, device=device, action='FACE_PROFILE_REGISTERED',
                            metadata={'face_profile_id': str(profile.id)})
    return profile


# ---------------------------------------------------------------- Bluetooth (tầm gần, offline)
# Luồng: app có mạng -> xin "vé" -> đến gần thì đưa vé cho ESP32 qua BLE -> ESP32 TỰ kiểm tra
# chữ ký + hạn (không cần mạng) rồi mở cửa -> khi có mạng, ESP32 publish sự kiện `ble_unlock`
# kèm vé để server ghi log. Vé không có bản ghi DB; thu hồi = để vé hết hạn (mặc định 24h).
#
#   key  = HMAC_SHA256(key=sha256_hex(provisioning_secret) [chuỗi ASCII], msg="ble-ticket-v1")
#   sig  = HMAC_SHA256(key, "<device_code>|<user_hex>|<exp>") -> hex, lấy 32 ký tự đầu
#   vé   = "<user_hex>.<exp>.<sig>"          (user_hex = UUID user bỏ dấu '-', exp = unix giây)
BLE_TICKET_TTL_SECONDS = int(getattr(settings, 'BLE_TICKET_TTL_SECONDS', 3600))   # mặc định 1 giờ (trước: 24h)


def _ble_sig(device, user_hex: str, exp: int) -> str:
    key = hmac.new(device.provisioning_secret_hash.encode(), b'ble-ticket-v1', hashlib.sha256).digest()
    msg = f'{device.device_code}|{user_hex}|{exp}'.encode()
    return hmac.new(key, msg, hashlib.sha256).hexdigest()[:32]


def issue_ble_ticket(device, user, ttl: int = BLE_TICKET_TTL_SECONDS):
    """Trả (ticket, exp_unix). Gọi view kiểm tra quyền UNLOCK + bluetooth_enabled trước."""
    exp = int(time.time()) + ttl
    user_hex = user.id.hex
    return f'{user_hex}.{exp}.{_ble_sig(device, user_hex, exp)}', exp


def parse_ble_ticket(device, ticket: str):
    """Trả (user, exp) nếu chữ ký hợp lệ và user tồn tại, ngược lại None. Không kiểm tra hạn."""
    try:
        user_hex, exp_s, sig = (ticket or '').strip().split('.')
        exp = int(exp_s)
    except ValueError:
        return None
    if not hmac.compare_digest(sig, _ble_sig(device, user_hex, exp)):
        return None
    uid = parse_uuid(user_hex)
    user = User.objects.filter(pk=uid).first() if uid else None
    return (user, exp) if user else None


def record_ble_unlock(device, ticket: str = '', ok: bool = True, reason=None, at=None) -> AccessEvent:
    """ESP32 báo 1 lượt mở/từ chối qua BLE (cửa đã xử lý tại chỗ, server chỉ ghi log).
    `at` = unix giây lúc xảy ra (sự kiện offline đến trễ)."""
    now = timezone.now()
    occurred = None
    try:
        t = datetime.fromtimestamp(float(at), tz=dt_timezone.utc)
        if now - timedelta(days=7) <= t <= now:
            occurred = t
    except (TypeError, ValueError, OverflowError, OSError):
        pass
    at_unix = (occurred or now).timestamp()

    user = None
    if ok:
        parsed = parse_ble_ticket(device, ticket)
        if not parsed:
            ok, reason = False, 'BLE_INVALID_TICKET'
        else:
            user, exp = parsed
            if exp < at_unix:
                ok, reason = False, 'BLE_TICKET_EXPIRED'
            elif not device.bluetooth_enabled or not has_permission(user, device, 'UNLOCK'):
                ok, reason = False, 'BLE_NOT_ALLOWED'
    return _log_event(occurred_at=occurred, device=device, method=AccessEvent.METHOD_BLE,
                      success=ok, reason=None if ok else (reason or 'BLE_DENIED')[:100], user=user)


# ============================================================================
# 5. RULE ENGINE (luật do user cấu hình, ngưỡng nằm trong DB)
# ============================================================================
#   evaluate_device_status(device, status_log)  <- subscriber gọi sau mỗi gói status
#   mark_offline_devices()                      <- subscriber gọi định kỳ (thread nền)
# Khi luật kích hoạt: tôn trọng cooldown, tạo Notification cho owner, thực hiện action
# (NOTIFY_ONLY / AUTO_LOCK / TEMP_BLOCK_ACCESS) và ghi AutomationRuleLog.
OFFLINE_AFTER_SECONDS = 180      # không nhận status > 3 phút -> coi là offline


def _rules_for(device, trigger_type):
    if not device.owner_id:
        return AutomationRule.objects.none()
    return (AutomationRule.objects
            .filter(is_active=True, trigger_type=trigger_type, owner_id=device.owner_id)
            .filter(Q(device=device) | Q(device__isnull=True)))


def _claim(rule) -> bool:
    """Giành quyền kích hoạt luật (atomic): chỉ 1 tiến trình thắng khi 2 gói tin đến cùng lúc."""
    now = timezone.now()
    cutoff = now - timedelta(seconds=rule.cooldown_seconds)
    return AutomationRule.objects.filter(pk=rule.pk).filter(
        Q(last_triggered_at__isnull=True) | Q(last_triggered_at__lte=cutoff)
    ).update(last_triggered_at=now) == 1


def _do_action(rule, device):
    if rule.action_type == AutomationRule.ACTION_AUTO_LOCK:
        dispatch_command(device, 'LOCK', source='automation_rule', issued_by=rule.owner, ttl=120)
    elif rule.action_type == AutomationRule.ACTION_TEMP_BLOCK_ACCESS:
        start_lockout(device, {'source': 'automation_rule', 'rule_id': str(rule.id)})


def _fire(rule, device, measured, title, message) -> int:
    """Kích hoạt luật nếu không còn trong cooldown. Trả 1 nếu đã kích hoạt, 0 nếu không."""
    if not _claim(rule):
        return 0
    notification = Notification.objects.create(
        user=rule.owner, device=device, type='AUTOMATION_RULE',
        title=title[:150], message=message, severity=rule.notify_severity,
    )
    try:
        _do_action(rule, device)
    except Exception:
        logger.exception('rules: lỗi khi thực hiện action %s của luật %s', rule.action_type, rule.id)
    AutomationRuleLog.objects.create(
        rule=rule, device=device, action_taken=rule.action_type, notification=notification,
        measured_value=None if measured is None else Decimal(str(measured)).quantize(Decimal('0.01')),
    )
    logger.info('rules: luật "%s" kích hoạt cho %s (giá trị=%s)', rule.name, device.device_code, measured)
    return 1


def _unlocked_since(device, current):
    """Thời điểm bắt đầu chuỗi trạng thái 'unlocked' liên tục gần nhất."""
    last_locked = (DeviceStatusLog.objects
                   .filter(device=device, lock_state='locked', recorded_at__lt=current.recorded_at)
                   .order_by('-recorded_at').first())
    qs = DeviceStatusLog.objects.filter(device=device, lock_state='unlocked')
    if last_locked:
        qs = qs.filter(recorded_at__gt=last_locked.recorded_at)
    first_open = qs.order_by('recorded_at').first()
    return first_open.recorded_at if first_open else current.recorded_at


def evaluate_device_status(device, status_log) -> int:
    """Đánh giá luật pin yếu / tamper / cửa mở quá lâu theo gói status mới nhất."""
    fired = 0
    for rule in _rules_for(device, AutomationRule.TRIGGER_BATTERY_LOW):
        if rule.threshold_value is not None and status_log.battery_level < rule.threshold_value:
            fired += _fire(rule, device, status_log.battery_level, f'Pin yếu: {device.name}',
                           f'Pin thiết bị "{device.name}" còn {status_log.battery_level}% '
                           f'(ngưỡng {rule.threshold_value}%).')

    if status_log.tamper_detected:
        for rule in _rules_for(device, AutomationRule.TRIGGER_TAMPER_DETECTED):
            fired += _fire(rule, device, None, f'Cảnh báo tác động vật lý: {device.name}',
                           f'Thiết bị "{device.name}" phát hiện bị tác động vật lý (tamper).')

    if status_log.lock_state == 'unlocked':
        for rule in _rules_for(device, AutomationRule.TRIGGER_DOOR_OPEN_TOO_LONG):
            if rule.threshold_value is None:
                continue
            seconds_open = (timezone.now() - _unlocked_since(device, status_log)).total_seconds()
            if seconds_open >= float(rule.threshold_value):
                fired += _fire(rule, device, seconds_open, f'Cửa mở quá lâu: {device.name}',
                               f'Cửa "{device.name}" đã mở khoảng {int(seconds_open)} giây '
                               f'(ngưỡng {rule.threshold_value} giây).')
    return fired


def evaluate_offline_devices() -> int:
    """Luật OFFLINE_TOO_LONG (threshold_value = số giây)."""
    fired = 0
    now = timezone.now()
    rules = (AutomationRule.objects.filter(is_active=True, trigger_type=AutomationRule.TRIGGER_OFFLINE_TOO_LONG)
             .select_related('owner', 'device'))
    for rule in rules:
        if rule.threshold_value is None:
            continue
        devices = Device.objects.filter(owner_id=rule.owner_id, status='offline', last_seen_at__isnull=False)
        if rule.device_id:
            devices = devices.filter(pk=rule.device_id)
        for device in devices:
            offline_seconds = (now - device.last_seen_at).total_seconds()
            if offline_seconds >= float(rule.threshold_value):
                fired += _fire(rule, device, offline_seconds, f'Mất kết nối: {device.name}',
                               f'Thiết bị "{device.name}" đã mất kết nối khoảng {int(offline_seconds)} giây.')
    return fired


def mark_offline_devices() -> int:
    """Thiết bị 'online' mà lâu không gửi status -> 'offline', rồi chạy luật OFFLINE_TOO_LONG."""
    cutoff = timezone.now() - timedelta(seconds=OFFLINE_AFTER_SECONDS)
    n = Device.objects.filter(status='online', last_seen_at__lt=cutoff).update(status='offline')
    evaluate_offline_devices()
    return n


# ============================================================================
# 6. PUSH FCM (app Android)
# ============================================================================
# Mỗi Notification mới -> signal post_save gửi push tới các phiên app còn hạn có fcm_token.
# Bật bằng `pip install firebase-admin` + đặt FIREBASE_CREDENTIALS_JSON (nội dung JSON) hoặc
# GOOGLE_APPLICATION_CREDENTIALS (đường dẫn file). Chưa cấu hình -> bỏ qua êm.
# Data gửi kèm (đều là chuỗi): notification_id, type, severity, device_id.
# Kênh Android: smartlock_info | smartlock_warning | smartlock_critical (app phải tạo sẵn).
_fcm_app = None
_fcm_initialised = False


def _get_fcm_app():
    global _fcm_app, _fcm_initialised
    if _fcm_initialised:
        return _fcm_app
    _fcm_initialised = True
    try:
        import firebase_admin
        from firebase_admin import credentials
    except ImportError:
        logger.info('push: chưa cài firebase-admin, bỏ qua push.')
        return None
    raw = os.environ.get('FIREBASE_CREDENTIALS_JSON')
    path = os.environ.get('GOOGLE_APPLICATION_CREDENTIALS')
    try:
        if raw:
            cred = credentials.Certificate(json.loads(raw))
        elif path:
            cred = credentials.Certificate(path)
        else:
            logger.info('push: chưa cấu hình thông tin Firebase, bỏ qua push.')
            return None
        _fcm_app = firebase_admin.initialize_app(cred, {'httpTimeout': 5}, name='smartlock-push')
    except Exception:
        logger.exception('push: khởi tạo Firebase thất bại')
        _fcm_app = None
    return _fcm_app


def send_notification_push(notification_id) -> int:
    """Gửi push cho 1 Notification. Trả số tin gửi thành công. Không bao giờ ném lỗi."""
    try:
        from .models import MobileSession
        notification = Notification.objects.filter(pk=notification_id).first()
        if not notification:
            return 0
        sessions = list(MobileSession.objects.filter(
            user_id=notification.user_id, revoked_at__isnull=True, expires_at__gt=timezone.now(),
            push_enabled=True).exclude(fcm_token=''))
        if not sessions:
            return 0
        app = _get_fcm_app()
        if app is None:
            return 0
        from firebase_admin import messaging

        data = {'notification_id': str(notification.id), 'type': notification.type,
                'severity': notification.severity,
                'device_id': str(notification.device_id) if notification.device_id else ''}
        critical = notification.severity == 'critical'
        messages = [messaging.Message(
            token=s.fcm_token,
            notification=messaging.Notification(title=notification.title[:100], body=notification.message[:300]),
            data=data,
            android=messaging.AndroidConfig(
                priority='high' if critical else 'normal',
                notification=messaging.AndroidNotification(channel_id=f'smartlock_{notification.severity}')),
        ) for s in sessions]
        batch = messaging.send_each(messages, app=app)

        dead = (messaging.UnregisteredError, messaging.SenderIdMismatchError)
        sent = 0
        for session, resp in zip(sessions, batch.responses):
            if resp.success:
                sent += 1
            elif isinstance(resp.exception, dead):     # token hết hạn / gỡ app -> dọn
                MobileSession.objects.filter(pk=session.pk).update(fcm_token='')
            else:
                logger.warning('push: gửi thất bại tới phiên %s: %s', session.pk, resp.exception)
        return sent
    except Exception:
        logger.exception('push: lỗi không mong đợi khi gửi push')
        return 0


def _on_notification_saved(sender, instance, created, **kwargs):
    if created:
        transaction.on_commit(lambda: send_notification_push(instance.pk))


def register_signals():
    """Gọi 1 lần trong AppConfig.ready()."""
    post_save.connect(_on_notification_saved, sender=Notification, dispatch_uid='push_on_notification')