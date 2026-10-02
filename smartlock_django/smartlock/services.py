# smartlock/services.py
"""

Mục lục
  1. Helper chung (hash, IP, audit, quyền, đăng nhập sai, gửi mail xác thực)
  2. Email (render HTML + bản text tự sinh)
  3. MQTT + gửi lệnh xuống thiết bị
  4. Mở khoá: RFID / PIN / khuôn mặt / Bluetooth / NFC điện thoại + khoá tạm khi sai liên tiếp
  5. Online/offline của thiết bị
  6. Push FCM tới app Android
  7. Vòng đời khoá (claim / gỡ chủ / xoay secret)
  (Quyền theo tính năng, chia sẻ khoá và popup nằm ở mục 1.)
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
    AccessCard, AccessEvent, AuditLog, CardDeviceAccess, Device,
    DeviceAccess, DeviceCommand, DeviceStatusLog, DoorPinCode, FaceProfile, NfcLog, NfcReader,
    Notification, OneTimeCode, Permission, SystemSettings, User, hash_card_uid,
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


def user_session_seconds() -> int:
    """Thời gian phiên của USER thường theo SystemSettings.session_timeout_hours.
    Nơi đăng nhập user (smartlock/views.py login_view) PHẢI gọi request.session.set_expiry(services.user_session_seconds())
    (và dùng cho hạn MobileSession khi làm API). Phiên admin dùng MANAGE_SYS_SESSION_SECONDS riêng."""
    return int(system_settings().session_timeout_hours) * 3600


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


class AuditWriteError(Exception):
    """Không ghi được AuditLog cho thao tác bắt buộc phải có log (audit(..., strict=True))."""


def audit(request, action, *, device=None, target_user=None, success=True,
          severity='info', metadata=None, actor='auto', username_attempt=None, strict=False):
    """Ghi AuditLog. Mặc định NUỐT lỗi ghi log (không làm hỏng luồng chính).
    strict=True (thao tác nhạy cảm: cấp quyền, gán/gỡ chủ, xoay secret...) -> ném AuditWriteError để
    view đặt thao tác + audit trong cùng transaction.atomic() và HUỶ thao tác khi không ghi được log."""
    if actor == 'auto':
        actor = request.user if request.user.is_authenticated else None
    snapshot = dict(metadata or {})
    if actor is not None:
        snapshot.setdefault('actor_email', actor.email)
    if target_user is not None:
        snapshot.setdefault('target_email', target_user.email)
    if device is not None:
        snapshot.setdefault('device_code', device.device_code)
    try:
        with transaction.atomic():  # savepoint: lỗi ghi log không làm hỏng transaction bên ngoài
            AuditLog.objects.create(
                actor_user=actor, target_user=target_user, device=device, action=action[:50],
                username_attempt=username_attempt, severity=severity, success=success,
                ip_address=client_ip(request), user_agent=user_agent(request), metadata=snapshot or None,
            )
    except Exception as exc:
        logger.exception('audit: không ghi được log %s', action)
        if strict:
            raise AuditWriteError(action) from exc


def notify(user, title, message, severity='info', device=None, type_='SYSTEM'):
    Notification.objects.create(
        user=user, device=device, type=type_, title=title[:150], message=message, severity=severity,
    )


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


# ---------------------------------------------------------------- Quyền theo TỪNG TÍNH NĂNG
# Chủ khoá luôn có đủ mọi quyền. Người được chia sẻ chỉ có đúng các quyền chủ chọn lúc chia sẻ.
# (code, tên hiển thị, mô tả, nhạy cảm?)
PERMISSION_CATALOG = [
    ('UNLOCK', 'Mở khoá từ xa', 'Mở cửa qua Internet (trình duyệt hoặc app).', False),
    ('LOCK', 'Khoá từ xa', 'Khoá cửa qua Internet (trình duyệt hoặc app).', False),
    ('BLUETOOTH', 'Mở bằng Bluetooth', 'Dùng điện thoại mở cửa khi đứng gần (app xin vé BLE).', False),
    ('NFC_PHONE', 'Mở bằng NFC trên điện thoại', 'Điện thoại giả lập thẻ NFC để chạm đầu đọc.', False),
    ('manage_nfc', 'Quản lý thẻ NFC', 'Đăng ký thẻ của mình, bật/tắt thẻ trên khoá này.', True),
    ('manage_pins', 'Quản lý mã PIN', 'Cấp/thu hồi mã PIN để khách bấm trên bàn phím.', True),
    ('manage_face_profiles', 'Quản lý khuôn mặt', 'Đăng ký khuôn mặt được phép mở cửa.', True),
    ('view_history', 'Xem lịch sử ra vào', 'Xem nhật ký mở cửa và nhận popup khi cửa mở.', False),
]
PERMISSION_CODES = tuple(code for code, *_ in PERMISSION_CATALOG)


def ensure_default_permissions() -> None:
    existing = set(Permission.objects.values_list('code', flat=True))
    for code, name, desc, sensitive in PERMISSION_CATALOG:
        if code not in existing:
            Permission.objects.get_or_create(
                code=code, defaults={'name': name, 'description': desc, 'is_sensitive': sensitive})


def _live_access(user, now):
    """DeviceAccess còn hiệu lực của user (đang bật, đã đến hạn bắt đầu, chưa hết hạn)."""
    return (DeviceAccess.objects.filter(user=user, is_active=True, accepted=True, valid_from__lte=now)
            .filter(Q(expires_at__isnull=True) | Q(expires_at__gt=now)))


def devices_with_permission(user, code):
    """Khoá user dùng được tính năng `code`: khoá của mình + khoá được chia sẻ kèm quyền đó."""
    ids = _live_access(user, timezone.now()).filter(permissions__code=code).values('device_id')
    return Device.objects.filter(Q(owner=user) | Q(id__in=ids))


def permission_codes(user, device) -> set:
    if device.owner_id == user.id:
        return set(PERMISSION_CODES)
    codes = (_live_access(user, timezone.now()).filter(device=device)
             .values_list('permissions__code', flat=True))
    return {c for c in codes if c}


def capabilities(user, device) -> dict:
    """Giao diện dùng dict này để hiện/ẩn từng khối chức năng cho CHỦ và cho NGƯỜI ĐƯỢC CHIA SẺ.
    `bluetooth` / `nfc_phone` là tính năng của ĐIỆN THOẠI (app), trình duyệt không dùng được."""
    codes = permission_codes(user, device)
    return {
        'is_owner': device.owner_id == user.id,
        'remote_unlock': 'UNLOCK' in codes and device.wifi_enabled,
        'remote_lock': 'LOCK' in codes and device.wifi_enabled,
        'bluetooth': 'BLUETOOTH' in codes and device.bluetooth_enabled,
        'nfc_phone': 'NFC_PHONE' in codes and device.nfc_enabled,
        'manage_nfc': 'manage_nfc' in codes,
        'manage_pins': 'manage_pins' in codes,
        'manage_faces': 'manage_face_profiles' in codes,
        'view_history': 'view_history' in codes,
        'manage_sharing': device.owner_id == user.id,     # chỉ chủ mới chia sẻ/thu hồi
    }


# ---------------------------------------------------------------- Chia sẻ khoá (có hiệu lực NGAY)
def grant_access(device, owner, target, permissions, expires_at):
    """Chia sẻ khoá cho `target` (không cần người nhận xác nhận). Đã có quyền -> cập nhật.
    Trả (DeviceAccess, created)."""
    with transaction.atomic():
        access = (DeviceAccess.objects.select_for_update()
                  .filter(device=device, user=target, is_active=True).order_by('-created_at').first())
        created = access is None
        if created:
            access = DeviceAccess.objects.create(device=device, user=target, created_by=owner,
                                                 accepted=True, source='DIRECT', expires_at=expires_at)
        else:
            access.expires_at = expires_at
            access.accepted = True
            access.save(update_fields=['expires_at', 'accepted'])
        access.permissions.set(permissions)
    return access, created


def _expiry_text(dt) -> str:
    return timezone.localtime(dt).strftime('%H:%M %d/%m/%Y') if dt else 'Không giới hạn'


def notify_access_shared(request, access, created=True) -> bool:
    """Báo cho người được chia sẻ: thông báo trong app (kèm popup + push) VÀ email.
    Trả True nếu email gửi được. Không bao giờ ném lỗi."""
    device, target, owner = access.device, access.user, access.created_by
    owner_name = owner.full_name or owner.username
    perm_names = [p.name for p in access.permissions.order_by('name')]
    expires = _expiry_text(access.expires_at)
    if created:
        title = f'{owner_name} đã chia sẻ khoá cho bạn'
    else:
        title = f'Quyền của bạn trên khoá "{device.name}" đã thay đổi'
    message = (f'Khoá "{device.name}". Quyền: {", ".join(perm_names) or "chưa có quyền nào"}. '
               f'Hết hạn: {expires}.')
    try:
        notify(target, title, message, device=device, type_='SHARE')
    except Exception:
        logger.exception('share: không tạo được thông báo cho %s', target.pk)
    try:
        subject, html, plain = render_email('device_shared.html', {
            'full_name': target.full_name or target.username,
            'owner_name': owner_name, 'device_name': device.name,
            'device_location': device.location or '', 'permissions': perm_names,
            'expires_text': expires, 'is_update': not created,
            'action_url': request.build_absolute_uri(reverse('smartlock:device-detail', args=[device.id])),
        })
        return send_mail(subject, plain, html, target.email)
    except Exception:
        logger.exception('share: không gửi được email tới %s', target.pk)
        return False


# ---------------------------------------------------------------- Popup trên màn hình
# Mọi Notification mới đều hiện thành popup NGAY TRONG TRANG (JS poll smartlock:events), không dùng
# Notification API của trình duyệt. Hàm dưới tạo Notification cho những ai đang "theo dõi" cánh cửa.
def door_watchers(device):
    """Chủ khoá + người được chia sẻ có quyền xem lịch sử."""
    shared = (_live_access_for_device(device).filter(permissions__code='view_history').values('user_id'))
    return User.objects.filter(Q(pk=device.owner_id) | Q(pk__in=shared), is_active=True).distinct()


def _live_access_for_device(device):
    now = timezone.now()
    return (DeviceAccess.objects.filter(device=device, is_active=True, accepted=True, valid_from__lte=now)
            .filter(Q(expires_at__isnull=True) | Q(expires_at__gt=now)))


def announce_door_event(device, title, message, severity='info', type_='DOOR_EVENT', extra_users=()):
    recipients = {u.pk: u for u in door_watchers(device)}
    for u in extra_users:
        if u is not None:
            recipients.setdefault(u.pk, u)
    for u in recipients.values():
        notify(u, title, message, severity=severity, device=device, type_=type_)


def announce_command_result(cmd, ok=True) -> None:
    """SUBSCRIBER MQTT gọi khi nhận ack của lệnh LOCK/UNLOCK -> popup "Đã khoá/Đã mở khoá" cho
    người gửi lệnh + những người theo dõi cửa. Lệnh khác bỏ qua."""
    verb = {'LOCK': 'khoá', 'UNLOCK': 'mở khoá'}.get(cmd.command_type)
    if not verb:
        return
    who = cmd.issued_by.full_name or cmd.issued_by.username
    name = cmd.device.name
    if ok:
        title, msg, sev = f'Cửa đã {verb}', f'"{name}" đã {verb} theo lệnh của {who}.', 'info'
    else:
        title, msg, sev = f'Lệnh {verb} thất bại', f'"{name}" không thực hiện được lệnh {verb} của {who}.', 'warning'
    announce_door_event(cmd.device, title, msg, severity=sev, type_='DOOR_EVENT', extra_users=[cmd.issued_by])


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
    'device_shared.html': 'Có người vừa chia sẻ khoá cho bạn',
    'admin_device_approval.html': 'Thiết bị mới cần kích hoạt',
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
        keys = ('verification_link', 'password_reset_link', 'otp_code', 'action_url')
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
NON_COUNTED_REASONS = ('DEVICE_LOCKED_OUT', 'MQTT_PUBLISH_FAILED', 'CARD_REGISTERED')


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


METHOD_TEXT = {'RFID': 'thẻ NFC', 'PIN': 'mã PIN', 'FACE': 'khuôn mặt', 'BLE': 'Bluetooth',
               'NFC_PHONE': 'NFC trên điện thoại'}
STALE_EVENT_SECONDS = 300      # sự kiện offline đến trễ hơn mức này thì không bật popup


def _announce_access(event: AccessEvent) -> None:
    who = (event.user.full_name or event.user.username) if event.user_id else 'Ai đó'
    announce_door_event(
        event.device, 'Cửa vừa được mở',
        f'{who} đã mở "{event.device.name}" bằng {METHOD_TEXT.get(event.method, event.method)}.')


def _log_event(occurred_at=None, **kwargs) -> AccessEvent:
    event = AccessEvent.objects.create(**kwargs)
    if occurred_at:  # sự kiện offline đến trễ: đặt lại đúng giờ xảy ra
        AccessEvent.objects.filter(pk=event.pk).update(created_at=occurred_at)
        event.created_at = occurred_at
    if not event.success and event.reason not in NON_COUNTED_REASONS:
        _handle_burst_if_needed(event.device)
    if event.success and (occurred_at is None
                          or (timezone.now() - occurred_at).total_seconds() <= STALE_EVENT_SECONDS):
        try:
            _announce_access(event)
        except Exception:      # popup chỉ là phụ trợ, không được làm hỏng luồng mở cửa
            logger.exception('popup: không tạo được thông báo mở cửa')
    return event


# ---------------------------------------------------------------- RFID
def _auto_register_card(device, raw_uid, ip_address=None):
    """Đầu đọc của khoá đang trong cửa sổ đăng ký (auto_register_until còn hạn) + có chủ:
    thẻ lạ quẹt vào sẽ được gắn cho CHỦ khoá, KHÔNG cần admin duyệt. Trả về AccessEvent nếu đã
    xử lý (đăng ký xong), None nếu không áp dụng. Việc này không mở cửa và không tính vào bộ đếm sai."""
    if not device.owner_id:
        return None
    now = timezone.now()
    reader = NfcReader.objects.filter(device=device, is_active=True, auto_register=True,
                                      auto_register_until__gt=now).first()
    if not reader:
        return None
    uid = normalize_uid(raw_uid)
    if len(uid) < 4:
        return None
    uid_hashes = [hash_card_uid(uid), hash_token(uid)]
    card = AccessCard.objects.filter(card_uid_hash__in=uid_hashes).first()
    if card and card.user_id != device.owner_id:
        AuditLog.objects.create(device=device, action='CARD_AUTO_REGISTER_FAILED', success=False,
                                severity='warning', ip_address=ip_address,
                                metadata={'reason': 'owned_by_other_user', 'reader_id': str(reader.id)})
        return None
    with transaction.atomic():
        if not card:
            card = AccessCard.objects.create(card_uid_hash=hash_card_uid(uid), user=device.owner,
                                             name='Thẻ đăng ký tại đầu đọc', is_active=True)
        link, _ = CardDeviceAccess.objects.get_or_create(access_card=card, device=device)
        if not link.is_active:
            link.is_active = True
            link.save(update_fields=['is_active'])
        NfcLog.objects.create(reader=reader, nfc_tag=card, device=device, user=device.owner,
                              event_type='CARD_REGISTER', ip_address=ip_address,
                              metadata={'via': 'reader_tap', 'auto_register': True})
        AuditLog.objects.create(actor_user=None, target_user=device.owner, device=device,
                                action='CARD_AUTO_REGISTERED', ip_address=ip_address,
                                metadata={'card_id': str(card.id), 'reader_id': str(reader.id),
                                          'device_code': device.device_code})
    Notification.objects.create(
        user=device.owner, device=device, type='CARD', severity='info',
        title='Đã thêm thẻ mới tại đầu đọc'[:150],
        message=f'Một thẻ vừa được đăng ký tại đầu đọc của khoá \"{device.name}\". '
                'Nếu không phải bạn, hãy vô hiệu hoá thẻ trong mục Thẻ NFC.')
    return _log_event(device=device, method=AccessEvent.METHOD_RFID, success=False,
                      reason='CARD_REGISTERED', user=device.owner, access_card=card,
                      ip_address=ip_address)


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
            registered = _auto_register_card(device, raw_uid, ip_address)
            if registered:
                return registered
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


def register_face(device, user, embedding: list, name: str = '', consent_confirmed: bool = False,
                  request=None) -> FaceProfile:
    """CHỈ được gọi từ giao diện app/web của chủ/người có quyền. Không được gọi từ subscriber MQTT
    (khoá/camera không có đường đăng ký khuôn mặt)."""
    if not consent_confirmed:
        raise ValueError('Cần xác nhận đồng ý thu thập dữ liệu khuôn mặt.')
    profile, _created = FaceProfile.objects.update_or_create(
        user=user, device=device,
        defaults={'name': name, 'consent_confirmed': consent_confirmed, 'is_active': True},
    )
    profile.set_embedding(embedding)
    profile.save()
    meta = {'face_profile_id': str(profile.id)}
    if request is not None:
        audit(request, 'FACE_PROFILE_REGISTERED', device=device, target_user=user, metadata=meta)
    else:
        AuditLog.objects.create(actor_user=user, device=device, action='FACE_PROFILE_REGISTERED',
                                metadata=meta)
    return profile


# ---------------------------------------------------------------- Điện thoại: Bluetooth + NFC giả lập thẻ (HCE)
# Cả 2 kênh dùng cùng cơ chế "vé" ký HMAC; thiết bị TỰ kiểm tra chữ ký + hạn (không cần mạng) rồi
# mở cửa, khi có mạng mới publish sự kiện kèm vé để server ghi log. Vé không có bản ghi DB;
# thu hồi = để vé hết hạn (mặc định 1 giờ) hoặc xoay secret thiết bị.
#
#   key  = HMAC_SHA256(key=<provisioning_secret_hash ASCII>, msg=<nhãn kênh>)
#   sig  = HMAC_SHA256(key, "<device_code>|<user_hex>|<exp>") -> hex, lấy 32 ký tự đầu
#   vé   = "<user_hex>.<exp>.<sig>"          (user_hex = UUID bỏ dấu '-', exp = unix giây)
# Nhãn kênh khác nhau => vé BLE không dùng được ở đầu đọc NFC và ngược lại. Nhãn BLE giữ nguyên
# như trước nên firmware cũ vẫn chạy.
PHONE_CHANNELS = {
    'ble': {'label': b'ble-ticket-v1', 'permission': 'BLUETOOTH', 'flag': 'bluetooth_enabled',
            'method': AccessEvent.METHOD_BLE, 'prefix': 'BLE', 'name': 'Bluetooth'},
    'nfc': {'label': b'nfc-phone-ticket-v1', 'permission': 'NFC_PHONE', 'flag': 'nfc_enabled',
            'method': AccessEvent.METHOD_NFC_PHONE, 'prefix': 'NFC_PHONE', 'name': 'NFC'},
}
TICKET_TTL_SECONDS = int(getattr(settings, 'BLE_TICKET_TTL_SECONDS', 3600))
BLE_TICKET_TTL_SECONDS = TICKET_TTL_SECONDS     # tên cũ


def _ticket_sig(device, kind: str, user_hex: str, exp: int) -> str:
    key = hmac.new(device.provisioning_secret_hash.encode(), PHONE_CHANNELS[kind]['label'],
                   hashlib.sha256).digest()
    msg = f'{device.device_code}|{user_hex}|{exp}'.encode()
    return hmac.new(key, msg, hashlib.sha256).hexdigest()[:32]


def issue_phone_ticket(device, user, kind: str, ttl: int = None):
    """Trả (ticket, exp_unix). View phải kiểm tra quyền + cờ bật kênh của thiết bị trước."""
    exp = int(time.time()) + (ttl or TICKET_TTL_SECONDS)
    user_hex = user.id.hex
    return f'{user_hex}.{exp}.{_ticket_sig(device, kind, user_hex, exp)}', exp


def parse_phone_ticket(device, ticket: str, kind: str):
    """Trả (user, exp) nếu chữ ký hợp lệ và user tồn tại, ngược lại None. Không kiểm tra hạn."""
    try:
        user_hex, exp_s, sig = (ticket or '').strip().split('.')
        exp = int(exp_s)
    except ValueError:
        return None
    if not hmac.compare_digest(sig, _ticket_sig(device, kind, user_hex, exp)):
        return None
    uid = parse_uuid(user_hex)
    user = User.objects.filter(pk=uid).first() if uid else None
    return (user, exp) if user else None


def issue_ble_ticket(device, user, ttl: int = TICKET_TTL_SECONDS):
    return issue_phone_ticket(device, user, 'ble', ttl)


def parse_ble_ticket(device, ticket: str):
    return parse_phone_ticket(device, ticket, 'ble')


def _record_phone_unlock(device, kind, ticket='', ok=True, reason=None, at=None) -> AccessEvent:
    """Thiết bị báo 1 lượt mở/từ chối qua điện thoại (cửa đã xử lý tại chỗ, server chỉ ghi log).
    `at` = unix giây lúc xảy ra (sự kiện offline đến trễ)."""
    cfg = PHONE_CHANNELS[kind]
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
        parsed = parse_phone_ticket(device, ticket, kind)
        if not parsed:
            ok, reason = False, f"{cfg['prefix']}_INVALID_TICKET"
        else:
            user, exp = parsed
            if exp < at_unix:
                ok, reason = False, f"{cfg['prefix']}_TICKET_EXPIRED"
            elif not getattr(device, cfg['flag']) or not has_permission(user, device, cfg['permission']):
                ok, reason = False, f"{cfg['prefix']}_NOT_ALLOWED"
    return _log_event(occurred_at=occurred, device=device, method=cfg['method'], success=ok,
                      reason=None if ok else (reason or f"{cfg['prefix']}_DENIED")[:100], user=user)


def record_ble_unlock(device, ticket: str = '', ok: bool = True, reason=None, at=None) -> AccessEvent:
    return _record_phone_unlock(device, 'ble', ticket, ok, reason, at)


def record_nfc_phone_unlock(device, ticket: str = '', ok: bool = True, reason=None, at=None) -> AccessEvent:
    return _record_phone_unlock(device, 'nfc', ticket, ok, reason, at)


# ============================================================================
# 5. ONLINE / OFFLINE CỦA THIẾT BỊ   (đã BỎ rule engine tự động hoá)
# ============================================================================
OFFLINE_AFTER_SECONDS = 180      # không nhận status > 3 phút -> coi là offline


def evaluate_device_status(device, status_log) -> int:
    """Đã bỏ tự động hoá. Hàm rỗng chỉ để subscriber cũ chưa sửa không bị lỗi - hãy XOÁ lời gọi này."""
    return 0


def mark_offline_devices() -> int:
    """Thiết bị 'online' mà lâu không gửi status -> 'offline'. Subscriber gọi định kỳ."""
    cutoff = timezone.now() - timedelta(seconds=OFFLINE_AFTER_SECONDS)
    return Device.objects.filter(status='online', last_seen_at__lt=cutoff).update(status='offline')


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

# ============================================================================
# 7. VÒNG ĐỜI KHOÁ: KẾT NỐI / CLAIM / GỠ CHỦ / XOAY SECRET
# ============================================================================
# Quy tắc nghiệp vụ:
#   - 'provisioning' = khoá mới, chưa từng có chủ  -> ADMIN hoặc USER đều gán/claim được.
#   - 'revoked'      = đã bị gỡ chủ (factory_reset) -> CHỈ USER tự claim (kể cả chủ cũ); admin KHÔNG gán lại.
#   - Mọi lần claim đều yêu cầu khoá ĐANG kết nối thật (có status/ack gần đây), kể cả khoá giả lập.
ONLINE_WINDOW_SECONDS = 120        # status/ack trong vòng 2 phút => coi là đang kết nối
CLAIM_MAX_FAILS = 5                # sai secret quá số lần này trong cửa sổ => tạm chặn user đó
CLAIM_FAIL_WINDOW_SECONDS = 600


class ClaimError(Exception):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code
        self.message = message


def touch_device(device, *, firmware=None, battery=None) -> None:
    """SUBSCRIBER MQTT phải gọi hàm này mỗi khi nhận status/ack/event từ thiết bị.
    Dùng queryset.update() nên KHÔNG vi phạm chk_devices_owner_vs_status: khoá chưa có chủ chỉ
    được cập nhật last_seen_at, không bao giờ bị đặt 'online'."""
    now = timezone.now()
    fields = {'last_seen_at': now, 'updated_at': now}
    if firmware:
        fields['firmware_version'] = str(firmware)[:30]
    if battery is not None:
        try:
            fields['battery_level'] = max(0, min(100, int(battery)))
        except (TypeError, ValueError):
            pass
    Device.objects.filter(pk=device.pk).update(**fields)
    Device.objects.filter(pk=device.pk, owner__isnull=False, status='offline').update(status='online')


def link_status(device, window: int = ONLINE_WINDOW_SECONDS) -> dict:
    """Bằng chứng khoá đang nối với hệ thống: lần nhận tin MỚI NHẤT (last_seen_at hoặc
    DeviceStatusLog) còn trong cửa sổ `window` giây. Kèm kết quả PING gần nhất (vòng hai chiều)."""
    device = Device.objects.get(pk=device.pk)
    last_log = (DeviceStatusLog.objects.filter(device=device).order_by('-recorded_at')
                .values_list('recorded_at', flat=True).first())
    seen = [t for t in (device.last_seen_at, last_log) if t]
    last = max(seen) if seen else None
    age = (timezone.now() - last).total_seconds() if last else None
    ping = DeviceCommand.objects.filter(device=device, command_type='PING').order_by('-created_at').first()
    return {
        'connected': bool(last is not None and age <= window),
        'last_seen_at': last,
        'seconds_ago': int(age) if age is not None else None,
        'firmware': device.firmware_version, 'battery': device.battery_level,
        'mac': device.mac_address, 'status': device.status, 'has_owner': bool(device.owner_id),
        'ping_status': ping.status if ping else None,
        'ping_at': ping.created_at if ping else None,
    }


def ping_device(device, issued_by) -> DeviceCommand:
    """Gửi PING (hai chiều: thiết bị phải ack). issued_by bắt buộc vì khoá chưa có chủ."""
    return dispatch_command(device, 'PING', source='admin', issued_by=issued_by, ttl=15)


def claim_device(device_id, new_owner, *, by_admin: bool) -> Device:
    """Gán chủ cho khoá. Dùng chung cho admin và user (người gọi tự ghi audit)."""
    with transaction.atomic():
        device = Device.objects.select_for_update().get(pk=device_id)
        if device.owner_id:
            raise ClaimError('ALREADY_OWNED', 'Thiết bị đã có chủ sở hữu.')
        if device.status not in Device.NO_OWNER_STATUSES:
            raise ClaimError('BAD_STATE', 'Trạng thái thiết bị không cho phép gán chủ.')
        if not new_owner.is_active:
            raise ClaimError('OWNER_INACTIVE', 'Tài khoản chủ sở hữu đang bị vô hiệu hoá.')
        if is_admin(new_owner):
            raise ClaimError('OWNER_IS_ADMIN',
                             'Tài khoản quản trị không được làm chủ khoá. Hãy dùng tài khoản người dùng thường.')
        if by_admin and device.status != 'provisioning':
            raise ClaimError('ADMIN_CANNOT_REASSIGN',
                             'Khoá đã bị gỡ chủ (revoked): quản trị viên không được gán lại. '
                             'Người dùng phải tự thêm khoá bằng mã thiết bị + secret.')
        if not link_status(device)['connected']:
            raise ClaimError('NOT_CONNECTED',
                             'Khoá chưa kết nối với hệ thống (chưa nhận được tín hiệu gần đây). '
                             'Hãy cấp nguồn/kết nối mạng cho khoá rồi thử lại.')
        device.owner = new_owner
        device.status = 'online'
        fields = ['owner', 'status', 'updated_at']
        if not device.is_purchased:
            device.is_purchased = True
            device.purchased_at = timezone.now()
            fields += ['is_purchased', 'purchased_at']
        device.save(update_fields=fields)
        return device


def user_claim_device(user, device_code: str, secret: str, request=None) -> Device:
    """User tự claim khoá bằng device_code + provisioning secret (kể cả chủ cũ). Có giới hạn thử sai."""
    since = timezone.now() - timedelta(seconds=CLAIM_FAIL_WINDOW_SECONDS)
    fails = AuditLog.objects.filter(actor_user=user, action='DEVICE_CLAIM_FAILED',
                                    created_at__gte=since).count()
    if fails >= CLAIM_MAX_FAILS:
        raise ClaimError('RATE_LIMITED', 'Bạn đã thử sai quá nhiều lần. Vui lòng thử lại sau ít phút.')
    code = (device_code or '').strip().upper()
    device = Device.objects.filter(device_code=code).first()
    ok = bool(device and secret and hmac.compare_digest(device.provisioning_secret_hash, hash_token(secret)))
    if not ok:
        raise ClaimError('BAD_CREDENTIALS', 'Mã thiết bị hoặc secret không đúng.')   # không lộ cái nào sai
    return claim_device(device.pk, user, by_admin=False)


def release_device(device_id):
    """Gỡ chủ: factory_reset (status=revoked, owner=None) + thu hồi mọi quyền truy cập cũ.
    Trả về (device, chủ_cũ, số_lượng_đã_thu_hồi). Người gọi ghi audit + thông báo."""
    with transaction.atomic():
        device = Device.objects.select_for_update().select_related('owner').get(pk=device_id)
        if not device.owner_id:
            raise ClaimError('NO_OWNER', 'Thiết bị hiện không có chủ.')
        previous = device.owner
        now = timezone.now()
        counts = {
            'accesses': DeviceAccess.objects.filter(device=device, is_active=True)
                        .update(is_active=False, revoked_at=now),
            'cards': CardDeviceAccess.objects.filter(device=device, is_active=True).update(is_active=False),
            'pins': DoorPinCode.objects.filter(device=device, is_revoked=False)
                    .update(is_revoked=True, revoked_at=now),
            'faces': FaceProfile.objects.filter(device=device, is_active=True).update(is_active=False),
            'share_codes': 0,      # đã bỏ mã chia sẻ; giữ khoá để code gọi release_device cũ không lỗi
            'commands': DeviceCommand.objects.filter(device=device, status__in=('pending', 'sent'))
                        .update(status='expired'),
        }
        device.factory_reset()
        return device, previous, counts


def rotate_secret(device_id) -> tuple:
    """Xoay provisioning secret. Trả về (device, secret_gốc). Thiết bị phải nạp lại secret mới;
    vé BLE đã cấp (ký bằng secret cũ) cũng mất hiệu lực."""
    with transaction.atomic():
        device = Device.objects.select_for_update().get(pk=device_id)
        secret = secrets.token_hex(16)
        device.provisioning_secret_hash = hash_token(secret)
        device.save(update_fields=['provisioning_secret_hash', 'updated_at'])
        return device, secret