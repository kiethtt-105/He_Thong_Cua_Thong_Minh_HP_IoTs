# smartlock/services.py

import hashlib
import html as _html
import hmac
import ipaddress
import json
import logging
import math
import os
import re
import secrets
import threading
import time
import uuid
from datetime import datetime, timedelta, timezone as dt_timezone
from email.utils import parseaddr
from typing import Optional

import pyotp
from django.conf import settings
from django.contrib.auth.tokens import default_token_generator
from django.core.mail import send_mail as _django_send_mail
from django.db import connections, transaction
from django.db.models import F, Q
from django.db.models.signals import post_save
from django.template import engines
from django.template.loader import render_to_string
from django.urls import reverse
from django.utils import timezone
from django.utils.encoding import force_bytes
from django.utils.html import linebreaks, strip_tags, urlize
from django.utils.http import urlsafe_base64_encode
from django.utils.safestring import mark_safe

from smartlock_django import links

from .models import (
    AccessCard, AccessEvent, AuditLog, CardDeviceAccess, Device,
    DeviceAccess, DeviceCommand, DeviceStatusLog, DoorPinCode, FaceProfile, NfcLog, NfcReader,
    Notification, OneTimeCode, Permission, SystemSettings, TwoFactorConfig, User, hash_card_uid,
)

logger = logging.getLogger('smartlock.services')


LOGIN_FAIL_WINDOW = timedelta(minutes=30)
LOGIN_STAGE_RESET = timedelta(hours=24)
MAX_FAILED_ATTEMPTS = 5


EMAIL_ASYNC = os.environ.get('EMAIL_ASYNC', '' if os.environ.get('VERCEL') else '1').strip().lower() in ('1', 'true', 'yes')


def send_mail(subject, plain, html, to, log_body=True) -> bool:
    if EMAIL_ASYNC:
        threading.Thread(target=_send_mail_now, args=(subject, plain, html, to, log_body),
                         name='send-mail', daemon=True).start()
        return True
    return _send_mail_now(subject, plain, html, to, log_body)


def _send_mail_now(subject, plain, html, to, log_body=True) -> bool:
    logger.info('send_mail: to=%s subject=%r plain_preview=%r', to, subject,
                plain[:200] if log_body else '<ẩn nội dung>')
    try:
        n = _django_send_mail(subject, plain, None, [to], html_message=html)
        logger.info('send_mail: OK (%s mail) -> %s', n, to)
        return True
    except Exception:
        logger.exception('send_mail: THẤT BẠI -> %s', to)
        return False


def safe_eq(a, b) -> bool:
    if not a or not b:
        return False
    return hmac.compare_digest(str(a).encode('utf-8'), str(b).encode('utf-8'))


def hash_token(token) -> str:
    return hashlib.sha256(str(token).encode()).hexdigest()


def valid_ip(value):
    try:
        return str(ipaddress.ip_address((value or '').strip()))
    except ValueError:
        return None


def client_ip(request) -> str:
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
    return int(system_settings().session_timeout_hours) * 3600


def is_admin(user) -> bool:
    return bool(user.is_staff or user.is_superuser or user.is_admin)


def admins():
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
    pass


def audit(request, action, *, device=None, target_user=None, success=True,
          severity='info', metadata=None, actor='auto', username_attempt=None, strict=False):
    if actor == 'auto':
        actor = request.user if request.user.is_authenticated else None
    snapshot = dict(metadata or {})
    if actor is not None:
        snapshot.setdefault('actor_email', actor.email)
    if target_user is not None:
        snapshot.setdefault('target_email', target_user.email)
    if device is not None:
        snapshot.setdefault('device_code', device.device_code)
    fields = dict(
        actor_user=actor, target_user=target_user, device=device, action=action[:50],
        username_attempt=username_attempt, severity=severity, success=success,
        ip_address=client_ip(request), user_agent=user_agent(request), metadata=snapshot or None,
    )
    try:
        if connections['default'].in_atomic_block:
            with transaction.atomic():
                AuditLog.objects.create(**fields)
        else:
            AuditLog.objects.create(**fields)
    except Exception as exc:
        logger.exception('audit: không ghi được log %s', action)
        if strict:
            raise AuditWriteError(action) from exc


def notify(user, title, message, severity='info', device=None, type_='SYSTEM'):
    Notification.objects.create(
        user=user, device=device, type=type_, title=title[:150], message=message, severity=severity,
    )


def notify_login(request, user) -> None:
    try:
        ip = client_ip(request)
        known = set(AuditLog.objects.filter(actor_user=user, action='LOGIN', success=True, ip_address__isnull=False)
                    .order_by('-created_at').values_list('ip_address', flat=True)[:100])
        if not known or ip in known:
            return
        notify(user, 'Đăng nhập từ địa chỉ IP mới',
               f'Tài khoản vừa đăng nhập từ IP {ip}. Nếu không phải bạn, hãy đổi mật khẩu ngay.',
               severity='warning', type_='LOGIN_NEW_IP')
    except Exception:
        logger.exception('notify_login: lỗi (bỏ qua, không ảnh hưởng đăng nhập)')


def accessible_devices(user):
    now = timezone.now()
    shared_ids = (
        DeviceAccess.objects.filter(user=user, is_active=True, accepted=True, valid_from__lte=now)
        .filter(Q(expires_at__isnull=True) | Q(expires_at__gt=now))
        .values('device_id')
    )
    return Device.objects.filter(Q(owner=user) | Q(id__in=shared_ids))


def user_has_live_access(user, device) -> bool:
    if user is None or not user.is_active:
        return False
    if device.owner_id == user.id:
        return True
    return _live_access(user, timezone.now()).filter(device=device).exists()


def revoke_user_credentials(device, user) -> dict:
    now = timezone.now()
    return {
        'cards': CardDeviceAccess.objects.filter(device=device, access_card__user=user, is_active=True)
                 .update(is_active=False),
        'faces': FaceProfile.objects.filter(device=device, user=user, is_active=True).update(is_active=False),
        'pins': DoorPinCode.objects.filter(device=device, created_by=user, is_revoked=False)
                .update(is_revoked=True, revoked_at=now),
    }


def has_permission(user, device, code) -> bool:
    if device.owner_id == user.id:
        return True
    now = timezone.now()
    return DeviceAccess.objects.filter(
        device=device, user=user, is_active=True, accepted=True,
        valid_from__lte=now, permissions__code=code,
    ).filter(Q(expires_at__isnull=True) | Q(expires_at__gt=now)).exists()


PERMISSION_CATALOG = [
    ('UNLOCK', 'Mở khoá từ xa (Internet)',
     'Bấm nút MỞ trên web/app khi khoá đang online và bật Wi-Fi.', False),
    ('LOCK', 'Khoá cửa từ xa (Internet)',
     'Bấm nút KHOÁ trên web/app khi khoá đang online và bật Wi-Fi.', False),
    ('BLUETOOTH', 'Mở bằng Bluetooth (app điện thoại)',
     'App xin vé Bluetooth để mở khi đứng gần cửa. Vé hết hạn sau 1 giờ.', False),
    ('NFC_PHONE', 'Mở bằng NFC điện thoại (app)',
     'Điện thoại giả lập thẻ NFC để chạm đầu đọc. Vé hết hạn sau 1 giờ.', False),
    ('manage_nfc', 'Đăng ký thẻ NFC CỦA RIÊNG MÌNH',
     'Thêm/đổi tên/bật-tắt/xoá thẻ do chính người này đăng ký trên khoá. Không thấy và không đụng được thẻ của người khác.', True),
    ('manage_face_profiles', 'Đăng ký khuôn mặt CỦA RIÊNG MÌNH',
     'Quét và quản lý khuôn mặt của chính người này trên khoá. Không thấy khuôn mặt của người khác.', True),
    ('manage_pins', 'Cấp mã PIN cho khách',
     'Tạo mã PIN cho khách bấm trên bàn phím và thu hồi các mã DO CHÍNH MÌNH TẠO. Không thấy mã của người khác.', True),
    ('view_history', 'Xem lịch sử ra vào',
     'Xem toàn bộ nhật ký mở cửa của khoá và nhận popup khi cửa mở.', False),
]
PERMISSION_CODES = tuple(code for code, *_ in PERMISSION_CATALOG)

PERMISSION_META = {
    'UNLOCK': {'group': 'open', 'scope': 'device'},
    'LOCK': {'group': 'open', 'scope': 'device'},
    'BLUETOOTH': {'group': 'open', 'scope': 'device'},
    'NFC_PHONE': {'group': 'open', 'scope': 'device'},
    'manage_nfc': {'group': 'own', 'scope': 'own'},
    'manage_face_profiles': {'group': 'own', 'scope': 'own'},
    'manage_pins': {'group': 'guest', 'scope': 'own'},
    'view_history': {'group': 'watch', 'scope': 'device'},
}
PERMISSION_GROUPS = [
    ('open', 'Mở / khoá cửa', 'Điều khiển cửa trực tiếp.'),
    ('own', 'Phương tiện mở cửa của chính họ', 'Chỉ thao tác trên thẻ / khuôn mặt do họ tự đăng ký.'),
    ('guest', 'Cấp quyền cho khách', 'Tạo mã PIN tạm thời cho người khác.'),
    ('watch', 'Giám sát', 'Xem nhật ký và nhận thông báo.'),
]

ROLE_PRESETS = {
    'viewer': {'label': 'Chỉ xem', 'desc': 'Xem lịch sử ra vào và nhận thông báo cửa mở. Không điều khiển được cửa.',
               'codes': ['view_history']},
    'guest': {'label': 'Khách / người thuê', 'desc': 'Mở và khoá cửa từ xa, dùng điện thoại mở cửa. Không xem lịch sử, không quản lý gì.',
              'codes': ['UNLOCK', 'LOCK', 'BLUETOOTH', 'NFC_PHONE']},
    'family': {'label': 'Thành viên gia đình', 'desc': 'Như Khách, thêm xem lịch sử và tự đăng ký thẻ NFC + khuôn mặt của mình.',
               'codes': ['UNLOCK', 'LOCK', 'BLUETOOTH', 'NFC_PHONE', 'view_history', 'manage_nfc',
                         'manage_face_profiles']},
    'manager': {'label': 'Người trông nhà', 'desc': 'Như Thành viên gia đình, thêm cấp mã PIN cho khách.',
                'codes': list(PERMISSION_CODES)},
}
OWNER_ONLY_ACTIONS = [
    'Chia sẻ lại / thu hồi quyền của người khác',
    'Sửa tên, vị trí, bật/tắt Wi-Fi, Bluetooth, NFC của khoá',
    'Khởi động lại khoá',
    'Cấu hình đầu đọc NFC và bật đăng ký thẻ bằng quẹt',
    'Xem, bật/tắt, xoá thẻ - khuôn mặt - mã PIN của người khác',
]

_perms_synced = False


def ensure_default_permissions() -> None:
    global _perms_synced
    if _perms_synced:
        return
    existing = {p.code: p for p in Permission.objects.all()}
    for code, name, desc, sensitive in PERMISSION_CATALOG:
        p = existing.get(code)
        if p is None:
            Permission.objects.get_or_create(
                code=code, defaults={'name': name, 'description': desc, 'is_sensitive': sensitive})
        elif (p.name, p.description, p.is_sensitive) != (name, desc, sensitive):
            Permission.objects.filter(pk=p.pk).update(name=name, description=desc, is_sensitive=sensitive)
    _perms_synced = True


def preset_codes(key):
    preset = ROLE_PRESETS.get(key)
    return list(preset['codes']) if preset else None


def permission_form_context() -> dict:
    by_code = {p.code: p for p in Permission.objects.filter(code__in=PERMISSION_CODES)}
    groups = []
    for gkey, gname, gdesc in PERMISSION_GROUPS:
        items = []
        for code, name, desc, sensitive in PERMISSION_CATALOG:
            meta = PERMISSION_META[code]
            if meta['group'] == gkey:
                items.append({'code': code, 'name': name, 'description': desc, 'sensitive': sensitive,
                              'scope': meta['scope'], 'scope_text': 'chỉ dữ liệu của chính họ' if meta['scope'] == 'own'
                              else 'toàn bộ khoá', 'id': by_code[code].id if code in by_code else None})
        groups.append({'key': gkey, 'name': gname, 'description': gdesc, 'items': items})
    return {
        'permission_groups': groups,
        'role_presets': [{'key': k, **v} for k, v in ROLE_PRESETS.items()],
        'owner_only_actions': OWNER_ONLY_ACTIONS,
    }


def _live_access(user, now):
    return (DeviceAccess.objects.filter(user=user, is_active=True, accepted=True, valid_from__lte=now)
            .filter(Q(expires_at__isnull=True) | Q(expires_at__gt=now)))


def devices_with_permission(user, code):
    ids = _live_access(user, timezone.now()).filter(permissions__code=code).values('device_id')
    return Device.objects.filter(Q(owner=user) | Q(id__in=ids))


def permission_codes(user, device) -> set:
    if device.owner_id == user.id:
        return set(PERMISSION_CODES)
    codes = (_live_access(user, timezone.now()).filter(device=device)
             .values_list('permissions__code', flat=True))
    return {c for c in codes if c}


def permission_map(user, devices) -> dict:
    out, shared = {}, []
    for d in devices:
        if d.owner_id == user.id:
            out[d.id] = set(PERMISSION_CODES)
        else:
            out[d.id] = set()
            shared.append(d.id)
    if shared:
        rows = (_live_access(user, timezone.now()).filter(device_id__in=shared)
                .values_list('device_id', 'permissions__code'))
        for device_id, code in rows:
            if code:
                out[device_id].add(code)
    return out


def capabilities(user, device) -> dict:
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
        'manage_sharing': device.owner_id == user.id,
    }


def grant_access(device, owner, target, permissions, expires_at):
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
        subject, html, plain = render_email('device_shared', {
            'full_name': target.full_name or target.username,
            'owner_name': owner_name, 'device_name': device.name,
            'device_location': device.location or '', 'permissions': perm_names,
            'expires_text': expires, 'is_update': not created,
            'action_url': links.public_absolute(reverse('smartlock:device-detail', args=[device.id])),
        })
        return send_mail(subject, plain, html, target.email)
    except Exception:
        logger.exception('share: không gửi được email tới %s', target.pk)
        return False


def door_watchers(device):
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
    dev_id = parse_uuid(raw_id)
    if strict:
        return queryset.filter(id=dev_id).first() if dev_id else None
    device = queryset.filter(id=dev_id).first() if dev_id else None
    return device or queryset.first()


def register_failure(user, ip):
    stages = system_settings().login_lockout_stage_minutes or [5, 10, 30]
    now = timezone.now()
    locked_minutes = None
    with transaction.atomic():
        lock = User.objects.select_for_update().get(pk=user.pk)
        if lock.login_locked_until and lock.login_locked_until > now:
            return None
        last = lock.login_last_failed_at
        if last and now - last > LOGIN_FAIL_WINDOW:
            lock.login_failed_attempts = 0
        if last and now - last > LOGIN_STAGE_RESET:
            lock.login_lock_stage = 0
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
    link = links.public_absolute(reverse('smartlock:verify_email', args=[token]))
    subject, html, plain = render_email('user_verification', {
        'full_name': user.full_name or user.username,
        'username': user.username,
        'verification_link': link,
        'expiry_minutes': minutes,
    })
    return send_mail(subject, plain, html, user.email, log_body=False)


BRAND_NAME = 'Smart Lock'

_GREET = 'Xin chào <strong>{{ full_name }}</strong>,'
EMAIL_SPECS = {
    'user_verification': dict(
        subject='Xác thực tài khoản {{ brand_name }}',
        preheader='Xác thực email để kích hoạt tài khoản {{ brand_name }} của bạn.',
        heading='Xác thực tài khoản của bạn',
        greeting='Xin chào <strong>{{ full_name|default:username }}</strong>,',
        paras=['Cảm ơn bạn đã đăng ký tài khoản {{ brand_name }}. Chỉ còn một bước nữa: nhấn nút bên dưới '
               'để xác thực email và kích hoạt tài khoản.'],
        notice=('info', '{% if expiry_minutes %}&#9201;&#65039; Liên kết có hiệu lực trong '
                        '<strong>{{ expiry_minutes }} phút</strong>.{% endif %}'),
        button=('{{ verification_link }}', 'Xác thực tài khoản'),
        link='{{ verification_link }}',
        footnote='Nếu bạn không thực hiện đăng ký này, hãy bỏ qua email &mdash; sẽ không có tài khoản nào được kích hoạt.',
    ),
    'password_reset': dict(
        subject='Đặt lại mật khẩu {{ brand_name }}',
        preheader='Nhấn vào liên kết để đặt lại mật khẩu, liên kết hết hạn sau {{ expiry_minutes }} phút.',
        heading='Đặt lại mật khẩu',
        greeting=_GREET,
        paras=['{% if by_admin %}Quản trị viên đã gửi liên kết này theo yêu cầu của bạn. {% endif %}'
               'Chúng tôi đã nhận được yêu cầu đặt lại mật khẩu cho tài khoản {{ brand_name }} của bạn. '
               'Nhấn nút bên dưới để tạo mật khẩu mới.'],
        notice=('warn', '&#9201;&#65039; Liên kết chỉ có hiệu lực trong <strong>{{ expiry_minutes }} phút</strong> '
                        'và dùng được một lần.'),
        button=('{{ password_reset_link }}', 'Đặt lại mật khẩu'),
        link='{{ password_reset_link }}',
        footnote='<strong>Không phải bạn?</strong> Hãy bỏ qua email này &mdash; mật khẩu hiện tại vẫn được giữ '
                 'nguyên và an toàn.',
    ),
    'two_factor_code': dict(
        subject='Mã xác thực 2 lớp {{ brand_name }}',
        preheader='Mã xác thực của bạn có hiệu lực {{ expiry_minutes }} phút.',
        heading='Mã xác thực của bạn',
        greeting=_GREET,
        paras=['Dùng mã bên dưới để hoàn tất bước xác thực 2 lớp:'],
        code=('Mã OTP', '{{ otp_code }}'),
        notice=('warn', '&#9201;&#65039; Mã có hiệu lực trong <strong>{{ expiry_minutes }} phút</strong> và chỉ '
                        'dùng được một lần. Tuyệt đối không chia sẻ mã này với bất kỳ ai.'),
        footnote='Nếu không phải bạn yêu cầu, hãy đổi mật khẩu ngay'
                 '{% if support_email %} hoặc liên hệ {{ support_email }}{% endif %}.',
    ),
    'device_shared': dict(
        subject='{% if is_update %}Quyền truy cập khoá của bạn đã thay đổi{% else %}Có người vừa chia sẻ khoá cho bạn{% endif %}',
        preheader='{{ owner_name }} {% if is_update %}đã thay đổi quyền của bạn trên{% else %}đã chia sẻ{% endif %} khoá {{ device_name }}.',
        heading='{% if is_update %}Quyền truy cập đã thay đổi{% else %}Bạn được chia sẻ một chiếc khoá{% endif %}',
        greeting=_GREET,
        paras=['<strong>{{ owner_name }}</strong> {% if is_update %}vừa thay đổi quyền của bạn trên khoá '
               '<strong>{{ device_name }}</strong>.{% else %}vừa chia sẻ khoá <strong>{{ device_name }}</strong> '
               'cho bạn. Quyền có hiệu lực ngay, không cần nhập mã.{% endif %}'],
        rows=[('Khoá', '{{ device_name }}', False),
              ('Vị trí', '{{ device_location }}', False),
              ('Quyền', '{{ permissions|join:", "|default:"Chưa có quyền nào" }}', False),
              ('Hết hạn', '{{ expires_text }}', False)],
        button=('{{ action_url }}', 'Mở khoá'),
        footnote='Nếu bạn không biết người chia sẻ, hãy liên hệ chủ khoá hoặc bỏ qua email này.',
    ),
    'device_added': dict(
        subject='Thiết bị mới đã được thêm vào tài khoản của bạn',
        preheader='Thiết bị {{ device_name }} đã được thêm vào tài khoản của bạn.',
        heading='Thiết bị mới đã được thêm',
        greeting=_GREET,
        paras=['Quản trị viên vừa thêm một thiết bị vào tài khoản của bạn. Bạn có thể truy cập ngay để điều khiển.'],
        rows=[('Tên thiết bị', '{{ device_name }}', False), ('Mã thiết bị', '{{ device_code }}', True)],
        button=('{{ action_url }}', 'Mở bảng điều khiển'),
        footnote='Nếu bạn không nhận ra thiết bị này, hãy liên hệ quản trị viên.',
    ),
    'admin_device_approval': dict(
        subject='Thiết bị mới cần kích hoạt',
        preheader='Thiết bị {{ device_code }} của {{ user_email }} đang chờ kích hoạt.',
        heading='Thiết bị mới cần kích hoạt',
        greeting='Xin chào Quản trị viên,',
        paras=['Có một thiết bị mới đang chờ kích hoạt. Vui lòng kiểm tra và kích hoạt, hoặc thông báo cho chủ thiết bị.'],
        rows=[('Mã thiết bị', '{{ device_code }}', True), ('Chủ thiết bị', '{{ user_email }}', False)],
        button=('{{ action_url }}', 'Kích hoạt thiết bị'),
    ),
    'system_announcement': dict(
        subject='{{ title|default:"Thông báo hệ thống" }}',
        preheader='{{ title|default:"Thông báo hệ thống" }} từ {{ brand_name }}.',
        heading='{{ title|default:"Thông báo hệ thống" }}',
        paras=['{{ body|linebreaks }}'],
        button=('{{ action_url }}', '{{ action_label|default:"Xem chi tiết" }}'),
    ),
}


def _email_context(context: dict) -> dict:
    ctx = dict(context)
    if not ctx.get('password_reset_link') and ctx.get('reset_link'):
        ctx['password_reset_link'] = ctx['reset_link']
    ctx.setdefault('brand_name', BRAND_NAME)
    ctx.setdefault('year', timezone.now().year)
    if 'support_email' not in ctx:
        ctx['support_email'] = parseaddr(getattr(settings, 'DEFAULT_FROM_EMAIL', '') or '')[1]
    return ctx


def _rt(text, ctx):
    if not text:
        return mark_safe('')
    return mark_safe(engines['django'].from_string(text).render(ctx).strip())


def _plain(text) -> str:
    return _html.unescape(strip_tags(str(text or ''))).strip()


def _email_plain(v: dict, brand: str) -> str:
    out = [_plain(v['heading']), '']
    if v['greeting']:
        out += [_plain(v['greeting']), '']
    out += [x for p in v['paras'] for x in (_plain(p), '')]
    if v['code']:
        out += [f"{_plain(v['code_label'])}: {_plain(v['code'])}", '']
    if v['rows']:
        out += [f'{label}: {_plain(value)}' for label, value, _mono in v['rows']] + ['']
    if v['notice']:
        out += [_plain(v['notice']), '']
    if v['button_url']:
        out += [f"{_plain(v['button_label'])}: {_plain(v['button_url'])}", '']
    if v['footnote']:
        out += [_plain(v['footnote']), '']
    out.append(f'-- {brand}')
    return re.sub(r'\n{3,}', '\n\n', '\n'.join(out)).strip()


def render_email(template_name: str, context: dict) -> tuple:
    key = template_name[:-5] if template_name.endswith('.html') else template_name
    ctx = _email_context(context)
    fallback_title = key.replace('_', ' ').title()
    spec = EMAIL_SPECS.get(key) or {'subject': fallback_title, 'heading': fallback_title}
    subject = fallback_title
    try:
        subject = ' '.join(_html.unescape(_rt(spec['subject'], ctx)).split())
        notice_kind, notice_text = spec.get('notice') or ('info', '')
        button_url, button_label = spec.get('button') or ('', '')
        code_label, code_value = spec.get('code') or ('', '')
        v = {
            'preheader': _rt(spec.get('preheader'), ctx),
            'heading': _rt(spec.get('heading') or spec['subject'], ctx),
            'greeting': _rt(spec.get('greeting'), ctx),
            'paras': [p for p in (_rt(x, ctx) for x in spec.get('paras', ())) if p],
            'code_label': _rt(code_label, ctx), 'code': _rt(code_value, ctx),
            'rows': [(label, val, mono) for label, raw, mono in spec.get('rows', ())
                     for val in [_rt(raw, ctx)] if val],
            'notice_kind': notice_kind, 'notice': _rt(notice_text, ctx),
            'button_url': _rt(button_url, ctx), 'button_label': _rt(button_label, ctx),
            'link': _rt(spec.get('link'), ctx),
            'footnote': _rt(spec.get('footnote'), ctx),
        }
        html = render_to_string('emails/message.html', {**ctx, **v})
        plain = _email_plain(v, ctx['brand_name'])
    except Exception:
        logger.exception('render_email: lỗi khi dựng mail %s', key)
        keys = ('verification_link', 'password_reset_link', 'otp_code', 'action_url')
        plain = '\n'.join(str(ctx[k]) for k in keys if ctx.get(k)) or subject
        html = linebreaks(urlize(plain, autoescape=True))
    return subject, html, plain


def send_password_reset(request, user, by_admin=None) -> bool:
    link = links.public_absolute(reverse('smartlock:reset_password_confirm', args=[
        urlsafe_base64_encode(force_bytes(str(user.pk))), default_token_generator.make_token(user),
    ]))
    subject, html, plain = render_email('password_reset', {
        'full_name': user.full_name or user.username,
        'password_reset_link': link,
        'expiry_minutes': settings.PASSWORD_RESET_TIMEOUT // 60,
        'by_admin': bool(by_admin),
    })
    return send_mail(subject, plain, html, user.email, log_body=False)


def mask_email(email: str) -> str:
    name, _, dom = (email or '').partition('@')
    return (name[:2] if len(name) > 2 else name[:1]) + '***@' + dom


def invalidate_system_settings() -> None:
    pass


MQTT_BROKER_HOST = links.MQTT_HOST
MQTT_BROKER_PORT = links.MQTT_PORT
MQTT_USE_TLS = links.MQTT_USE_TLS
MQTT_PUBLISHER_USERNAME = os.environ.get('MQTT_PUBLISHER_USERNAME', '')
MQTT_PUBLISHER_PASSWORD = os.environ.get('MQTT_PUBLISHER_PASSWORD', '')


class MqttPublishError(Exception):
    pass


def cmd_topic(device_code: str) -> str:
    return f'smartlock/{device_code}/cmd'


STATUS_TOPIC = 'smartlock/+/status'
EVENT_TOPIC = 'smartlock/+/event'
ACK_TOPIC = 'smartlock/+/ack'


def publish_command(device_code: str, payload: dict) -> None:
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
            client_id=f'django-pub-{uuid.uuid4().hex[:16]}',
        )
    except Exception as e:
        logger.warning('MQTT publish thất bại tới %s: %s', device_code, e)
        raise MqttPublishError(str(e)) from e


def dispatch_command(device, command, *, source, issued_by=None, ttl=30, extra=None) -> DeviceCommand:
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
            'token': cmd.command_token_hash,
            'source': source,
            'expires_at': int(cmd.expires_at.timestamp()), 'ttl': int(ttl), 'server_time': int(time.time()),
            **(extra or {}),
        })
        cmd.status = 'sent'
    except MqttPublishError as e:
        cmd.status = 'failed'
        cmd.publish_error = str(e)[:200]
        logger.warning('dispatch_command: publish %s thất bại cho %s: %s', command, device.device_code, e)
    cmd.save(update_fields=['status'])
    return cmd


BURST_FAIL_THRESHOLD = 3
BURST_FAIL_WINDOW_SECONDS = 60
BURST_LOCKOUT_SECONDS = 60
BURST_LOCKOUT_STAGES = (60, 300, 1800)
BURST_STAGE_WINDOW_SECONDS = 24 * 3600
BURST_NOTIFY_COOLDOWN_SECONDS = 600
LOCKOUT_ACTION = 'ACCESS_BURST_LOCKOUT'
NON_COUNTED_REASONS = ('DEVICE_LOCKED_OUT', 'MQTT_PUBLISH_FAILED', 'CARD_REGISTERED', 'ACCESS_REVOKED',
                       'BLE_NOT_ALLOWED', 'NFC_PHONE_NOT_ALLOWED')


def normalize_uid(raw_uid: str) -> str:
    return re.sub(r'[\s:\-]', '', raw_uid or '').upper()


def count_recent_failures(device, window_seconds) -> int:
    since = timezone.now() - timedelta(seconds=window_seconds)
    return (AccessEvent.objects.filter(device=device, success=False, created_at__gte=since)
            .exclude(reason__in=NON_COUNTED_REASONS).count())


def in_lockout(device) -> bool:
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
        pass
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
STALE_EVENT_SECONDS = 300


def _announce_access(event: AccessEvent) -> None:
    who = (event.user.full_name or event.user.username) if event.user_id else 'Ai đó'
    announce_door_event(
        event.device, 'Cửa vừa được mở',
        f'{who} đã mở "{event.device.name}" bằng {METHOD_TEXT.get(event.method, event.method)}.')


def _push_unlock(device, source, extra, push=True) -> bool:
    if not push:
        return True
    return dispatch_command(device, 'UNLOCK', source=source, extra=extra).status == 'sent'


def _log_event(occurred_at=None, **kwargs) -> AccessEvent:
    event = AccessEvent.objects.create(**kwargs)
    if occurred_at:
        AccessEvent.objects.filter(pk=event.pk).update(created_at=occurred_at)
        event.created_at = occurred_at
    if not event.success and event.reason not in NON_COUNTED_REASONS:
        _handle_burst_if_needed(event.device)
    if event.success and (occurred_at is None
                          or (timezone.now() - occurred_at).total_seconds() <= STALE_EVENT_SECONDS):
        try:
            _announce_access(event)
        except Exception:
            logger.exception('popup: không tạo được thông báo mở cửa')
    return event


def _auto_register_card(device, raw_uid, ip_address=None):
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


def verify_rfid_tap(device, raw_uid: str, ip_address=None, push: bool = True) -> AccessEvent:
    with transaction.atomic():
        if in_lockout(device):
            return _log_event(device=device, method=AccessEvent.METHOD_RFID, success=False,
                              reason='DEVICE_LOCKED_OUT', ip_address=ip_address)
        card = AccessCard.objects.filter(
            card_uid_hash__in=[hash_card_uid(normalize_uid(raw_uid)),
                               hash_token(normalize_uid(raw_uid))],
            is_active=True,
            carddeviceaccess__device=device, carddeviceaccess__is_active=True,
        ).first()
        if not card:
            registered = _auto_register_card(device, raw_uid, ip_address)
            if registered:
                return registered
            return _log_event(device=device, method=AccessEvent.METHOD_RFID, success=False,
                              reason='UNKNOWN_CARD', ip_address=ip_address)
        if not user_has_live_access(card.user, device):
            return _log_event(device=device, method=AccessEvent.METHOD_RFID, success=False,
                              reason='ACCESS_REVOKED', user=card.user, access_card=card, ip_address=ip_address)

    ok = _push_unlock(device, 'rfid', {'card_id': str(card.id)}, push)
    return _log_event(device=device, method=AccessEvent.METHOD_RFID, success=ok,
                      reason=None if ok else 'MQTT_PUBLISH_FAILED', user=card.user,
                      access_card=card, ip_address=ip_address)


def verify_door_pin(device, raw_pin: str, ip_address=None, push: bool = True) -> AccessEvent:
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
        if matched.created_by_id and not user_has_live_access(matched.created_by, device):
            return _log_event(device=device, method=AccessEvent.METHOD_PIN, success=False,
                              reason='ACCESS_REVOKED', door_pin=matched, user=matched.created_by,
                              ip_address=ip_address)
        matched.register_use()

    ok = _push_unlock(device, 'pin', {'pin_id': str(matched.id)}, push)
    if not ok:
        DoorPinCode.objects.filter(pk=matched.pk, use_count__gt=0).update(use_count=F('use_count') - 1)
    return _log_event(device=device, method=AccessEvent.METHOD_PIN, success=ok,
                      reason=None if ok else 'MQTT_PUBLISH_FAILED',
                      door_pin=matched, user=matched.created_by, ip_address=ip_address)


def generate_unique_pin(device, digits: int = 6, attempts: int = 20) -> str:
    active = list(DoorPinCode.objects.filter(device=device, is_revoked=False, expires_at__gt=timezone.now()))
    for _ in range(attempts):
        pin = ''.join(secrets.choice('0123456789') for _ in range(digits))
        if not any(p.check_pin(pin) for p in active):
            return pin
    raise RuntimeError('Không sinh được PIN không trùng, hãy thu hồi bớt PIN cũ.')


def issue_door_pin(device, created_by, plain_pin: str, ttl_minutes: int,
                   label: str = '', max_uses: int = 1) -> DoorPinCode:
    pin = DoorPinCode(device=device, created_by=created_by, label=label,
                      expires_at=timezone.now() + timedelta(minutes=ttl_minutes), max_uses=max_uses)
    pin.set_pin(plain_pin)
    pin.save()
    AuditLog.objects.create(actor_user=created_by, device=device, action='DOOR_PIN_ISSUED',
                            metadata={'pin_id': str(pin.id), 'ttl_minutes': ttl_minutes, 'label': label})
    return pin


def issue_unique_door_pin(device, created_by, ttl_minutes: int, label: str = '', max_uses: int = 1,
                          digits: int = 6):
    with transaction.atomic():
        Device.objects.select_for_update().get(pk=device.pk)
        plain_pin = generate_unique_pin(device, digits=digits)
        pin = issue_door_pin(device=device, created_by=created_by, plain_pin=plain_pin,
                             ttl_minutes=ttl_minutes, label=label, max_uses=max_uses)
    return pin, plain_pin


def _euclidean_distance(a, b) -> float:
    if len(a) != len(b) or not a:
        return math.inf
    return math.sqrt(sum((x - y) ** 2 for x, y in zip(a, b)))


FACE_MAX_THRESHOLD = float(getattr(settings, 'FACE_MAX_THRESHOLD', 0.5))
FACE_MIN_MARGIN = float(getattr(settings, 'FACE_MIN_MARGIN', 0.04))


def verify_face(device, embedding: list, snapshot_url: str = '', ip_address=None, push: bool = True) -> AccessEvent:
    if in_lockout(device):
        return _log_event(device=device, method=AccessEvent.METHOD_FACE, success=False,
                          reason='DEVICE_LOCKED_OUT', snapshot_url=snapshot_url, ip_address=ip_address)

    best_profile, best_distance, second_distance = None, math.inf, math.inf
    for profile in FaceProfile.objects.filter(device=device, is_active=True, consent_confirmed=True):
        d = _euclidean_distance(embedding, profile.get_embedding())
        if d < best_distance:
            if best_profile is not None and best_profile.user_id != profile.user_id:
                second_distance = best_distance
            best_profile, best_distance = profile, d
        elif best_profile is not None and profile.user_id != best_profile.user_id and d < second_distance:
            second_distance = d

    limit = min(float(best_profile.threshold), FACE_MAX_THRESHOLD) if best_profile else 0.0
    if not best_profile or best_distance > limit:
        return _log_event(device=device, method=AccessEvent.METHOD_FACE, success=False,
                          reason='NO_MATCH', snapshot_url=snapshot_url, ip_address=ip_address)

    if second_distance - best_distance < FACE_MIN_MARGIN:
        return _log_event(device=device, method=AccessEvent.METHOD_FACE, success=False,
                          reason='AMBIGUOUS_MATCH', snapshot_url=snapshot_url, ip_address=ip_address)

    if not user_has_live_access(best_profile.user, device):
        return _log_event(device=device, method=AccessEvent.METHOD_FACE, success=False, reason='ACCESS_REVOKED',
                          user=best_profile.user, face_profile=best_profile, snapshot_url=snapshot_url,
                          ip_address=ip_address)

    confidence = max(0.0, 1 - (best_distance / limit))
    ok = _push_unlock(device, 'face', {'face_profile_id': str(best_profile.id)}, push)
    return _log_event(device=device, method=AccessEvent.METHOD_FACE, success=ok,
                      reason=None if ok else 'MQTT_PUBLISH_FAILED', user=best_profile.user,
                      face_profile=best_profile, confidence=round(confidence, 4),
                      snapshot_url=snapshot_url, ip_address=ip_address)


def register_face(device, user, embedding: list, name: str = '', consent_confirmed: bool = False,
                  request=None) -> FaceProfile:
    if not consent_confirmed:
        raise ValueError('Cần xác nhận đồng ý thu thập dữ liệu khuôn mặt.')
    probe = FaceProfile()
    probe.set_embedding(embedding)
    profile, _created = FaceProfile.objects.update_or_create(
        user=user, device=device,
        defaults={'name': name, 'consent_confirmed': consent_confirmed, 'is_active': True,
                  'embedding_encrypted': probe.embedding_encrypted},
    )
    meta = {'face_profile_id': str(profile.id)}
    if request is not None:
        audit(request, 'FACE_PROFILE_REGISTERED', device=device, target_user=user, metadata=meta)
    else:
        AuditLog.objects.create(actor_user=user, device=device, action='FACE_PROFILE_REGISTERED',
                                metadata=meta)
    return profile


FACE_DIM = 128
FACE_MIN_FRAMES = 3
FACE_MAX_FRAMES = 10
FACE_FRAME_SPREAD_MAX = 0.45


class FaceEnrollError(Exception):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code
        self.message = message


def enroll_face(device, user, vectors, name: str = '', request=None) -> FaceProfile:
    if not isinstance(vectors, list) or not (FACE_MIN_FRAMES <= len(vectors) <= FACE_MAX_FRAMES):
        raise FaceEnrollError('FRAME_COUNT', f'Cần {FACE_MIN_FRAMES}-{FACE_MAX_FRAMES} khung hình. Hãy quét lại.')
    clean = []
    for v in vectors:
        try:
            vec = [float(x) for x in v]
        except (TypeError, ValueError):
            raise FaceEnrollError('BAD_VECTOR', 'Dữ liệu quét không hợp lệ. Hãy quét lại.')
        if len(vec) != FACE_DIM or not all(math.isfinite(x) and abs(x) < 10 for x in vec):
            raise FaceEnrollError('BAD_VECTOR', 'Dữ liệu quét không hợp lệ. Hãy quét lại.')
        if max(vec) - min(vec) < 1e-3:
            raise FaceEnrollError('BAD_VECTOR', 'Không nhận diện được khuôn mặt rõ ràng. Hãy quét lại.')
        clean.append(vec)
    centroid = [sum(col) / len(clean) for col in zip(*clean)]
    worst = max(_euclidean_distance(v, centroid) for v in clean)
    if worst > FACE_FRAME_SPREAD_MAX:
        raise FaceEnrollError('INCONSISTENT', 'Các khung hình không khớp nhau (có thể có nhiều người trong khung hoặc '
                                              'khuôn mặt bị che/mờ). Hãy quét lại, chỉ một người nhìn thẳng camera.')
    return register_face(device=device, user=user, embedding=centroid, name=name,
                         consent_confirmed=True, request=request)


PHONE_CHANNELS = {
    'ble': {'label': b'ble-ticket-v1', 'permission': 'BLUETOOTH', 'flag': 'bluetooth_enabled',
            'method': AccessEvent.METHOD_BLE, 'prefix': 'BLE', 'name': 'Bluetooth'},
    'nfc': {'label': b'nfc-phone-ticket-v1', 'permission': 'NFC_PHONE', 'flag': 'nfc_enabled',
            'method': AccessEvent.METHOD_NFC_PHONE, 'prefix': 'NFC_PHONE', 'name': 'NFC'},
}
TICKET_TTL_SECONDS = int(getattr(settings, 'BLE_TICKET_TTL_SECONDS', 3600))
BLE_TICKET_TTL_SECONDS = TICKET_TTL_SECONDS


def _ticket_sig(device, kind: str, user_hex: str, exp: int) -> str:
    key = hmac.new(device.provisioning_secret_hash.encode(), PHONE_CHANNELS[kind]['label'],
                   hashlib.sha256).digest()
    msg = f'{device.device_code}|{user_hex}|{exp}'.encode()
    return hmac.new(key, msg, hashlib.sha256).hexdigest()[:32]


def issue_phone_ticket(device, user, kind: str, ttl: int = None):
    exp = int(time.time()) + (ttl or TICKET_TTL_SECONDS)
    user_hex = user.id.hex
    return f'{user_hex}.{exp}.{_ticket_sig(device, kind, user_hex, exp)}', exp


def parse_phone_ticket(device, ticket: str, kind: str):
    try:
        user_hex, exp_s, sig = (ticket or '').strip().split('.')
        exp = int(exp_s)
    except (ValueError, TypeError):
        return None
    try:
        sig_ok = hmac.compare_digest(sig.encode('utf-8'), _ticket_sig(device, kind, user_hex, exp).encode('utf-8'))
    except (TypeError, ValueError, UnicodeError):
        return None
    if not sig_ok:
        return None
    uid = parse_uuid(user_hex)
    user = User.objects.filter(pk=uid).first() if uid else None
    return (user, exp) if user else None


def issue_ble_ticket(device, user, ttl: int = TICKET_TTL_SECONDS):
    return issue_phone_ticket(device, user, 'ble', ttl)


def parse_ble_ticket(device, ticket: str):
    return parse_phone_ticket(device, ticket, 'ble')


def _record_phone_unlock(device, kind, ticket='', ok=True, reason=None, at=None) -> AccessEvent:
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


OFFLINE_AFTER_SECONDS = 180


def evaluate_device_status(device, status_log) -> int:
    return 0


def mark_offline_devices() -> int:
    cutoff = timezone.now() - timedelta(seconds=OFFLINE_AFTER_SECONDS)
    return Device.objects.filter(status='online', last_seen_at__lt=cutoff).update(status='offline')


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
            elif isinstance(resp.exception, dead):
                MobileSession.objects.filter(pk=session.pk).update(fcm_token='')
            else:
                logger.warning('push: gửi thất bại tới phiên %s: %s', session.pk, resp.exception)
        return sent
    except Exception:
        logger.exception('push: lỗi không mong đợi khi gửi push')
        return 0


def _push_in_thread(notification_id):
    try:
        send_notification_push(notification_id)
    finally:
        connections.close_all()


def _on_notification_saved(sender, instance, created, **kwargs):
    if not created:
        return
    nid = instance.pk
    if EMAIL_ASYNC:
        transaction.on_commit(lambda: threading.Thread(
            target=_push_in_thread, args=(nid,), name='fcm-push', daemon=True).start())
    else:
        transaction.on_commit(lambda: send_notification_push(nid))


def register_signals():
    post_save.connect(_on_notification_saved, sender=Notification, dispatch_uid='push_on_notification')

ONLINE_WINDOW_SECONDS = 120
CLAIM_MAX_FAILS = 5
CLAIM_FAIL_WINDOW_SECONDS = 600


class ClaimError(Exception):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code
        self.message = message


def touch_device(device, *, firmware=None, battery=None) -> None:
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
    return dispatch_command(device, 'PING', source='admin', issued_by=issued_by, ttl=15)


def claim_device(device_id, new_owner, *, by_admin: bool) -> Device:
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
    since = timezone.now() - timedelta(seconds=CLAIM_FAIL_WINDOW_SECONDS)
    fails = AuditLog.objects.filter(actor_user=user, action='DEVICE_CLAIM_FAILED',
                                    created_at__gte=since).count()
    if fails >= CLAIM_MAX_FAILS:
        raise ClaimError('RATE_LIMITED', 'Bạn đã thử sai quá nhiều lần. Vui lòng thử lại sau ít phút.')
    code = (device_code or '').strip().upper()
    device = Device.objects.filter(device_code=code).first()
    ok = bool(device and secret and safe_eq(device.provisioning_secret_hash, hash_token(secret)))
    if not ok:
        raise ClaimError('BAD_CREDENTIALS', 'Mã thiết bị hoặc secret không đúng.')
    return claim_device(device.pk, user, by_admin=False)


def release_device(device_id):
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
            'share_codes': 0,
            'commands': DeviceCommand.objects.filter(device=device, status__in=('pending', 'sent'))
                        .update(status='expired'),
        }
        device.factory_reset()
        return device, previous, counts


def rotate_secret(device_id) -> tuple:
    with transaction.atomic():
        device = Device.objects.select_for_update().get(pk=device_id)
        secret = secrets.token_hex(16)
        device.provisioning_secret_hash = hash_token(secret)
        device.save(update_fields=['provisioning_secret_hash', 'updated_at'])
        return device, secret


def visible_logs(user):
    return AuditLog.objects.filter(Q(actor_user=user) | Q(target_user=user) | Q(device__owner=user))


def revoke_mobile_sessions(user) -> int:
    from .models import MobileSession
    return MobileSession.objects.filter(user=user, revoked_at__isnull=True).update(
        revoked_at=timezone.now(), fcm_token='')


COMMAND_TTL_SECONDS = 120
COMMAND_TTL_BY_TYPE = {'UNLOCK': 30}


def command_ttl(command: str) -> int:
    return COMMAND_TTL_BY_TYPE.get(command, COMMAND_TTL_SECONDS)
ALLOWED_COMMANDS = {'LOCK': 'LOCK', 'UNLOCK': 'UNLOCK', 'REBOOT': None}
COMMAND_LABELS = {'LOCK': 'Khóa', 'UNLOCK': 'Mở khóa', 'REBOOT': 'Khởi động lại'}

EVENTS_MAX_BACKLOG_SECONDS = 300
EVENTS_BATCH = 10

RESET_NEUTRAL_MSG = ('Nếu email này đã đăng ký, chúng tôi đã gửi link đặt lại mật khẩu. '
                     'Vui lòng kiểm tra hộp thư (kể cả mục Spam).')


EMAIL_CODE_TTL_MIN = 10
EMAIL_CODE_COOLDOWN = 60
EMAIL_CODE_MAX_ATTEMPTS = 5
WEBAUTHN_TTL = 5 * 60
TOTP_ISSUER = 'Smart Lock'


def pepper_hash(user, value: str) -> str:
    msg = f'{user.pk}:{value}'.encode()
    return hmac.new(settings.SECRET_KEY.encode(), msg, hashlib.sha256).hexdigest()


def digits(value) -> str:
    return re.sub(r'\D', '', value or '')


def get_cfg(user) -> TwoFactorConfig:
    return TwoFactorConfig.objects.get_or_create(user=user)[0]


def verify_totp(cfg: TwoFactorConfig, code: str) -> bool:
    code = digits(code)
    secret = cfg.get_totp_secret()
    if len(code) != 6 or not secret:
        return False
    totp = pyotp.TOTP(secret)
    step_now = int(timezone.now().timestamp() // totp.interval)
    with transaction.atomic():
        locked = TwoFactorConfig.objects.select_for_update().get(pk=cfg.pk)
        for offset in (-1, 0, 1):
            step = step_now + offset
            if step <= locked.totp_last_step:
                continue
            if hmac.compare_digest(totp.at(step * totp.interval), code):
                locked.totp_last_step = step
                locked.save(update_fields=['totp_last_step', 'updated_at'])
                return True
    return False


def send_email_code(user, purpose):
    now = timezone.now()
    purposes = ('TF_SETUP', 'TF_VERIFY')
    code = f'{secrets.randbelow(10 ** 6):06d}'
    with transaction.atomic():
        User.objects.select_for_update().get(pk=user.pk)
        if OneTimeCode.objects.filter(user=user, purpose__in=purposes,
                                      created_at__gt=now - timedelta(seconds=EMAIL_CODE_COOLDOWN)).exists():
            return 'cooldown'
        OneTimeCode.objects.filter(user=user, purpose__in=purposes, is_used=False).update(is_used=True, used_at=now)
        rec = OneTimeCode.objects.create(
            user=user, purpose='TF_' + purpose, token_hash=pepper_hash(user, 'em:' + code),
            expires_at=now + timedelta(minutes=EMAIL_CODE_TTL_MIN),
        )
    subject, html, plain = render_email('two_factor_code', {
        'full_name': user.full_name or user.username,
        'otp_code': code,
        'expiry_minutes': EMAIL_CODE_TTL_MIN,
    })
    if send_mail(subject, plain, html, user.email, log_body=False):
        return 'sent'
    OneTimeCode.objects.filter(pk=rec.pk).delete()
    return 'failed'


def verify_email_code(user, code, purpose) -> bool:
    code = digits(code)
    if len(code) != 6:
        return False
    with transaction.atomic():
        rec = OneTimeCode.objects.select_for_update().filter(
            user=user, purpose='TF_' + purpose, is_used=False, expires_at__gt=timezone.now(),
        ).order_by('-created_at').first()
        if not rec:
            return False
        rec.attempts += 1
        if rec.attempts > EMAIL_CODE_MAX_ATTEMPTS:
            rec.is_used = True
            rec.save(update_fields=['attempts', 'is_used'])
            return False
        ok = hmac.compare_digest(rec.token_hash, pepper_hash(user, 'em:' + code))
        if ok:
            rec.is_used = True
        rec.save(update_fields=['attempts', 'is_used'])
        return ok


def lock_minutes(user) -> int:
    locked_until = User.objects.filter(pk=user.pk).values_list('login_locked_until', flat=True).first()
    now = timezone.now()
    if locked_until and locked_until > now:
        return math.ceil((locked_until - now).total_seconds() / 60)
    return 0


def webauthn_rp(request):
    return links.WEBAUTHN_RP_ID, links.WEBAUTHN_ORIGIN, getattr(settings, 'WEBAUTHN_RP_NAME', TOTP_ISSUER)
