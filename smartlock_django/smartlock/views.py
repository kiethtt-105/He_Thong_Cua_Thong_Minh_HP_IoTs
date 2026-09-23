# smartlock/views.py
import base64
import hashlib
import hmac
import io
import ipaddress
import json
import logging
import math
import re
import secrets
import uuid
from datetime import datetime, timedelta
from urllib.parse import urlencode

import pyotp
import qrcode
import qrcode.image.svg
from django.conf import settings as dj_settings
from django.contrib import messages
from django.contrib.auth import authenticate, login, logout, update_session_auth_hash
from django.contrib.auth.decorators import login_required
from django.contrib.auth.password_validation import validate_password
from django.contrib.auth.tokens import default_token_generator
from django.core.exceptions import ValidationError
from django.core.mail import send_mail
from django.core.paginator import Paginator
from django.db import IntegrityError, transaction
from django.db.models import Count, Q
from django.db.models.functions import TruncDate
from django.http import HttpResponse, JsonResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.urls import reverse
from django.utils import timezone
from django.utils.encoding import force_bytes, force_str
from django.utils.http import (
    url_has_allowed_host_and_scheme, urlsafe_base64_decode, urlsafe_base64_encode,
)
from django.views.decorators.http import require_http_methods, require_POST
from django.views.decorators.csrf import csrf_exempt
from webauthn import (
    generate_authentication_options,
    generate_registration_options,
    options_to_json,
    verify_authentication_response,
    verify_registration_response,
)
from webauthn.helpers import base64url_to_bytes, bytes_to_base64url
from webauthn.helpers.structs import (
    AuthenticatorSelectionCriteria,
    PublicKeyCredentialDescriptor,
    ResidentKeyRequirement,
    UserVerificationRequirement,
)

from .utils import SmartlockUtils
from .email_templates import render_email
from .models import (
    AccessCard, Announcement, AuditLog, CardDeviceAccess, Device, DeviceAccess,
    DeviceCommand, DeviceStatusLog, EmailVerificationToken, Fido2Credential, LoginAttemptLog,
    LoginLockout, NfcLog, NfcReader, NfcReaderConfig, Notification, Permission,
    ShareAccessCode, SupportRequest, SystemSettings, TwoFactorBackupCode, TwoFactorConfig,
    TwoFactorEmailCode, User, fernet, sync_two_fa_flag,
)
from .mqtt_client import publish_command, MqttPublishError

logger = logging.getLogger('smartlock.views')

# ====================== CONSTANTS ======================
# From lấy từ settings.DEFAULT_FROM_EMAIL 
MAX_FAILED_ATTEMPTS = SmartlockUtils.MAX_FAILED_ATTEMPTS
COMMAND_TTL_SECONDS = SmartlockUtils.COMMAND_TTL_SECONDS
SHARED_ACCESS_HOURS = SmartlockUtils.SHARED_ACCESS_HOURS
SUPPORT_TTL_HOURS = SmartlockUtils.SUPPORT_TTL_HOURS
PAGE_SIZE = SmartlockUtils.PAGE_SIZE
ALLOWED_COMMANDS = SmartlockUtils.ALLOWED_COMMANDS
RECOVERY_ACTIONS = SmartlockUtils.RECOVERY_ACTIONS

# ====================== AUTH REQUIRED DECORATOR (đưa lên đầu) ======================
auth_required = login_required(login_url='smartlock:login')

# ====================== HELPERS ======================
def _send_mail(subject, plain, html, to, log_body=True):
    # log_body=False: không ghi nội dung mail vào log (dùng cho mail chứa mã OTP)
    logger.info("send_mail: to=%s subject=%r plain_preview=%r", to, subject,
                plain[:200] if log_body else '<ẩn nội dung>')
    try:
        n = send_mail(subject, plain, None, [to], html_message=html)
        logger.info("send_mail: OK (%s mail) -> %s", n, to)
        return True
    except Exception:
        logger.exception("send_mail: THẤT BẠI -> %s", to)
        return False

def _hash_token(token) -> str:
    return hashlib.sha256(str(token).encode()).hexdigest()

def _valid_ip(value):
    try:
        return str(ipaddress.ip_address((value or '').strip()))
    except ValueError:
        return None

def _client_ip(request):
    """Chỉ tin X-Forwarded-For khi settings.TRUST_PROXY_HEADERS = True (đứng sau nginx/proxy).
    Luôn trả về IP hợp lệ để không làm hỏng ghi log / GenericIPAddressField."""
    ip = None
    if getattr(dj_settings, 'TRUST_PROXY_HEADERS', False):
        ip = _valid_ip((request.META.get('HTTP_X_FORWARDED_FOR') or '').split(',')[0])
    return ip or _valid_ip(request.META.get('REMOTE_ADDR')) or '0.0.0.0'

def _user_agent(request):
    return (request.META.get('HTTP_USER_AGENT') or '')[:500]

def _settings():
    return SystemSettings.objects.get_or_create(pk=1)[0]

def _is_admin(user):
    return bool(user.is_staff or user.is_superuser or user.is_admin)

def _parse_uuid(value):
    try:
        return uuid.UUID(str(value))
    except (ValueError, AttributeError, TypeError):
        return None

def _parse_dt(value):
    if not value:
        return None
    try:
        return timezone.make_aware(datetime.strptime(value, '%Y-%m-%dT%H:%M'))
    except ValueError:
        return None

def _find_user(identifier):
    identifier = (identifier or '').strip()
    if not identifier:
        return None
    return User.objects.filter(Q(email__iexact=identifier) | Q(username__iexact=identifier)).first()

def _audit(request, action, *, device=None, target_user=None, success=True,
           severity='info', metadata=None, actor='auto', username_attempt=None):
    if actor == 'auto':
        actor = request.user if request.user.is_authenticated else None
    try:
        with transaction.atomic():  # savepoint: lỗi ghi log không làm hỏng transaction bên ngoài
            AuditLog.objects.create(
                actor_user=actor, target_user=target_user, device=device, action=action[:50],
                username_attempt=username_attempt, severity=severity, success=success,
                ip_address=_client_ip(request), user_agent=_user_agent(request), metadata=metadata,
            )
    except Exception:
        logger.exception("audit: không ghi được log %s", action)

def _notify(user, title, message, severity='info', device=None, type_='SYSTEM'):
    Notification.objects.create(
        user=user, device=device, type=type_, title=title[:150], message=message, severity=severity,
    )

def _visible_logs(user):
    """Log user được phép xem: mình làm, mình là đối tượng (bị admin/người khác tác động,
    bị đăng nhập sai...), hoặc xảy ra trên thiết bị của mình."""
    return AuditLog.objects.filter(
        Q(actor_user=user) | Q(target_user=user) | Q(device__owner=user)
    )

def _ip_blacklisted(ip):
    lines = [l.strip() for l in (_settings().ip_blacklist or '').splitlines()]
    return ip in [l for l in lines if l]

def _accessible_devices(user):
    now = timezone.now()
    shared_ids = (
        DeviceAccess.objects.filter(user=user, is_active=True, accepted=True, valid_from__lte=now)
        .filter(Q(expires_at__isnull=True) | Q(expires_at__gt=now))
        .values('device_id')
    )
    return Device.objects.filter(Q(owner=user) | Q(id__in=shared_ids))

def _has_permission(user, device, code):
    if device.owner_id == user.id:
        return True
    now = timezone.now()
    return (
        DeviceAccess.objects.filter(
            device=device, user=user, is_active=True, accepted=True,
            valid_from__lte=now, permissions__code=code,
        ).filter(Q(expires_at__isnull=True) | Q(expires_at__gt=now)).exists()
    )

def _pick_device(queryset, raw_id, strict=False):
    """strict=True (dùng cho POST): id gửi lên phải khớp đúng thiết bị,
    không được âm thầm rơi về thiết bị đầu tiên (thao tác nhầm thiết bị)."""
    dev_id = _parse_uuid(raw_id)
    if strict:
        return queryset.filter(id=dev_id).first() if dev_id else None
    device = queryset.filter(id=dev_id).first() if dev_id else None
    return device or queryset.first()

def _default_permissions():
    # Ưu tiên danh sách khai báo trong utils; không có thì suy ra từ ALLOWED_COMMANDS.
    preset = getattr(SmartlockUtils, 'DEFAULT_PERMISSIONS', None)
    if preset:
        return preset
    codes = sorted({c for c in ALLOWED_COMMANDS.values() if c})
    return [(c, c.replace('_', ' ').title(), None, False) for c in codes]

def _ensure_default_permissions():
    existing = set(Permission.objects.values_list('code', flat=True))
    for code, name, desc, sensitive in _default_permissions():
        if code not in existing:
            Permission.objects.get_or_create(
                code=code, defaults={'name': name, 'description': desc, 'is_sensitive': sensitive},
            )

def _unique_share_plain():
    """Mã 6 số không trùng với mã đang còn hạn nào khác (tránh cấp nhầm thiết bị)."""
    for _ in range(20):
        plain = f'{secrets.randbelow(10 ** 6):06d}'
        if not ShareAccessCode.is_code_taken(plain):
            return plain
    return None

def _clean_ip_lines(text):
    good, bad = [], []
    for line in (text or '').splitlines():
        line = line.strip()
        if not line:
            continue
        ip = _valid_ip(line)
        (good if ip else bad).append(ip or line)
    return good, bad

def _redirect_with(url_name, **params):
    url = reverse(url_name)
    if params:
        url += '?' + '&'.join(f'{k}={v}' for k, v in params.items())
    return redirect(url)

def _register_failure(user, ip):
    """Ghi 1 lần đăng nhập sai. Trả về số phút bị khóa nếu vừa kích hoạt khóa, ngược lại None."""
    st = _settings()
    stages = st.login_lockout_stage_minutes or [5, 10, 30]
    now = timezone.now()
    locked_minutes = None
    with transaction.atomic():
        lock, _ = LoginLockout.objects.select_for_update().get_or_create(user=user)
        lock.failed_attempts += 1
        lock.last_failed_at = now
        lock.last_failed_ip = ip
        if lock.failed_attempts >= MAX_FAILED_ATTEMPTS:
            locked_minutes = stages[min(lock.stage, len(stages) - 1)]
            lock.locked_until = now + timedelta(minutes=locked_minutes)
            lock.stage += 1
            lock.failed_attempts = 0
        lock.save()
    if locked_minutes:
        _notify(user, 'Tài khoản bị khóa tạm thời',
                f'Đăng nhập sai nhiều lần từ IP {ip}. Tài khoản bị khóa {locked_minutes} phút.',
                severity='critical', type_='LOGIN_LOCKOUT')
    return locked_minutes

def _reset_lockout(user):
    LoginLockout.objects.filter(user=user).update(
        failed_attempts=0, stage=0, locked_until=None,
    )

def _ensure_sync_key(request):
    """Cấp (mỗi lần login mới) một khoá ngẫu nhiên gắn với session hiện tại. Client dùng khoá
    này để suy ra (HKDF) AES key mã hoá cache dashboard lưu trong IndexedDB của trình duyệt.
    Vì khoá đổi mỗi khi có session mới và bị xoá khi logout (Django logout() flush session),
    cache cũ mã hoá bằng khoá cũ vĩnh viễn không đọc được nữa dù còn sót lại trong IndexedDB."""
    request.session['sync_key'] = secrets.token_urlsafe(32)

def _send_verification(request, user):
    st = _settings()
    minutes = st.verification_token_expiry_minutes
    EmailVerificationToken.objects.filter(
        user=user, purpose='EMAIL_VERIFY', is_used=False,
    ).update(is_used=True, used_at=timezone.now())

    token = uuid.uuid4()
    EmailVerificationToken.objects.create(
        user=user, purpose='EMAIL_VERIFY', token_hash=_hash_token(token),
        expires_at=timezone.now() + timedelta(minutes=minutes),
    )
    link = request.build_absolute_uri(reverse('smartlock:verify_email', args=[token]))
    context = {
        'full_name': user.full_name or user.username,
        'username': user.username,
        'verification_link': link,
        'expiry_minutes': minutes,
    }
    subject, html, plain = render_email('user_verification.html', context)
    return _send_mail(subject, plain, html, user.email)

def _page(request, queryset):
    return Paginator(queryset, PAGE_SIZE).get_page(request.GET.get('page'))

# ====================== AUTH ======================
def login_view(request):
    if request.user.is_authenticated:
        return redirect('smartlock:dashboard')

    next_url = request.POST.get('next') or request.GET.get('next') or ''
    ctx = {'next': next_url}

    if request.method != 'POST':
        return render(request, 'account/base/login.html', ctx)

    identifier = (request.POST.get('identifier') or '').strip()
    password = request.POST.get('password') or ''

    if not identifier or not password:
        messages.error(request, 'Vui lòng điền đầy đủ thông tin.')
        return render(request, 'account/base/login.html', ctx)

    ip = _client_ip(request)
    if _ip_blacklisted(ip):
        _audit(request, 'LOGIN_BLOCKED_IP', success=False, severity='warning',
               username_attempt=identifier[:150])
        messages.error(request, 'Địa chỉ IP của bạn đã bị chặn.')
        return render(request, 'account/base/login.html', ctx)

    user = _find_user(identifier)
    now = timezone.now()

    if user:
        lock = LoginLockout.objects.filter(user=user).first()
        if lock and lock.locked_until and lock.locked_until > now:
            remaining = math.ceil((lock.locked_until - now).total_seconds() / 60)
            messages.error(request, f'Tài khoản đang bị khóa tạm thời. Thử lại sau {remaining} phút.')
            _audit(request, 'LOGIN_LOCKED', success=False, severity='warning',
                   actor=None, target_user=user, username_attempt=identifier[:150])
            return render(request, 'account/base/login.html', ctx)

    auth_user = authenticate(request, username=user.email, password=password) if user else None

    # Tài khoản quản trị chỉ được đăng nhập ở cổng quản trị riêng (app manage_sys).
    if auth_user and _is_admin(auth_user):
        LoginAttemptLog.objects.create(
            identifier=identifier[:255], user=user, ip_address=ip,
            user_agent=_user_agent(request), success=False,
        )
        _audit(request, 'LOGIN_ADMIN_REJECTED', success=False, severity='warning',
               actor=None, target_user=user, username_attempt=identifier[:150])
        messages.error(request, 'Email/Username hoặc mật khẩu không đúng.')
        return render(request, 'account/base/login.html', ctx)

    LoginAttemptLog.objects.create(
        identifier=identifier[:255], user=user, ip_address=ip,
        user_agent=_user_agent(request), success=bool(auth_user),
    )

    if auth_user:
        # ---- 2FA: mật khẩu đúng nhưng chưa đăng nhập, chuyển sang bước xác thực 2 lớp ----
        # Chưa reset lockout ở đây (chỉ reset sau khi qua bước 2) để không thể
        # "đăng nhập lại bằng mật khẩu" nhằm xóa bộ đếm rồi dò tiếp mã 2FA.
        if auth_user.two_fa_enabled:
            request.session.cycle_key()
            _start_pending(request, auth_user, 'login',
                           backend=getattr(auth_user, 'backend', ''), next_url=next_url)
            _audit(request, 'LOGIN_2FA_REQUIRED', actor=None, target_user=auth_user)
            return redirect('smartlock:tf-verify')

        _reset_lockout(auth_user)
        login(request, auth_user)
        _ensure_sync_key(request)
        request.session.set_expiry(_settings().session_timeout_hours * 3600)
        _audit(request, 'LOGIN', actor=auth_user)
        messages.success(request, 'Đăng nhập thành công!')

        if next_url and url_has_allowed_host_and_scheme(next_url, {request.get_host()}):
            return redirect(next_url)

        return redirect('smartlock:dashboard')

    if user and not user.is_active and user.check_password(password):
        messages.warning(request, 'Tài khoản chưa được kích hoạt. Vui lòng xác thực email.')
    else:
        if user:
            locked = _register_failure(user, ip)
            if locked:
                _audit(request, 'ACCOUNT_LOCKED', success=False, severity='critical', actor=None,
                       target_user=user, username_attempt=identifier[:150],
                       metadata={'locked_minutes': locked})
        messages.error(request, 'Email/Username hoặc mật khẩu không đúng.')
    _audit(request, 'LOGIN_FAILED', success=False, severity='warning', actor=None,
           target_user=user, username_attempt=identifier[:150])
    return render(request, 'account/base/login.html', ctx)


def logout_view(request):
    if request.user.is_authenticated:
        _audit(request, 'LOGOUT')
    logout(request)
    messages.success(request, 'Đã đăng xuất.')
    return redirect('smartlock:login')


def register(request):
    if request.user.is_authenticated:
        return redirect('smartlock:dashboard')

    if not _settings().registration_enabled:
        return render(request, 'account/base/register.html', {'disabled': True})

    if request.method != 'POST':
        return render(request, 'account/base/register.html')

    email = (request.POST.get('email') or '').strip()
    username = (request.POST.get('username') or '').strip()
    full_name = (request.POST.get('full_name') or '').strip()
    password1 = request.POST.get('password1') or ''
    password2 = request.POST.get('password2') or ''
    ctx = {'form': {'email': email, 'username': username, 'full_name': full_name}}

    if '@' in username:
        messages.error(request, 'Tên đăng nhập không được chứa ký tự @.')
        return render(request, 'account/base/register.html', ctx)
    if password1 != password2:
        messages.error(request, 'Mật khẩu không khớp.')
        return render(request, 'account/base/register.html', ctx)
    try:
        validate_password(password1)
    except ValidationError as e:
        messages.error(request, ' '.join(e.messages))
        return render(request, 'account/base/register.html', ctx)

    try:
        with transaction.atomic():
            user = User.objects.create_user(
                email=email, username=username, password=password1,
                full_name=full_name or None,
            )
    except ValidationError as e:
        _audit(request, 'REGISTER_FAILED', actor=None, success=False, username_attempt=email[:150],
               metadata={'reason': 'validation'})
        messages.error(request, 'Không thể tạo tài khoản: ' + ' '.join(e.messages))
        return render(request, 'account/base/register.html', ctx)
    except IntegrityError:
        _audit(request, 'REGISTER_FAILED', actor=None, success=False, username_attempt=email[:150],
               metadata={'reason': 'duplicate'})
        messages.error(request, 'Email hoặc tên đăng nhập đã được sử dụng.')
        return render(request, 'account/base/register.html', ctx)
    except ValueError as e:
        _audit(request, 'REGISTER_FAILED', actor=None, success=False, username_attempt=email[:150],
               metadata={'reason': 'invalid'})
        messages.error(request, f'Không thể tạo tài khoản: {e}')
        return render(request, 'account/base/register.html', ctx)

    logger.info("register: tạo user %s", email)
    _audit(request, 'REGISTER', actor=user, target_user=user)
    if not _send_verification(request, user):
        _audit(request, 'VERIFY_MAIL_FAILED', actor=user, target_user=user, success=False,
               severity='warning')
        messages.warning(request, 'Chưa gửi được email xác thực. Vui lòng bấm "Gửi lại" sau ít phút.')
    return render(request, 'account/base/verify_email.html', {'email': email})


def verify_email(request, token):
    try:
        vt = EmailVerificationToken.objects.select_related('user').get(
            token_hash=_hash_token(token), purpose='EMAIL_VERIFY',
            is_used=False, expires_at__gt=timezone.now(),
        )
    except EmailVerificationToken.DoesNotExist:
        _audit(request, 'EMAIL_VERIFY_FAILED', actor=None, success=False, severity='warning')
        messages.error(request, 'Link xác thực không hợp lệ hoặc đã hết hạn.')
        return redirect('smartlock:login')

    user = vt.user
    user.email_verified = True
    user.is_active = True
    user.save()
    vt.is_used = True
    vt.used_at = timezone.now()
    vt.save()

    _audit(request, 'EMAIL_VERIFIED', actor=user, target_user=user)
    _notify(user, 'Chào mừng đến Smart Lock', 'Tài khoản của bạn đã được kích hoạt.', type_='WELCOME')
    messages.success(request, 'Tài khoản đã được kích hoạt thành công!')
    return redirect('smartlock:login')


@require_POST
def resend_verification(request):
    email = (request.POST.get('email') or '').strip()
    user = User.objects.filter(email__iexact=email, is_active=False, email_verified=False).first()
    if user:
        recent = EmailVerificationToken.objects.filter(
            user=user, purpose='EMAIL_VERIFY',
            created_at__gt=timezone.now() - timedelta(seconds=60),
        ).exists()
        if recent:
            messages.warning(request, 'Vui lòng đợi 60 giây trước khi gửi lại.')
        else:
            sent = _send_verification(request, user)
            _audit(request, 'VERIFY_MAIL_RESENT', actor=None, target_user=user, success=sent)
            if sent:
                messages.success(request, 'Đã gửi lại email xác thực.')
            else:
                messages.error(request, 'Không gửi được email. Vui lòng thử lại sau.')
    else:
        messages.success(request, 'Nếu tài khoản cần xác thực, email đã được gửi lại.')
    return render(request, 'account/base/verify_email.html', {'email': email})


def password_reset_request(request):
    if request.method == 'POST':
        email = (request.POST.get('email') or '').strip()
        user = User.objects.filter(email__iexact=email, is_active=True).first()
        if not user:
            _audit(request, 'PASSWORD_RESET_UNKNOWN_EMAIL', actor=None, success=False,
                   severity='warning', username_attempt=email[:150])
        elif AuditLog.objects.filter(action='PASSWORD_RESET_REQUEST', target_user=user,
                                     created_at__gte=timezone.now() - timedelta(seconds=60)).exists():
            _audit(request, 'PASSWORD_RESET_THROTTLED', actor=None, success=False, target_user=user)
        else:
            reset_link = request.build_absolute_uri(
                reverse('smartlock:reset_password_confirm', args=[
                    force_str(urlsafe_base64_encode(force_bytes(str(user.pk)))),
                    default_token_generator.make_token(user),
                ])
            )
            context = {
                'full_name': user.full_name or user.username,
                'password_reset_link': reset_link,
                'reset_link': reset_link,
                'expiry_minutes': dj_settings.PASSWORD_RESET_TIMEOUT // 60,
            }
            subject, html, plain = render_email('password_reset.html', context)
            sent = _send_mail(subject, plain, html, user.email)
            _audit(request, 'PASSWORD_RESET_REQUEST', actor=None, target_user=user, success=sent,
                   severity='info' if sent else 'warning',
                   metadata=None if sent else {'error': 'send_mail_failed'})
        messages.success(request, 'Nếu email tồn tại, link đặt lại mật khẩu đã được gửi.')
    return render(request, 'account/base/reset_password.html', {'mode': 'request'})


def reset_password(request, uidb64, token):
    try:
        user = User.objects.get(pk=force_str(urlsafe_base64_decode(uidb64)))
    except Exception:
        user = None

    if user is None or not user.is_active or not default_token_generator.check_token(user, token):
        _audit(request, 'PASSWORD_RESET_INVALID', actor=None, success=False, severity='warning',
               target_user=user)
        messages.error(request, 'Yêu cầu không hợp lệ')
        return render(request, 'account/base/reset_password.html', {'mode': 'expired'})

    ctx = {'mode': 'confirm'}
    if request.method == 'POST':
        p1 = request.POST.get('new_password1') or ''
        p2 = request.POST.get('new_password2') or ''
        if not p1 or p1 != p2:
            messages.error(request, 'Mật khẩu không khớp.')
            return render(request, 'account/base/reset_password.html', ctx)
        try:
            validate_password(p1, user)
        except ValidationError as e:
            messages.error(request, ' '.join(e.messages))
            return render(request, 'account/base/reset_password.html', ctx)
        user.set_password(p1)
        user.save()
        _reset_lockout(user)
        _audit(request, 'PASSWORD_RESET_DONE', actor=user, target_user=user)
        _notify(user, 'Mật khẩu đã thay đổi', 'Mật khẩu tài khoản vừa được đặt lại.',
                severity='warning', type_='SECURITY')
        messages.success(request, 'Mật khẩu đã được thay đổi thành công!')
        return redirect('smartlock:login')
    return render(request, 'account/base/reset_password.html', ctx)


# ====================== DASHBOARD ======================
@auth_required
def dashboard(request):
    user = request.user
    devices = _accessible_devices(user).order_by('name')
    current = _pick_device(devices, request.GET.get('device'))
    now = timezone.now()

    share_code, share_progress = None, 0
    if current:
        last_log = DeviceStatusLog.objects.filter(device=current).order_by('-recorded_at').first()
        current.lock_state = last_log.lock_state if last_log else 'unknown'
        if current.owner_id == user.id:
            share_code = (ShareAccessCode.objects
                          .filter(device=current, expires_at__gt=now).order_by('-created_at').first())
            if share_code:
                total = (share_code.expires_at - share_code.created_at).total_seconds() or 1
                left = (share_code.expires_at - now).total_seconds()
                share_progress = max(0, min(100, int(left / total * 100)))

    today = timezone.localdate()
    days = [today - timedelta(days=i) for i in range(6, -1, -1)]
    counts = {
        r['d']: r['c'] for r in
        _visible_logs(user).filter(created_at__date__gte=days[0])
        .annotate(d=TruncDate('created_at')).values('d').annotate(c=Count('id'))
    }
    chart_data = {'labels': [d.strftime('%d/%m') for d in days],
                  'values': [counts.get(d, 0) for d in days]}

    context = {
        'devices': devices,
        'current_device': current,
        'total_devices': devices.count(),
        'online_devices': devices.filter(status='online').count(),
        'unapproved_cards': AccessCard.objects.filter(user=user, is_active=False).count(),
        'unread_count': Notification.objects.filter(user=user, is_read=False).count(),
        'active_share_code': share_code,
        'share_progress': share_progress,
        'recent_notifications': Notification.objects.filter(user=user).order_by('-created_at')[:4],
        'recent_logs': _visible_logs(user).select_related('device').order_by('-created_at')[:6],
        'announcements': Announcement.objects.filter(is_active=True).order_by('-created_at')[:3],
        'chart_data': chart_data,
    }
    return render(request, 'account/base/dashboard.html', context)


# ====================== SYNC: bootstrap toàn bộ dữ liệu dashboard cho client cache ======================
@auth_required
def sync_bootstrap(request):
    """Trả JSON gộp mọi thứ user thấy trên dashboard - client mã hoá (AES-GCM, khoá suy ra từ
    session hiện tại, xem _ensure_sync_key) rồi lưu vào IndexedDB để tải nhanh + auto refresh
    nền. KHÔNG cấp thêm quyền xem dữ liệu nào ngoài những gì các view khác đã cho phép."""
    user = request.user
    devices = list(_accessible_devices(user).order_by('name'))
    device_ids = [d.id for d in devices]

    # Lấy log trạng thái mới nhất mỗi thiết bị mà không phụ thuộc tính năng riêng của DB
    # (DISTINCT ON chỉ có ở Postgres): quét 500 log gần nhất toàn bộ rồi giữ bản đầu tiên
    # gặp cho mỗi device - đủ dùng ở quy mô thiết bị cá nhân/hộ gia đình của app này.
    last_logs = {}
    for log in DeviceStatusLog.objects.filter(device_id__in=device_ids).order_by('-recorded_at')[:500]:
        last_logs.setdefault(log.device_id, log)

    devices_json = [{
        'id': str(d.id), 'name': d.name, 'device_code': d.device_code,
        'status': d.status, 'status_display': d.get_status_display(),
        'battery_level': d.battery_level,
        'lock_state': (last_logs[d.id].lock_state if d.id in last_logs else 'unknown'),
        'location': d.location or '', 'is_owner': d.owner_id == user.id,
        'updated_at': d.updated_at.isoformat(),
    } for d in devices]

    notifications_json = [{
        'id': str(n.id), 'title': n.title, 'message': n.message, 'severity': n.severity,
        'is_read': n.is_read, 'created_at': n.created_at.isoformat(),
        'device_id': str(n.device_id) if n.device_id else None,
    } for n in Notification.objects.filter(user=user).order_by('-created_at')[:20]]

    logs_json = [{
        'id': str(l.id), 'action': l.action, 'device': l.device.name if l.device_id else None,
        'success': l.success, 'severity': l.severity, 'created_at': l.created_at.isoformat(),
    } for l in _visible_logs(user).select_related('device').order_by('-created_at')[:20]]

    owned_ids = {d.id for d in devices if d.owner_id == user.id}
    accesses_json = [{
        'id': str(a.id), 'device_id': str(a.device_id), 'user': a.user.username,
        'permissions': [p.code for p in a.permissions.all()],
        'expires_at': a.expires_at.isoformat() if a.expires_at else None,
    } for a in (DeviceAccess.objects.filter(device_id__in=owned_ids, is_active=True)
                .select_related('user').prefetch_related('permissions'))] if owned_ids else []

    data = {
        'generated_at': timezone.now().isoformat(),
        'unread_count': Notification.objects.filter(user=user, is_read=False).count(),
        'devices': devices_json,
        'notifications': notifications_json,
        'recent_logs': logs_json,
        'accesses': accesses_json,
    }
    response = JsonResponse(data)
    response['Cache-Control'] = 'no-store'  # dữ liệu nhạy cảm, không cho trình duyệt/proxy cache thô ngoài IndexedDB đã mã hoá
    return response


# ====================== DEVICES ======================
@auth_required
def device_add(request):
    if request.method == 'POST':
        name = (request.POST.get('name') or '').strip()[:100]
        if not name:
            messages.error(request, 'Tên thiết bị không được để trống.')
            return redirect('smartlock:devices-list')

        device_code = f'DEV-{secrets.token_hex(4).upper()}'
        while Device.objects.filter(device_code=device_code).exists():
            device_code = f'DEV-{secrets.token_hex(4).upper()}'

        # Secret chỉ hiện 1 lần cho người dùng, DB chỉ lưu hash.
        provisioning_secret = secrets.token_hex(16)
        device = Device.objects.create(
            name=name,
            device_code=device_code,
            provisioning_secret_hash=_hash_token(provisioning_secret),
            # constraint chk_devices_owner_vs_status: 'provisioning' bắt buộc owner=NULL,
            # còn ở đây đã gán owner nên phải dùng trạng thái khác.
            status='offline',
            owner=request.user,
            bluetooth_enabled=True,
            wifi_enabled=True,
            nfc_enabled=True,
            battery_level=100,
        )

        _audit(request, 'DEVICE_ADDED', device=device, metadata={'device_code': device_code})
        _notify(request.user, 'Thiết bị mới đã được tạo',
                f'Dữ liệu thiết bị đã được khởi tạo. Vui lòng cấu hình device code: {device_code}',
                device=device, type_='DEVICE')

        messages.success(request, f'Đã thêm thiết bị "{name}". Device code: {device_code} — '
                                  f'Provisioning secret: {provisioning_secret} '
                                  '(chỉ hiển thị một lần, hãy lưu lại).')
        return redirect('smartlock:devices-list')

    return render(request, 'account/devices/add.html')


@auth_required
def devices_list(request):
    devices = _accessible_devices(request.user).order_by('name')
    return render(request, 'account/devices/list.html', {'device_list': devices})


@auth_required
def device_detail(request, device_id):
    device = get_object_or_404(_accessible_devices(request.user), id=device_id)
    is_owner = device.owner_id == request.user.id

    if request.method == 'POST':
        if not is_owner:
            _audit(request, 'DEVICE_UPDATE_DENIED', device=device, success=False, severity='warning')
            messages.error(request, 'Chỉ chủ thiết bị mới được chỉnh sửa.')
            return redirect('smartlock:device-detail', device_id=device.id)
        name = (request.POST.get('name') or '').strip()
        if not name:
            messages.error(request, 'Tên thiết bị không được để trống.')
        else:
            fields = ('name', 'location', 'wifi_enabled', 'bluetooth_enabled', 'nfc_enabled')
            before = {f: getattr(device, f) for f in fields}
            device.name = name[:100]
            device.location = (request.POST.get('location') or '').strip()[:255] or None
            device.wifi_enabled = 'wifi_enabled' in request.POST
            device.bluetooth_enabled = 'bluetooth_enabled' in request.POST
            device.nfc_enabled = 'nfc_enabled' in request.POST
            device.save()
            changes = {f: [before[f], getattr(device, f)] for f in fields if before[f] != getattr(device, f)}
            _audit(request, 'DEVICE_UPDATED', device=device, metadata={'changes': changes} if changes else None)
            messages.success(request, 'Đã cập nhật thiết bị.')
        return redirect('smartlock:device-detail', device_id=device.id)

    last_log = DeviceStatusLog.objects.filter(device=device).order_by('-recorded_at').first()
    device.lock_state = last_log.lock_state if last_log else 'unknown'
    accesses = []
    if is_owner:
        accesses = (DeviceAccess.objects.filter(device=device, is_active=True)
                    .select_related('user').prefetch_related('permissions'))
    context = {
        'device': device,
        'is_owner': is_owner,
        'last_log': last_log,
        'recent_commands': DeviceCommand.objects.filter(device=device)
                           .select_related('issued_by').order_by('-created_at')[:6],
        'accesses': accesses,
    }
    return render(request, 'account/devices/detail.html', context)


@auth_required
@require_POST
def device_command(request, device_id):
    device = get_object_or_404(_accessible_devices(request.user), id=device_id)
    command = (request.POST.get('command') or '').upper()
    if command not in ALLOWED_COMMANDS:
        _audit(request, 'CMD_INVALID', device=device, success=False, severity='warning',
               metadata={'command': command[:30]})
        return JsonResponse({'ok': False, 'message': 'Lệnh không hợp lệ.'}, status=400)

    needed = ALLOWED_COMMANDS[command]
    allowed = (device.owner_id == request.user.id) if needed is None \
        else _has_permission(request.user, device, needed)
    if not allowed:
        _audit(request, f'CMD_{command}_DENIED', device=device, success=False, severity='warning')
        return JsonResponse({'ok': False, 'message': 'Bạn không có quyền thực hiện lệnh này.'}, status=403)
    if device.status != 'online':
        _audit(request, f'CMD_{command}_FAILED', device=device, success=False,
               metadata={'reason': 'device_not_online', 'status': device.status})
        return JsonResponse({'ok': False, 'message': 'Thiết bị đang không online.'}, status=409)

    now = timezone.now()
    DeviceCommand.objects.filter(device=device, status='pending', expires_at__lte=now).update(status='expired')
    if DeviceCommand.objects.filter(device=device, status='pending', command_type=command).exists():
        _audit(request, f'CMD_{command}_FAILED', device=device, success=False,
               metadata={'reason': 'duplicate_pending'})
        return JsonResponse({'ok': False, 'message': 'Lệnh này đang chờ thiết bị xử lý.'}, status=429)

    cmd = DeviceCommand.objects.create(
        device=device, issued_by=request.user, command_type=command, status='pending',
        command_token_hash=_hash_token(secrets.token_urlsafe(32)),
        expires_at=now + timedelta(seconds=COMMAND_TTL_SECONDS),
    )

    # Bắn lệnh xuống thiết bị thật qua MQTT. Trước đây bước này KHÔNG tồn tại - lệnh chỉ
    # nằm trong DB ở trạng thái 'pending' mãi mãi trong khi UI vẫn báo "đã gửi lệnh".
    try:
        publish_command(device.device_code, {
            'command_id': str(cmd.id),
            'command': command,
            'token': cmd.command_token_hash,   # thiết bị gửi lại đúng hash này khi ack để đối chiếu
        })
        cmd.status = 'sent'
        cmd.save(update_fields=['status'])
    except MqttPublishError as e:
        cmd.status = 'failed'
        cmd.save(update_fields=['status'])
        _audit(request, f'CMD_{command}_FAILED', device=device, success=False,
               metadata={'reason': 'mqtt_publish_failed', 'error': str(e)[:200]})
        return JsonResponse({'ok': False, 'message': 'Không kết nối được tới thiết bị. Vui lòng thử lại.'}, status=502)

    _audit(request, f'CMD_{command}', device=device, metadata={'command_id': str(cmd.id)})
    labels = {'LOCK': 'Khóa', 'UNLOCK': 'Mở khóa', 'REBOOT': 'Khởi động lại'}
    return JsonResponse({'ok': True, 'command_id': str(cmd.id),
                         'message': f'Đã gửi lệnh {labels.get(command, command)} tới "{device.name}".'})


# ====================== MQTT: WEBHOOK XÁC THỰC THIẾT BỊ (gọi bởi plugin auth của broker) ======================
@csrf_exempt
@require_POST
def mqtt_auth_webhook(request):
    """
    Endpoint cho plugin HTTP-auth của broker (vd. mosquitto-go-auth) gọi vào để kiểm
    tra 1 thiết bị có được phép kết nối/publish/subscribe hay không.

    Thiết bị connect vào broker với username=device_code, password=provisioning_secret
    (secret gốc thiết bị đã lưu lúc provisioning - KHÔNG lưu thêm secret riêng cho MQTT,
    tái dùng đúng Device.provisioning_secret_hash đã có).

    Trả 200 = cho phép, 401/403 = từ chối. KHÔNG dùng @auth_required (đây không phải
    người dùng đăng nhập) và bỏ qua CSRF (broker gọi server-to-server, không có session).
    Cần chặn endpoint này ở tầng mạng/tường lửa chỉ cho phép broker gọi vào, không public.
    """
    username = (request.POST.get('username') or '').strip()
    password = request.POST.get('password') or ''
    if not username or not password:
        return JsonResponse({'ok': False}, status=401)

    device = Device.objects.filter(device_code=username).first()
    if not device or not hmac.compare_digest(device.provisioning_secret_hash, _hash_token(password)):
        _audit(request, 'MQTT_AUTH_DENIED', success=False, severity='warning',
               username_attempt=username[:150])
        return JsonResponse({'ok': False}, status=401)

    return JsonResponse({'ok': True})


# ====================== NFC ======================
@auth_required
def nfc_tags(request):
    if request.method == 'POST':
        action = request.POST.get('action')
        card_id = _parse_uuid(request.POST.get('card_id'))
        card = AccessCard.objects.filter(id=card_id, user=request.user).first() if card_id else None
        if not card:
            _audit(request, 'CARD_NOT_FOUND', success=False, severity='warning',
                   metadata={'card_id': str(request.POST.get('card_id'))[:64], 'action': str(action)[:30]})
            messages.error(request, 'Không tìm thấy thẻ.')
        elif action == 'toggle':
            card.is_active = not card.is_active
            card.save()
            _audit(request, 'CARD_ENABLED' if card.is_active else 'CARD_DISABLED',
                   metadata={'card_id': str(card.id), 'name': card.name})
            messages.success(request, 'Đã kích hoạt thẻ.' if card.is_active else 'Đã vô hiệu hóa thẻ.')
        elif action == 'rename':
            old_name = card.name
            card.name = (request.POST.get('name') or '').strip()[:100] or None
            card.save()
            _audit(request, 'CARD_RENAMED',
                   metadata={'card_id': str(card.id), 'from': old_name, 'to': card.name})
            messages.success(request, 'Đã đổi tên thẻ.')
        elif action == 'delete':
            info = {'card_id': str(card.id), 'name': card.name,
                    'devices': [str(d) for d in card.carddeviceaccess_set.values_list('device_id', flat=True)]}
            card.delete()
            _audit(request, 'CARD_DELETED', metadata=info)
            messages.success(request, 'Đã xóa thẻ.')
        return redirect('smartlock:nfc-tags')

    cards = (AccessCard.objects.filter(user=request.user)
             .prefetch_related('carddeviceaccess_set__device').order_by('-created_at'))
    return render(request, 'account/nfc/tags.html', {'access_cards': cards})


@auth_required
def nfc_reader(request):
    is_post = request.method == 'POST'
    devices = Device.objects.filter(owner=request.user).order_by('name')
    device = _pick_device(devices, request.POST.get('device') or request.GET.get('device'),
                          strict=is_post)

    if is_post:
        if not device:
            _audit(request, 'NFC_DEVICE_NOT_FOUND', success=False, severity='warning',
                   metadata={'device': str(request.POST.get('device') or request.GET.get('device'))[:64]})
            messages.error(request, 'Không tìm thấy thiết bị hoặc bạn không phải chủ.')
            return redirect('smartlock:devices-list')

        action = request.POST.get('action')
        back = lambda: _redirect_with('smartlock:nfc-reader', device=device.id)

        if action == 'add_reader':
            name = (request.POST.get('name') or '').strip()[:100] or 'Đầu đọc mô phỏng'
            with transaction.atomic():
                reader = NfcReader.objects.create(device=device, reader_mode='simulated',
                                                  name=name, is_active=True)
                NfcReaderConfig.objects.create(reader=reader)
                NfcLog.objects.create(reader=reader, device=device, user=request.user,
                                      event_type='READER_CONNECTED', ip_address=_client_ip(request),
                                      user_agent=_user_agent(request))
            _audit(request, 'NFC_READER_ADDED', device=device,
                   metadata={'reader_id': str(reader.id), 'name': name})
            messages.success(request, 'Đã thêm đầu đọc.')
            return back()

        if action in ('toggle_reader', 'toggle_auto'):
            reader = NfcReader.objects.filter(id=_parse_uuid(request.POST.get('reader_id')),
                                              device=device).first()
            if not reader:
                _audit(request, 'NFC_READER_NOT_FOUND', device=device, success=False, severity='warning')
                messages.error(request, 'Không tìm thấy đầu đọc.')
                return back()
            if action == 'toggle_reader':
                reader.is_active = not reader.is_active
                reader.save()
                event = 'READER_CONNECTED' if reader.is_active else 'READER_DISCONNECTED'
                audit_action = 'NFC_READER_ENABLED' if reader.is_active else 'NFC_READER_DISABLED'
            else:
                cfg, _ = NfcReaderConfig.objects.get_or_create(reader=reader)
                cfg.auto_register = not cfg.auto_register
                cfg.save()
                event = 'CONFIG_UPDATED'
                audit_action = 'NFC_AUTO_REGISTER_ON' if cfg.auto_register else 'NFC_AUTO_REGISTER_OFF'
            NfcLog.objects.create(reader=reader, device=device, user=request.user, event_type=event,
                                  ip_address=_client_ip(request), user_agent=_user_agent(request))
            _audit(request, audit_action, device=device, metadata={'reader_id': str(reader.id)})
            messages.success(request, 'Đã cập nhật đầu đọc.')
            return back()

        if action == 'register_card':
            uid = re.sub(r'[\s:\-]', '', request.POST.get('uid') or '').upper()
            name = (request.POST.get('name') or '').strip()[:100] or None
            if len(uid) < 4:
                messages.error(request, 'UID thẻ không hợp lệ.')
                return back()
            try:
                with transaction.atomic():
                    card = AccessCard.objects.create(
                        card_uid_hash=_hash_token(uid), user=request.user, name=name, is_active=True)
                    CardDeviceAccess.objects.create(access_card=card, device=device)
            except IntegrityError:
                _audit(request, 'CARD_REGISTER_FAILED', device=device, success=False,
                       severity='warning', metadata={'reason': 'duplicate'})
                messages.error(request, 'Thẻ này đã được đăng ký.')
                return back()
            reader = NfcReader.objects.filter(device=device, is_active=True).first()
            NfcLog.objects.create(reader=reader, nfc_tag=card, device=device, user=request.user,
                                  event_type='CARD_REGISTER', ip_address=_client_ip(request),
                                  user_agent=_user_agent(request))
            _audit(request, 'CARD_REGISTERED', device=device,
                   metadata={'card_id': str(card.id), 'name': name})
            messages.success(request, 'Đã đăng ký thẻ NFC.')
            return back()
        return back()

    context = {
        'device_list': devices,
        'device': device,
        'readers': NfcReader.objects.filter(device=device).select_related('config').order_by('-created_at') if device else [],
        'nfc_logs': NfcLog.objects.filter(device=device).select_related('nfc_tag', 'reader')
                    .order_by('-created_at')[:10] if device else [],
    }
    return render(request, 'account/nfc/reader.html', context)


# ====================== SHARE & SUPPORT ======================
@auth_required
def share_codes(request):
    user = request.user
    _ensure_default_permissions()
    owned = Device.objects.filter(owner=user).order_by('name')

    if request.method == 'POST':
        action = request.POST.get('action')
        if action == 'create':
            device = owned.filter(id=_parse_uuid(request.POST.get('device_id'))).first()
            if not device:
                _audit(request, 'SHARE_CODE_CREATE_DENIED', success=False, severity='warning')
                messages.error(request, 'Vui lòng chọn thiết bị của bạn.')
                return redirect('smartlock:share-codes')
            try:
                minutes = int(request.POST.get('minutes') or min(_settings().share_code_expiry_minutes, 1440))
                if not 1 <= minutes <= 1440:
                    raise ValueError
            except ValueError:
                messages.error(request, 'Thời hạn phải từ 1 đến 1440 phút.')
                return redirect('smartlock:share-codes')
            plain = _unique_share_plain()
            if not plain:
                messages.error(request, 'Không tạo được mã, vui lòng thử lại.')
                return redirect('smartlock:share-codes')
            perms = list(Permission.objects.filter(code__in=request.POST.getlist('permissions')))
            code = ShareAccessCode(device=device, created_by=user,
                                   expires_at=timezone.now() + timedelta(minutes=minutes))
            code.set_code(plain)
            code.save()
            code.permissions.set(perms)
            _audit(request, 'SHARE_CODE_CREATED', device=device,
                   metadata={'code_id': str(code.id), 'minutes': minutes,
                             'permissions': sorted(p.code for p in perms)})
            messages.success(request, f'Đã tạo mã chia sẻ {plain} (hết hạn sau {minutes} phút).')
        elif action == 'delete':
            code = (ShareAccessCode.objects.select_related('device')
                    .filter(id=_parse_uuid(request.POST.get('code_id')), device__owner=user).first())
            if code:
                device, code_id = code.device, str(code.id)
                code.delete()
                _audit(request, 'SHARE_CODE_DELETED', device=device, metadata={'code_id': code_id})
                messages.success(request, 'Đã xóa mã chia sẻ.')
        return redirect('smartlock:share-codes')

    now = timezone.now()
    codes = list(ShareAccessCode.objects.filter(device__owner=user)
                 .select_related('device').prefetch_related('permissions').order_by('-created_at'))
    for c in codes:
        # Mã lưu dạng hash 1 chiều nên không thể "giải mã" lại để hiển thị.
        # Mã gốc chỉ hiện đúng 1 lần trong thông báo ngay lúc tạo (xem nhánh action == 'create' ở trên).
        c.plain = '••••••'
        c.is_expired = c.expires_at <= now

    context = {
        'share_codes': codes,
        'device_list': owned,
        'permissions': Permission.objects.order_by('name'),
        'default_minutes': min(_settings().share_code_expiry_minutes, 1440),
    }
    return render(request, 'account/share/codes.html', context)


@auth_required
def share_request(request):
    user = request.user
    if request.method == 'POST':
        ip = _client_ip(request)
        now = timezone.now()
        plain = re.sub(r'\D', '', request.POST.get('code') or '')

        # Đếm lần NHẬP SAI (theo user hoặc theo IP) trong 15 phút.
        fails = (AuditLog.objects
                 .filter(action='SHARE_CODE_REDEEM_FAILED', created_at__gte=now - timedelta(minutes=15))
                 .filter(Q(actor_user=user) | Q(ip_address=ip)).count())
        if fails >= 5:
            _audit(request, 'SHARE_CODE_RATE_LIMITED', success=False, severity='critical')
            messages.error(request, 'Bạn nhập sai quá nhiều lần. Vui lòng thử lại sau 15 phút.')
            return redirect('smartlock:share-request')

        match = None
        if len(plain) == 6:
            match = ShareAccessCode.find_active_by_code(plain)

        if not match:
            _audit(request, 'SHARE_CODE_REDEEM_FAILED', success=False, severity='warning')
            messages.error(request, 'Mã chia sẻ không đúng hoặc đã hết hạn.')
            return redirect('smartlock:share-request')

        if match.device.owner_id == user.id:
            _audit(request, 'SHARE_CODE_OWN_DEVICE', device=match.device, success=False)
            messages.error(request, 'Đây là thiết bị của chính bạn.')
            return redirect('smartlock:share-request')

        with transaction.atomic():
            locked = ShareAccessCode.objects.select_for_update().filter(id=match.id).first()
            if not locked:  # người khác vừa dùng mã này
                _audit(request, 'SHARE_CODE_REDEEM_FAILED', success=False, severity='warning',
                       metadata={'reason': 'already_used'})
                messages.error(request, 'Mã chia sẻ không đúng hoặc đã hết hạn.')
                return redirect('smartlock:share-request')

            new_exp = now + timedelta(hours=SHARED_ACCESS_HOURS)
            perms = list(locked.permissions.all())
            access = (DeviceAccess.objects.select_for_update()
                      .filter(device=match.device, user=user, is_active=True).first())
            if access:  # đã có quyền: gia hạn + gộp quyền, không tạo bản ghi trùng
                if access.expires_at is not None:
                    access.expires_at = max(access.expires_at, new_exp)
                    access.save(update_fields=['expires_at'])
                access.permissions.add(*perms)
            else:
                access = DeviceAccess.objects.create(
                    device=match.device, user=user, source='SHARE_CODE', accepted=True,
                    valid_from=now, expires_at=new_exp, created_by=match.created_by,
                )
                access.permissions.set(perms)
            locked.delete()

        _audit(request, 'SHARE_CODE_REDEEMED', device=match.device, target_user=match.created_by,
               metadata={'access_id': str(access.id), 'permissions': sorted(p.code for p in perms)})
        _notify(match.created_by, 'Mã chia sẻ đã được sử dụng',
                f'{user.username} đã nhận quyền truy cập "{match.device.name}".',
                device=match.device, type_='SHARE')
        messages.success(request, f'Đã nhận quyền truy cập thiết bị "{match.device.name}".')
        return redirect('smartlock:share-request')

    now = timezone.now()
    accesses = (DeviceAccess.objects.filter(user=user, is_active=True)
                .filter(Q(expires_at__isnull=True) | Q(expires_at__gt=now))
                .select_related('device').prefetch_related('permissions').order_by('-created_at'))
    return render(request, 'account/share/request.html',
                  {'my_accesses': accesses, 'access_hours': SHARED_ACCESS_HOURS})


@auth_required
def support_requests(request):
    user = request.user
    now = timezone.now()
    SupportRequest.objects.filter(status='pending', expires_at__lte=now).update(
        status='expired', completed_at=now)

    if request.method == 'POST':
        device = Device.objects.filter(id=_parse_uuid(request.POST.get('device_id')), owner=user).first()
        action = request.POST.get('action')
        valid_actions = {c for c, _ in SupportRequest._meta.get_field('action').choices}
        if not device:
            _audit(request, 'SUPPORT_REQUEST_DENIED', success=False, severity='warning',
                   metadata={'reason': 'not_owner'})
            messages.error(request, 'Không phải thiết bị của bạn.')
            return redirect('smartlock:support-requests')
        if action not in valid_actions:
            _audit(request, 'SUPPORT_REQUEST_DENIED', device=device, success=False, severity='warning',
                   metadata={'reason': 'invalid_action', 'action': str(action)[:30]})
            messages.error(request, 'Loại yêu cầu không hợp lệ.')
            return redirect('smartlock:support-requests')
        if SupportRequest.objects.filter(device=device, requested_by=user, status='pending').count() >= 5:
            messages.error(request, 'Bạn đang có quá nhiều yêu cầu chờ xử lý cho thiết bị này.')
            return redirect('smartlock:support-requests')

        auth_code = secrets.token_hex(4).upper()
        recovery = secrets.token_hex(4).upper() if action in RECOVERY_ACTIONS else None
        sr = SupportRequest.objects.create(
            device=device, requested_by=user, action=action,
            scope=(request.POST.get('scope') or '').strip()[:100] or None,
            authorization_code_hash=_hash_token(auth_code),
            recovery_code_hash=_hash_token(recovery) if recovery else None,
            expires_at=now + timedelta(hours=SUPPORT_TTL_HOURS),
        )
        _audit(request, 'SUPPORT_REQUEST_CREATED', device=device,
               metadata={'request_id': str(sr.id), 'action': action})
        msg = f'Đã tạo yêu cầu. Mã ủy quyền: {auth_code}'
        if recovery:
            msg += f' — Mã khôi phục: {recovery}'
        messages.success(request, msg + ' (chỉ hiển thị một lần, hãy lưu lại).')
        return redirect('smartlock:support-request-detail', request_id=sr.id)

    reqs = SupportRequest.objects.filter(requested_by=user).select_related('device').order_by('-created_at')
    context = {
        'support_requests': _page(request, reqs),
        'device_list': Device.objects.filter(owner=user).order_by('name'),
        'action_choices': SupportRequest._meta.get_field('action').choices,
    }
    return render(request, 'account/support/requests.html', context)


@auth_required
def support_request_detail(request, request_id):
    sr = get_object_or_404(SupportRequest.objects.select_related('device', 'processed_by'),
                           id=request_id, requested_by=request.user)
    if request.method == 'POST' and request.POST.get('action') == 'cancel':
        if sr.status == 'pending' and sr.expires_at > timezone.now():
            sr.status = 'cancelled'
            sr.completed_at = timezone.now()
            sr.save()
            _audit(request, 'SUPPORT_REQUEST_CANCELLED', device=sr.device,
                   metadata={'request_id': str(sr.id)})
            messages.success(request, 'Đã hủy yêu cầu.')
        else:
            messages.error(request, 'Chỉ có thể hủy yêu cầu đang chờ xử lý.')
        return redirect('smartlock:support-request-detail', request_id=sr.id)
    return render(request, 'account/support/request_detail.html', {'support_request': sr})


# ====================== PERMISSIONS ======================
@auth_required
def permissions_manage(request):
    _ensure_default_permissions()
    user = request.user
    is_post = request.method == 'POST'
    devices = Device.objects.filter(owner=user).order_by('name')
    device = _pick_device(devices, request.POST.get('device') or request.GET.get('device'),
                          strict=is_post)

    if is_post:
        if not device:
            _audit(request, 'ACCESS_DEVICE_NOT_FOUND', success=False, severity='warning',
                   metadata={'device': str(request.POST.get('device') or request.GET.get('device'))[:64]})
            messages.error(request, 'Không tìm thấy thiết bị của bạn.')
            return redirect('smartlock:permissions-manage')

        action = request.POST.get('action')
        back = lambda: _redirect_with('smartlock:permissions-manage', device=device.id)
        perms = list(Permission.objects.filter(code__in=request.POST.getlist('permissions')))
        perm_codes = sorted(p.code for p in perms)

        if action == 'grant':
            identifier = request.POST.get('identifier')
            target = _find_user(identifier)
            raw_exp = (request.POST.get('expires_at') or '').strip()
            expires = _parse_dt(raw_exp)
            now = timezone.now()
            if raw_exp and expires is None:
                # Trước đây nhập sai định dạng bị coi là "không hết hạn" => cấp quyền vĩnh viễn.
                messages.error(request, 'Định dạng thời điểm hết hạn không hợp lệ.')
            elif not target or not target.is_active:
                _audit(request, 'ACCESS_GRANT_FAILED', device=device, success=False,
                       username_attempt=(identifier or '')[:150], metadata={'reason': 'user_not_found'})
                messages.error(request, 'Không tìm thấy người dùng (email hoặc username).')
            elif target.id == user.id:
                messages.error(request, 'Bạn đã là chủ thiết bị này.')
            elif expires and expires <= now:
                messages.error(request, 'Thời điểm hết hạn phải ở tương lai.')
            else:
                with transaction.atomic():
                    access = (DeviceAccess.objects.select_for_update()
                              .filter(device=device, user=target, is_active=True)
                              .order_by('-created_at').first())
                    if access:
                        access.expires_at = expires
                        access.accepted = True
                        access.save(update_fields=['expires_at', 'accepted'])
                    else:
                        access = DeviceAccess.objects.create(
                            device=device, user=target, created_by=user, accepted=True,
                            source='DIRECT', expires_at=expires)
                    access.permissions.set(perms)
                _audit(request, 'ACCESS_GRANTED', device=device, target_user=target,
                       metadata={'access_id': str(access.id), 'permissions': perm_codes,
                                 'expires_at': expires.isoformat() if expires else None})
                _notify(target, 'Bạn được cấp quyền thiết bị',
                        f'{user.username} đã cấp quyền cho bạn trên "{device.name}".',
                        device=device, type_='ACCESS')
                messages.success(request, f'Đã cấp quyền cho {target.username}.')
        elif action in ('update', 'revoke'):
            access = (DeviceAccess.objects.select_related('user')
                      .filter(id=_parse_uuid(request.POST.get('access_id')),
                              device=device, is_active=True).first())
            if not access:
                _audit(request, 'ACCESS_NOT_FOUND', device=device, success=False, severity='warning',
                       metadata={'action': str(action)})
                messages.error(request, 'Không tìm thấy quyền truy cập.')
            elif action == 'update':
                old_codes = sorted(p.code for p in access.permissions.all())
                access.permissions.set(perms)
                _audit(request, 'ACCESS_UPDATED', device=device, target_user=access.user,
                       metadata={'access_id': str(access.id), 'from': old_codes, 'to': perm_codes})
                messages.success(request, 'Đã cập nhật quyền.')
            else:
                access.is_active = False
                access.revoked_at = timezone.now()
                access.save()
                # Lệnh đang chờ do người bị thu hồi gửi không được phép chạy tiếp.
                cancelled = DeviceCommand.objects.filter(
                    device=device, issued_by=access.user, status='pending').update(status='failed')
                _audit(request, 'ACCESS_REVOKED', device=device, target_user=access.user,
                       severity='warning',
                       metadata={'access_id': str(access.id), 'cancelled_commands': cancelled})
                _notify(access.user, 'Quyền truy cập bị thu hồi',
                        f'Quyền của bạn trên "{device.name}" đã bị thu hồi.',
                        severity='warning', device=device, type_='ACCESS')
                messages.success(request, 'Đã thu hồi quyền.')
        return back()

    accesses = []
    if device:
        accesses = list(DeviceAccess.objects.filter(device=device, is_active=True)
                        .select_related('user').prefetch_related('permissions').order_by('-created_at'))
        for a in accesses:
            a.perm_codes = [p.code for p in a.permissions.all()]

    context = {
        'device_list': devices,
        'device': device,
        'permissions': Permission.objects.order_by('name'),
        'accesses': accesses,
    }
    return render(request, 'account/permissions/manage.html', context)


# ====================== SETTINGS / PROFILE / LOGS ======================
@auth_required
def settings_system(request):
    if not _is_admin(request.user):
        _audit(request, 'SETTINGS_ACCESS_DENIED', success=False, severity='warning')
        messages.error(request, 'Bạn không có quyền truy cập trang này.')
        return redirect('smartlock:dashboard')

    st = _settings()
    if request.method == 'POST':
        try:
            expiry = int(request.POST.get('verification_token_expiry_minutes'))
            share = int(request.POST.get('share_code_expiry_minutes'))
            timeout = int(request.POST.get('session_timeout_hours'))
            stages = [int(x) for x in re.split(r'[,\s]+', (request.POST.get('lockout_stages') or '').strip()) if x]
            if not stages or min(stages + [expiry, share, timeout]) <= 0:
                raise ValueError
            if expiry > 10080 or share > 1440 or timeout > 720 or max(stages) > 1440:
                raise ValueError
        except (TypeError, ValueError):
            messages.error(request, 'Giá trị không hợp lệ (số nguyên dương; token ≤ 10080 phút, '
                                    'mã chia sẻ ≤ 1440 phút, phiên ≤ 720 giờ, khóa ≤ 1440 phút).')
            return redirect('smartlock:settings-system')

        white, bad_w = _clean_ip_lines(request.POST.get('ip_whitelist'))
        black, bad_b = _clean_ip_lines(request.POST.get('ip_blacklist'))
        if bad_w or bad_b:
            messages.error(request, 'IP không hợp lệ: ' + ', '.join((bad_w + bad_b)[:5]))
            return redirect('smartlock:settings-system')
        if _client_ip(request) in black:
            messages.error(request, 'Không thể chặn chính IP bạn đang dùng.')
            return redirect('smartlock:settings-system')

        tracked = ('registration_enabled', 'verification_token_expiry_minutes', 'share_code_expiry_minutes',
                   'session_timeout_hours', 'login_lockout_stage_minutes', 'ip_whitelist', 'ip_blacklist')
        before = {f: getattr(st, f) for f in tracked}

        st.registration_enabled = 'registration_enabled' in request.POST
        st.verification_token_expiry_minutes = expiry
        st.share_code_expiry_minutes = share
        st.session_timeout_hours = timeout
        st.login_lockout_stage_minutes = stages
        st.ip_whitelist = '\n'.join(white)
        st.ip_blacklist = '\n'.join(black)
        st.updated_by = request.user
        st.save()
        changes = {f: [before[f], getattr(st, f)] for f in tracked if before[f] != getattr(st, f)}
        _audit(request, 'SETTINGS_UPDATED', severity='warning', metadata={'changes': changes})
        messages.success(request, 'Đã lưu cài đặt hệ thống.')
        return redirect('smartlock:settings-system')

    context = {
        'system_settings': st,
        'stages_text': ', '.join(str(x) for x in (st.login_lockout_stage_minutes or [])),
    }
    return render(request, 'account/settings/system.html', context)


@auth_required
def notifications_list(request):
    user = request.user
    if request.method == 'POST':
        action = request.POST.get('action')
        now = timezone.now()
        if action == 'mark_all':
            Notification.objects.filter(user=user, is_read=False).update(is_read=True, read_at=now)
        elif action == 'mark_read':
            Notification.objects.filter(user=user, id=_parse_uuid(request.POST.get('id'))).update(is_read=True, read_at=now)
        elif action == 'delete_all_read':
            Notification.objects.filter(user=user, is_read=True).delete()
        nxt = request.META.get('HTTP_REFERER')
        if nxt and url_has_allowed_host_and_scheme(nxt, {request.get_host()}):
            return redirect(nxt)
        return redirect('smartlock:notifications')

    only_unread = request.GET.get('filter') == 'unread'
    qs = Notification.objects.filter(user=user).select_related('device').order_by('-created_at')
    if only_unread:
        qs = qs.filter(is_read=False)
    context = {
        'notifications': _page(request, qs),
        'only_unread': only_unread,
        'unread_count': Notification.objects.filter(user=user, is_read=False).count(),
        'qs': '&filter=unread' if only_unread else '',
    }
    return render(request, 'account/base/notifications.html', context)


@auth_required
def profile(request):
    user = request.user
    if request.method == 'POST':
        action = request.POST.get('action')
        if action == 'update_info':
            before = {'full_name': user.full_name, 'phone': user.phone}
            user.full_name = (request.POST.get('full_name') or '').strip()[:100] or None
            user.phone = (request.POST.get('phone') or '').strip()[:20] or None
            user.save(update_fields=['full_name', 'phone', 'updated_at'])
            after = {'full_name': user.full_name, 'phone': user.phone}
            changes = {k: [before[k], after[k]] for k in after if before[k] != after[k]}
            _audit(request, 'PROFILE_UPDATED', target_user=user,
                   metadata={'changes': changes} if changes else None)
            messages.success(request, 'Đã cập nhật thông tin cá nhân.')
        elif action == 'change_password':
            old = request.POST.get('old_password') or ''
            p1 = request.POST.get('new_password1') or ''
            p2 = request.POST.get('new_password2') or ''
            recent_fails = AuditLog.objects.filter(
                action='PASSWORD_CHANGE_FAILED', actor_user=user,
                created_at__gte=timezone.now() - timedelta(minutes=15)).count()
            if recent_fails >= 5:
                messages.error(request, 'Nhập sai mật khẩu hiện tại quá nhiều lần. Thử lại sau 15 phút.')
            elif not user.check_password(old):
                _audit(request, 'PASSWORD_CHANGE_FAILED', success=False, severity='warning',
                       target_user=user)
                messages.error(request, 'Mật khẩu hiện tại không đúng.')
            elif not p1 or p1 != p2:
                messages.error(request, 'Mật khẩu mới không khớp.')
            else:
                try:
                    validate_password(p1, user)
                except ValidationError as e:
                    messages.error(request, ' '.join(e.messages))
                else:
                    user.set_password(p1)
                    user.save()
                    update_session_auth_hash(request, user)
                    _audit(request, 'PASSWORD_CHANGED', severity='warning', target_user=user)
                    _notify(user, 'Mật khẩu đã thay đổi', 'Bạn vừa đổi mật khẩu tài khoản.',
                            severity='warning', type_='SECURITY')
                    messages.success(request, 'Đã đổi mật khẩu.')
        return redirect('smartlock:profile')

    context = {
        'device_count': Device.objects.filter(owner=user).count(),
        'card_count': AccessCard.objects.filter(user=user).count(),
    }
    context.update(two_factor_context(request, user))
    return render(request, 'account/base/profile.html', context)


@auth_required
def audit_logs(request):
    user = request.user
    show_all = _is_admin(user) and request.GET.get('all') == '1'
    base = AuditLog.objects.all() if show_all else _visible_logs(user)
    qs = base.select_related('device', 'actor_user', 'target_user').order_by('-created_at')

    status = request.GET.get('status')
    if status == 'ok':
        qs = qs.filter(success=True)
    elif status == 'fail':
        qs = qs.filter(success=False)
    q = (request.GET.get('q') or '').strip()
    if q:
        qs = qs.filter(action__icontains=q)

    extra = ''.join('&' + urlencode({k: v}) for k, v in
                    (('status', status), ('q', q), ('all', '1' if show_all else '')) if v)
    context = {'audit_logs': _page(request, qs), 'show_all': show_all,
               'status': status or '', 'q': q, 'qs': extra, 'can_see_all': _is_admin(user)}
    return render(request, 'account/audit/logs.html', context)


# ====================== 2FA: CONSTANTS ======================
SESSION_KEY = 'pending_2fa'            # {user_id, purpose, backend, next, ts, fails}
PENDING_TTL = 10 * 60                  # 10 phút để hoàn tất bước 2
MAX_PENDING_FAILS = 5                  # sai quá 5 lần trong 1 phiên -> hủy phiên, phải nhập lại mật khẩu
EMAIL_CODE_TTL_MIN = 10
EMAIL_CODE_COOLDOWN = 60               # giây giữa 2 lần gửi mã
EMAIL_CODE_MAX_ATTEMPTS = 5
BACKUP_CODE_COUNT = 8
TOTP_ISSUER = 'Smart Lock'
SETUP_TTL = 10 * 60
WEBAUTHN_TTL = 5 * 60
DEFAULT_BACKEND = 'django.contrib.auth.backends.ModelBackend'

PURPOSE_TEXT = {
    'login':   ('Xác thực 2 lớp', 'Nhập mã xác thực để hoàn tất đăng nhập.'),
    'enable':  ('Xác nhận bật 2FA', 'Xác nhận bằng một phương thức bạn vừa thiết lập để bật 2FA.'),
    'disable': ('Xác nhận tắt 2FA', 'Cần xác thực lần cuối trước khi tắt xác thực 2 lớp.'),
}


def _now_ts():
    return int(timezone.now().timestamp())


# ====================== HÀM PHỤ (mã hóa / mã dự phòng / TOTP / email) ======================
def _pepper_hash(user, value: str) -> str:
    """HMAC-SHA256 gắn với SECRET_KEY + user để lưu hash của mã OTP / mã dự phòng."""
    msg = f'{user.pk}:{value}'.encode()
    return hmac.new(dj_settings.SECRET_KEY.encode(), msg, hashlib.sha256).hexdigest()


def _digits(value) -> str:
    return re.sub(r'\D', '', value or '')


def _get_cfg(user) -> TwoFactorConfig:
    return TwoFactorConfig.objects.get_or_create(user=user)[0]


def _qr_data_uri(text: str) -> str:
    """QR dạng SVG (không cần Pillow -> chạy được trên Vercel)."""
    img = qrcode.make(text, image_factory=qrcode.image.svg.SvgPathImage, box_size=10, border=2)
    buf = io.BytesIO()
    img.save(buf)
    return 'data:image/svg+xml;base64,' + base64.b64encode(buf.getvalue()).decode()


def _verify_totp(cfg: TwoFactorConfig, code: str) -> bool:
    """Kiểm tra mã TOTP (±1 bước 30s) và chặn dùng lại cùng một mã (replay)."""
    code = _digits(code)
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


def _new_backup_codes(user):
    """Xóa mã cũ, tạo BACKUP_CODE_COUNT mã mới (chỉ lưu hash). Trả về danh sách mã thô để hiển thị 1 lần."""
    alphabet = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'
    codes = [
        '-'.join(''.join(secrets.choice(alphabet) for _ in range(4)) for _ in range(2))
        for _ in range(BACKUP_CODE_COUNT)
    ]
    with transaction.atomic():
        TwoFactorBackupCode.objects.filter(user=user).delete()
        TwoFactorBackupCode.objects.bulk_create([
            TwoFactorBackupCode(user=user, code_hash=_pepper_hash(user, 'bk:' + _norm_backup(c)))
            for c in codes
        ])
    return codes


def _norm_backup(value) -> str:
    return re.sub(r'[^A-Z0-9]', '', (value or '').upper())


def _use_backup_code(user, raw) -> bool:
    norm = _norm_backup(raw)
    if len(norm) != 8:
        return False
    h = _pepper_hash(user, 'bk:' + norm)
    with transaction.atomic():
        obj = TwoFactorBackupCode.objects.select_for_update().filter(
            user=user, code_hash=h, is_used=False).first()
        if not obj:
            return False
        obj.is_used = True
        obj.used_at = timezone.now()
        obj.save(update_fields=['is_used', 'used_at'])
    return True


def _backup_left(user) -> int:
    return TwoFactorBackupCode.objects.filter(user=user, is_used=False).count()


def _send_email_code(user, purpose):
    """purpose: 'SETUP' (thiết lập Email OTP) hoặc 'VERIFY' (login/enable/disable).
    Trả về 'sent' | 'cooldown' | 'failed'."""
    now = timezone.now()
    if TwoFactorEmailCode.objects.filter(
            user=user, created_at__gt=now - timedelta(seconds=EMAIL_CODE_COOLDOWN)).exists():
        return 'cooldown'
    code = f'{secrets.randbelow(10 ** 6):06d}'
    TwoFactorEmailCode.objects.filter(user=user, is_used=False).update(is_used=True)
    TwoFactorEmailCode.objects.create(
        user=user, purpose=purpose, code_hash=_pepper_hash(user, 'em:' + code),
        expires_at=now + timedelta(minutes=EMAIL_CODE_TTL_MIN),
    )
    subject, html, plain = render_email('two_factor_code.html', {
        'full_name': user.full_name or user.username,
        'otp_code': code,
        'expiry_minutes': EMAIL_CODE_TTL_MIN,
    })
    return 'sent' if _send_mail(subject, plain, html, user.email, log_body=False) else 'failed'


def _verify_email_code(user, code, purpose) -> bool:
    code = _digits(code)
    if len(code) != 6:
        return False
    with transaction.atomic():
        rec = TwoFactorEmailCode.objects.select_for_update().filter(
            user=user, purpose=purpose, is_used=False, expires_at__gt=timezone.now(),
        ).order_by('-created_at').first()
        if not rec:
            return False
        rec.attempts += 1
        if rec.attempts > EMAIL_CODE_MAX_ATTEMPTS:
            rec.is_used = True
            rec.save(update_fields=['attempts', 'is_used'])
            return False
        ok = hmac.compare_digest(rec.code_hash, _pepper_hash(user, 'em:' + code))
        if ok:
            rec.is_used = True
        rec.save(update_fields=['attempts', 'is_used'])
        return ok


def _mask_email(email: str) -> str:
    name, _, dom = (email or '').partition('@')
    return (name[:2] if len(name) > 2 else name[:1]) + '***@' + dom


def _require_password(request) -> bool:
    """Bắt nhập lại mật khẩu cho thao tác nhạy cảm (gỡ/tắt/tạo lại mã). Có giới hạn số lần sai."""
    user = request.user
    recent = AuditLog.objects.filter(
        action='TWO_FACTOR_PASSWORD_FAILED', actor_user=user,
        created_at__gte=timezone.now() - timedelta(minutes=15)).count()
    if recent >= 5:
        messages.error(request, 'Nhập sai mật khẩu quá nhiều lần. Thử lại sau 15 phút.')
        return False
    if not user.check_password(request.POST.get('password') or ''):
        _audit(request, 'TWO_FACTOR_PASSWORD_FAILED', success=False, severity='warning', target_user=user)
        messages.error(request, 'Mật khẩu không đúng.')
        return False
    return True


# ====================== WEBAUTHN HELPERS ======================
def _rp(request):
    """(rp_id, origin, rp_name). Có thể ghi đè bằng settings.WEBAUTHN_RP_ID / WEBAUTHN_ORIGIN / WEBAUTHN_RP_NAME."""
    host = request.get_host()
    rp_id = getattr(dj_settings, 'WEBAUTHN_RP_ID', None) or host.split(':')[0]
    scheme = 'https' if request.is_secure() else 'http'
    if getattr(dj_settings, 'TRUST_PROXY_HEADERS', False) and \
            request.META.get('HTTP_X_FORWARDED_PROTO', '').split(',')[0].strip() == 'https':
        scheme = 'https'
    origin = getattr(dj_settings, 'WEBAUTHN_ORIGIN', None) or f'{scheme}://{host}'
    return rp_id, origin, getattr(dj_settings, 'WEBAUTHN_RP_NAME', TOTP_ISSUER)


def _json_body(request):
    try:
        return json.loads(request.body.decode() or '{}')
    except (ValueError, UnicodeDecodeError):
        return None


def _cred_descriptors(user):
    return [PublicKeyCredentialDescriptor(id=base64url_to_bytes(c.credential_id))
            for c in Fido2Credential.objects.filter(user=user)]


# ====================== PENDING SESSION (bước 2) ======================
def _start_pending(request, user, purpose, backend='', next_url=''):
    request.session[SESSION_KEY] = {
        'user_id': str(user.pk), 'purpose': purpose, 'backend': backend or DEFAULT_BACKEND,
        'next': next_url or '', 'ts': _now_ts(), 'fails': 0,
    }


def _clear_pending(request):
    request.session.pop(SESSION_KEY, None)
    request.session.pop('webauthn_auth', None)


def _get_pending(request):
    """Trả về (pending, user) hợp lệ hoặc (None, None)."""
    p = request.session.get(SESSION_KEY)
    if not isinstance(p, dict):
        return None, None
    if _now_ts() - int(p.get('ts', 0)) > PENDING_TTL:
        _clear_pending(request)
        return None, None
    uid = _parse_uuid(p.get('user_id'))
    user = User.objects.filter(pk=uid, is_active=True).first() if uid else None
    if not user:
        _clear_pending(request)
        return None, None
    if p.get('purpose') in ('enable', 'disable'):
        if not request.user.is_authenticated or request.user.pk != user.pk:
            _clear_pending(request)
            return None, None
    elif request.user.is_authenticated:
        _clear_pending(request)
        return None, None
    return p, user


def _pending_exit_url(p):
    return reverse('smartlock:login') if (p or {}).get('purpose') == 'login' else reverse('smartlock:profile')


def _lock_minutes(user) -> int:
    lock = LoginLockout.objects.filter(user=user).first()
    now = timezone.now()
    if lock and lock.locked_until and lock.locked_until > now:
        return math.ceil((lock.locked_until - now).total_seconds() / 60)
    return 0


def _fail(request, p, user, method, flash=True):
    """Ghi nhận 1 lần sai bước 2. Trả về URL cần chuyển hướng nếu phiên bị hủy, ngược lại None."""
    ip = _client_ip(request)
    p['fails'] = int(p.get('fails', 0)) + 1
    request.session[SESSION_KEY] = p
    locked = _register_failure(user, ip)
    _audit(request, 'TWO_FACTOR_FAILED', actor=None, target_user=user, success=False, severity='warning',
           metadata={'method': method, 'purpose': p.get('purpose'), 'locked_minutes': locked})
    exit_url = _pending_exit_url(p)
    if locked:
        _clear_pending(request)
        _audit(request, 'ACCOUNT_LOCKED', success=False, severity='critical', actor=None,
               target_user=user, metadata={'locked_minutes': locked, 'stage': '2fa'})
        if flash:
            messages.error(request, f'Sai quá nhiều lần. Tài khoản bị khóa {locked} phút.')
        return reverse('smartlock:login')
    if p['fails'] >= MAX_PENDING_FAILS:
        _clear_pending(request)
        if flash:
            messages.error(request, 'Sai quá nhiều lần. Vui lòng thực hiện lại từ đầu.')
        return exit_url
    if flash:
        messages.error(request, 'Mã xác thực không đúng hoặc đã hết hạn.')
    return None


def _complete(request, p, user, method):
    """Bước 2 thành công. Trả về URL đích."""
    purpose = p.get('purpose')
    _clear_pending(request)

    if purpose == 'login':
        _reset_lockout(user)
        login(request, user, backend=p.get('backend') or DEFAULT_BACKEND)
        _ensure_sync_key(request)
        request.session.set_expiry(_settings().session_timeout_hours * 3600)
        _audit(request, 'LOGIN', actor=user, metadata={'two_factor': method})
        messages.success(request, 'Đăng nhập thành công!')
        nxt = p.get('next') or ''
        if nxt and url_has_allowed_host_and_scheme(nxt, {request.get_host()}):
            return nxt
        return reverse('smartlock:dashboard')

    cfg = _get_cfg(user)
    if purpose == 'disable':
        # 2FA giờ luôn = "còn phương thức nào đang hoạt động không", không set tay được nữa.
        # Muốn tắt hẳn, user phải gỡ hết TOTP/Passkey/Email OTP (mỗi lần gỡ sẽ tự đồng bộ lại cờ này).
        messages.info(request, 'Xác thực 2 lớp được bật/tắt tự động theo phương thức bạn đang có. '
                                'Hãy gỡ hết các phương thức (Google Authenticator, Passkey, Email OTP) '
                                'ở mục bên dưới nếu muốn tắt hoàn toàn 2FA.')
    return reverse('smartlock:profile')


# ====================== TRANG XÁC THỰC 2FA (login / bật / tắt) ======================
@require_http_methods(['GET', 'POST'])
def verify_2fa(request):
    p, user = _get_pending(request)
    if not p:
        messages.error(request, 'Phiên xác thực 2FA đã hết hạn. Vui lòng thử lại.')
        return redirect('smartlock:login' if not request.user.is_authenticated else 'smartlock:profile')

    if p.get('purpose') == 'login':
        mins = _lock_minutes(user)
        if mins:
            _clear_pending(request)
            messages.error(request, f'Tài khoản đang bị khóa tạm thời. Thử lại sau {mins} phút.')
            return redirect('smartlock:login')

    cfg = _get_cfg(user)
    methods = cfg.available_methods()          # danh sách 'totp' / 'fido2' / 'email'
    backup_left = _backup_left(user)
    if not methods:
        _clear_pending(request)
        messages.error(request, 'Tài khoản chưa có phương thức 2FA khả dụng.')
        return redirect(_pending_exit_url(p))

    if request.method == 'POST':
        method = request.POST.get('method')
        code = request.POST.get('code') or ''
        ok = False
        if method == 'totp' and 'totp' in methods:
            ok = _verify_totp(cfg, code)
        elif method == 'email' and 'email' in methods:
            ok = _verify_email_code(user, code, 'VERIFY')
        elif method == 'backup' and backup_left:
            ok = _use_backup_code(user, code)
            if ok:
                left = _backup_left(user)
                _audit(request, 'TWO_FACTOR_BACKUP_USED', actor=user, target_user=user, severity='warning',
                       metadata={'left': left})
                _notify(user, 'Đã dùng mã dự phòng 2FA', f'Bạn còn {left} mã dự phòng.',
                        severity='warning', type_='SECURITY')
        else:
            messages.error(request, 'Phương thức không hợp lệ.')
            return redirect('smartlock:tf-verify')

        if ok:
            return redirect(_complete(request, p, user, method))
        exit_url = _fail(request, p, user, method)
        if exit_url:
            return redirect(exit_url)
        return redirect(f"{reverse('smartlock:tf-verify')}?tab={method}")

    order = [m for m in ('totp', 'fido2', 'email') if m in methods]
    default_tab = cfg.preferred_method if cfg.preferred_method in methods else order[0]
    tab = request.GET.get('tab')
    if tab not in methods + (['backup'] if backup_left else []):
        tab = default_tab
    title, subtitle = PURPOSE_TEXT.get(p['purpose'], PURPOSE_TEXT['login'])
    return render(request, 'account/base/verify_2fa.html', {
        'purpose': p['purpose'], 'title': title, 'subtitle': subtitle,
        'has_totp': 'totp' in methods, 'has_fido2': 'fido2' in methods, 'has_email': 'email' in methods,
        'has_backup': backup_left > 0, 'tab': tab,
        'email_masked': _mask_email(user.email),
        'cancel_url': reverse('smartlock:tf-cancel'),
    })


@require_POST
def verify_email_send(request):
    p, user = _get_pending(request)
    if not p:
        return redirect('smartlock:login')
    if not _get_cfg(user).email_otp_enabled:
        messages.error(request, 'Email OTP chưa được bật cho tài khoản này.')
        return redirect('smartlock:tf-verify')
    res = _send_email_code(user, 'VERIFY')
    if res == 'sent':
        messages.success(request, f'Đã gửi mã đến {_mask_email(user.email)}.')
    elif res == 'cooldown':
        messages.warning(request, f'Vui lòng đợi {EMAIL_CODE_COOLDOWN} giây trước khi gửi lại.')
    else:
        messages.error(request, 'Không gửi được email. Vui lòng thử lại sau.')
    _audit(request, 'TWO_FACTOR_EMAIL_SENT', actor=None, target_user=user, success=(res == 'sent'),
           metadata={'purpose': p.get('purpose')})
    return redirect(f"{reverse('smartlock:tf-verify')}?tab=email")


@require_POST
def verify_passkey_options(request):
    p, user = _get_pending(request)
    if not p:
        return JsonResponse({'ok': False, 'error': 'Phiên đã hết hạn.'}, status=400)
    creds = _cred_descriptors(user)
    if not creds:
        return JsonResponse({'ok': False, 'error': 'Chưa có passkey.'}, status=400)
    rp_id, _origin, _name = _rp(request)
    options = generate_authentication_options(
        rp_id=rp_id, allow_credentials=creds,
        user_verification=UserVerificationRequirement.PREFERRED,
    )
    request.session['webauthn_auth'] = {'challenge': bytes_to_base64url(options.challenge), 'ts': _now_ts()}
    return HttpResponse(options_to_json(options), content_type='application/json')


@require_POST
def verify_passkey_finish(request):
    p, user = _get_pending(request)
    if not p:
        return JsonResponse({'ok': False, 'error': 'Phiên đã hết hạn.', 'redirect': reverse('smartlock:login')}, status=400)
    state = request.session.pop('webauthn_auth', None)
    body = _json_body(request)
    if not state or _now_ts() - int(state.get('ts', 0)) > WEBAUTHN_TTL or not isinstance(body, dict):
        return JsonResponse({'ok': False, 'error': 'Yêu cầu không hợp lệ hoặc đã hết hạn.'}, status=400)

    credential = body.get('credential') or {}
    cred = Fido2Credential.objects.filter(user=user, credential_id=credential.get('id') or '').first()
    rp_id, origin, _name = _rp(request)
    ok = False
    if cred:
        try:
            v = verify_authentication_response(
                credential=credential,
                expected_challenge=base64url_to_bytes(state['challenge']),
                expected_rp_id=rp_id, expected_origin=origin,
                credential_public_key=bytes(cred.public_key),
                credential_current_sign_count=cred.sign_count,
                require_user_verification=False,
            )
            cred.sign_count = v.new_sign_count
            cred.last_used_at = timezone.now()
            cred.save(update_fields=['sign_count', 'last_used_at'])
            ok = True
        except Exception:
            logger.exception('verify_passkey_finish: xác thực thất bại')
    if ok:
        return JsonResponse({'ok': True, 'redirect': _complete(request, p, user, 'fido2')})
    exit_url = _fail(request, p, user, 'fido2', flash=False)
    return JsonResponse({'ok': False, 'error': 'Passkey không hợp lệ.', 'redirect': exit_url}, status=400)


def cancel_2fa(request):
    p = request.session.get(SESSION_KEY)
    _clear_pending(request)
    if isinstance(p, dict) and p.get('purpose') in ('enable', 'disable') and request.user.is_authenticated:
        return redirect('smartlock:profile')
    return redirect('smartlock:login')


# ====================== BẬT / TẮT 2FA (từ trang profile) ======================
@auth_required
@require_POST
def enable_2fa(request):
    user = request.user
    cfg = _get_cfg(user)
    if user.two_fa_enabled:
        messages.info(request, '2FA đã được bật.')
        return redirect('smartlock:profile')
    if not cfg.available_methods():
        messages.error(request, 'Hãy thiết lập ít nhất một phương thức trước khi bật 2FA.')
        return redirect('smartlock:profile')
    # Bật thẳng, không tạo phiên pending 'enable': user đã chứng minh sở hữu phương thức
    # ngay lúc xác nhận nó (totp_confirm / email_confirm / passkey_register), và
    # _after_method_added() đã tự sync cờ two_fa_enabled=True ngay sau đó rồi - nghĩa là
    # nhánh "if user.two_fa_enabled" phía trên luôn đúng trước khi tới được đây, nên phiên
    # pending 'enable' cũ không bao giờ thực sự chạy tới.
    sync_two_fa_flag(user)
    cfg.enabled_at = timezone.now()
    cfg.save(update_fields=['enabled_at', 'updated_at'])
    _audit(request, 'TWO_FACTOR_ENABLED', target_user=user, severity='warning')
    _notify(user, 'Đã bật xác thực 2 lớp', 'Tài khoản của bạn giờ được bảo vệ bằng 2FA.',
            severity='info', type_='SECURITY')
    messages.success(request, 'Đã bật xác thực 2 lớp.')
    return redirect('smartlock:profile')


@auth_required
@require_POST
def disable_2fa(request):
    if not request.user.two_fa_enabled:
        return redirect('smartlock:profile')
    if not _require_password(request):
        return redirect('smartlock:profile')
    _start_pending(request, request.user, 'disable')
    return redirect('smartlock:tf-verify')


# ====================== THIẾT LẬP GOOGLE AUTHENTICATOR (TOTP) ======================
@auth_required
@require_POST
def totp_begin(request):
    cfg = _get_cfg(request.user)
    if cfg.totp_confirmed:
        messages.error(request, 'Google Authenticator đã được thiết lập. Hãy gỡ trước nếu muốn cài lại.')
        return redirect('smartlock:profile')
    secret = pyotp.random_base32()
    request.session['totp_setup'] = {
        'secret': fernet.encrypt(secret.encode()).decode(),
        'token': secrets.token_urlsafe(24),      # setup_token dùng 1 lần, chống race/CSRF chéo phiên
        'ts': _now_ts(), 'tries': 0,
    }
    return redirect('smartlock:profile')


@auth_required
@require_POST
def totp_cancel(request):
    request.session.pop('totp_setup', None)
    return redirect('smartlock:profile')


def _read_totp_setup(request):
    s = request.session.get('totp_setup')
    if not isinstance(s, dict) or _now_ts() - int(s.get('ts', 0)) > SETUP_TTL:
        request.session.pop('totp_setup', None)
        return None
    try:
        return {**s, 'plain': fernet.decrypt(s['secret'].encode()).decode()}
    except Exception:
        request.session.pop('totp_setup', None)
        return None


@auth_required
@require_POST
def totp_confirm(request):
    user = request.user
    s = _read_totp_setup(request)
    if not s:
        messages.error(request, 'Phiên thiết lập đã hết hạn. Hãy bắt đầu lại.')
        return redirect('smartlock:profile')
    if not hmac.compare_digest(str(s['token']), request.POST.get('setup_token') or ''):
        request.session.pop('totp_setup', None)
        _audit(request, 'TWO_FACTOR_SETUP_TOKEN_BAD', success=False, severity='warning', target_user=user)
        messages.error(request, 'Phiên thiết lập không hợp lệ. Hãy bắt đầu lại.')
        return redirect('smartlock:profile')

    code = _digits(request.POST.get('code'))
    totp = pyotp.TOTP(s['plain'])
    step_now = int(timezone.now().timestamp() // totp.interval)
    matched = None
    for offset in (-1, 0, 1):
        if len(code) == 6 and hmac.compare_digest(totp.at((step_now + offset) * totp.interval), code):
            matched = step_now + offset
    if matched is None:
        s['tries'] = int(s.get('tries', 0)) + 1
        if s['tries'] >= 5:
            request.session.pop('totp_setup', None)
            messages.error(request, 'Sai quá nhiều lần. Hãy bắt đầu thiết lập lại.')
        else:
            request.session['totp_setup'] = {k: s[k] for k in ('secret', 'token', 'ts', 'tries')}
            messages.error(request, 'Mã không đúng. Kiểm tra lại giờ trên điện thoại và thử lại.')
        return redirect('smartlock:profile')

    with transaction.atomic():
        cfg = TwoFactorConfig.objects.select_for_update().get_or_create(user=user)[0]
        cfg.set_totp_secret(s['plain'])
        cfg.totp_confirmed = True
        cfg.totp_last_step = matched
        if not cfg.preferred_method:
            cfg.preferred_method = TwoFactorConfig.METHOD_TOTP
        cfg.save()
    request.session.pop('totp_setup', None)
    _after_method_added(request, user, 'totp')
    return redirect('smartlock:profile')


def _after_method_added(request, user, method):
    """Ghi log, thông báo, và tạo mã dự phòng lần đầu (hiển thị 1 lần ở trang profile)."""
    _audit(request, 'TWO_FACTOR_METHOD_ADDED', target_user=user, severity='warning', metadata={'method': method})
    _notify(user, 'Đã thêm phương thức 2FA', f'Phương thức {method.upper()} vừa được thêm vào tài khoản.',
            severity='info', type_='SECURITY')
    if not TwoFactorBackupCode.objects.filter(user=user).exists():
        request.session['new_backup_codes'] = _new_backup_codes(user)
    # Phương thức ĐẦU TIÊN vừa xác nhận xong -> tự bật 2FA luôn (user đã chứng minh sở hữu phương thức).
    cfg = _get_cfg(user)
    was_enabled = user.two_fa_enabled
    now_enabled = sync_two_fa_flag(user)
    auto = now_enabled and not was_enabled
    if auto:
        cfg.enabled_at = timezone.now()
        cfg.save(update_fields=['enabled_at', 'updated_at'])
        _audit(request, 'TWO_FACTOR_ENABLED', target_user=user, severity='warning',
               metadata={'method': method, 'auto': True})
    messages.success(request, 'Đã thêm phương thức xác thực và bật 2FA. Từ lần đăng nhập sau bạn sẽ được yêu cầu xác thực.'
                     if auto else 'Đã thêm phương thức xác thực.')


# ====================== EMAIL OTP ======================
@auth_required
@require_POST
def email_send(request):
    user = request.user
    if not user.email_verified:
        messages.error(request, 'Email chưa được xác thực.')
        return redirect('smartlock:profile')
    res = _send_email_code(user, 'SETUP')
    if res == 'sent':
        request.session['email_setup_pending'] = _now_ts()
        messages.success(request, f'Đã gửi mã đến {_mask_email(user.email)}.')
    elif res == 'cooldown':
        request.session['email_setup_pending'] = _now_ts()
        messages.warning(request, f'Vui lòng đợi {EMAIL_CODE_COOLDOWN} giây trước khi gửi lại.')
    else:
        messages.error(request, 'Không gửi được email. Vui lòng thử lại sau.')
    return redirect('smartlock:profile')


@auth_required
@require_POST
def email_confirm(request):
    user = request.user
    if _verify_email_code(user, request.POST.get('code'), 'SETUP'):
        with transaction.atomic():
            cfg = TwoFactorConfig.objects.select_for_update().get_or_create(user=user)[0]
            cfg.email_otp_enabled = True
            if not cfg.preferred_method:
                cfg.preferred_method = TwoFactorConfig.METHOD_EMAIL
            cfg.save()
        request.session.pop('email_setup_pending', None)
        _after_method_added(request, user, 'email')
    else:
        messages.error(request, 'Mã không đúng hoặc đã hết hạn.')
    return redirect('smartlock:profile')


# ====================== PASSKEY / FIDO2 ======================
@auth_required
@require_POST
def passkey_register_options(request):
    user = request.user
    rp_id, _origin, rp_name = _rp(request)
    options = generate_registration_options(
        rp_id=rp_id, rp_name=rp_name,
        user_id=user.pk.bytes, user_name=user.email,
        user_display_name=user.full_name or user.username,
        exclude_credentials=_cred_descriptors(user),
        authenticator_selection=AuthenticatorSelectionCriteria(
            resident_key=ResidentKeyRequirement.PREFERRED,
            user_verification=UserVerificationRequirement.PREFERRED,
        ),
    )
    request.session['webauthn_reg'] = {'challenge': bytes_to_base64url(options.challenge), 'ts': _now_ts()}
    return HttpResponse(options_to_json(options), content_type='application/json')


@auth_required
@require_POST
def passkey_register(request):
    user = request.user
    state = request.session.pop('webauthn_reg', None)
    body = _json_body(request)
    if not state or _now_ts() - int(state.get('ts', 0)) > WEBAUTHN_TTL or not isinstance(body, dict):
        return JsonResponse({'ok': False, 'error': 'Yêu cầu không hợp lệ hoặc đã hết hạn.'}, status=400)
    credential = body.get('credential') or {}
    rp_id, origin, _name = _rp(request)
    try:
        v = verify_registration_response(
            credential=credential,
            expected_challenge=base64url_to_bytes(state['challenge']),
            expected_rp_id=rp_id, expected_origin=origin,
            require_user_verification=False,
        )
    except Exception:
        logger.exception('passkey_register: xác minh thất bại')
        return JsonResponse({'ok': False, 'error': 'Không xác minh được passkey.'}, status=400)

    cred_id = bytes_to_base64url(v.credential_id)
    if len(cred_id) > 512 or Fido2Credential.objects.filter(credential_id=cred_id).exists():
        return JsonResponse({'ok': False, 'error': 'Passkey này đã được đăng ký.'}, status=400)
    transports = body.get('transports') if isinstance(body.get('transports'), list) else []
    with transaction.atomic():
        Fido2Credential.objects.create(
            user=user, credential_id=cred_id, public_key=v.credential_public_key,
            sign_count=v.sign_count, transports=[str(t)[:20] for t in transports][:8],
            name=((body.get('name') or '').strip()[:100] or 'Passkey'),
        )
        cfg = _get_cfg(user)
        if not cfg.preferred_method:
            cfg.preferred_method = TwoFactorConfig.METHOD_FIDO2
            cfg.save(update_fields=['preferred_method', 'updated_at'])
    _after_method_added(request, user, 'fido2')
    return JsonResponse({'ok': True})


@auth_required
@require_POST
def passkey_delete(request, cred_id):
    user = request.user
    cfg = _get_cfg(user)
    cred = Fido2Credential.objects.filter(pk=cred_id, user=user).first()
    if not cred:
        messages.error(request, 'Không tìm thấy passkey.')
        return redirect('smartlock:profile')
    if user.two_fa_enabled and len(cfg.available_methods()) == 1 and user.fido2_credentials.count() == 1:
        messages.error(request, 'Đây là phương thức cuối cùng. Hãy tắt 2FA trước khi gỡ.')
        return redirect('smartlock:profile')
    if not _require_password(request):
        return redirect('smartlock:profile')
    cred.delete()
    _after_method_removed(request, user, 'fido2')
    return redirect('smartlock:profile')


# ====================== GỠ PHƯƠNG THỨC / MÃ DỰ PHÒNG ======================
@auth_required
@require_POST
def remove_method(request, method):
    user = request.user
    cfg = _get_cfg(user)
    if method not in ('totp', 'email'):
        messages.error(request, 'Phương thức không hợp lệ.')
        return redirect('smartlock:profile')
    active = (cfg.totp_confirmed if method == 'totp' else cfg.email_otp_enabled)
    if not active:
        return redirect('smartlock:profile')
    if user.two_fa_enabled and cfg.available_methods() == [method]:
        messages.error(request, 'Đây là phương thức cuối cùng. Hãy tắt 2FA trước khi gỡ.')
        return redirect('smartlock:profile')
    if not _require_password(request):
        return redirect('smartlock:profile')
    if method == 'totp':
        cfg.totp_secret_encrypted = ''
        cfg.totp_confirmed = False
        cfg.totp_last_step = 0
    else:
        cfg.email_otp_enabled = False
    cfg.save()
    _after_method_removed(request, user, method)
    return redirect('smartlock:profile')


def _after_method_removed(request, user, method):
    cfg = _get_cfg(user)
    left = cfg.available_methods()
    if cfg.preferred_method not in left:
        cfg.preferred_method = left[0] if left else ''
    cfg.save()
    if not sync_two_fa_flag(user):
        TwoFactorBackupCode.objects.filter(user=user).delete()
    _audit(request, 'TWO_FACTOR_METHOD_REMOVED', target_user=user, severity='warning', metadata={'method': method})
    _notify(user, 'Đã gỡ phương thức 2FA', f'Phương thức {method.upper()} vừa được gỡ khỏi tài khoản.',
            severity='warning', type_='SECURITY')
    messages.success(request, 'Đã gỡ phương thức xác thực.')


@auth_required
@require_POST
def backup_regenerate(request):
    user = request.user
    if not _get_cfg(user).available_methods():
        messages.error(request, 'Cần thiết lập ít nhất một phương thức trước.')
        return redirect('smartlock:profile')
    if not _require_password(request):
        return redirect('smartlock:profile')
    request.session['new_backup_codes'] = _new_backup_codes(user)
    _audit(request, 'TWO_FACTOR_BACKUP_REGEN', target_user=user, severity='warning')
    messages.success(request, 'Đã tạo mã dự phòng mới. Mã cũ không còn dùng được.')
    return redirect('smartlock:profile')


# ====================== CONTEXT CHO TRANG PROFILE ======================
def two_factor_context(request, user):
    cfg = TwoFactorConfig.objects.filter(user=user).first()
    passkeys = list(Fido2Credential.objects.filter(user=user).order_by('created_at'))
    ctx = {
        'tf_enabled': user.two_fa_enabled,
        'tf_totp': bool(cfg and cfg.totp_confirmed),
        'tf_email': bool(cfg and cfg.email_otp_enabled),
        'tf_passkeys': passkeys,
        'tf_has_method': bool(cfg and cfg.available_methods()),
        'tf_backup_left': _backup_left(user),
        'tf_email_pending': False,
        'tf_totp_setup': None,
        'tf_new_backup_codes': request.session.pop('new_backup_codes', None),
        'tf_email_masked': _mask_email(user.email),
        'tf_email_verified': user.email_verified,
    }
    ts = request.session.get('email_setup_pending')
    if ts and _now_ts() - int(ts) <= EMAIL_CODE_TTL_MIN * 60 and not ctx['tf_email']:
        ctx['tf_email_pending'] = True
    setup = _read_totp_setup(request)
    if setup and not ctx['tf_totp']:
        uri = pyotp.TOTP(setup['plain']).provisioning_uri(name=user.email, issuer_name=TOTP_ISSUER)
        ctx['tf_totp_setup'] = {
            'qr': _qr_data_uri(uri),
            'secret': ' '.join(setup['plain'][i:i + 4] for i in range(0, len(setup['plain']), 4)),
            'token': setup['token'],
        }
    return ctx