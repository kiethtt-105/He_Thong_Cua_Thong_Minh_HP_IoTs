# smartlock/views.py
import hashlib
import hmac
import ipaddress
import logging
import math
import re
import secrets
import uuid
from datetime import datetime, timedelta
from urllib.parse import urlencode

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
from django.http import JsonResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.urls import reverse
from django.utils import timezone
from django.utils.encoding import force_bytes, force_str
from django.utils.http import (
    url_has_allowed_host_and_scheme, urlsafe_base64_decode, urlsafe_base64_encode,
)
from django.views.decorators.http import require_POST

from .utils import SmartlockUtils
from .email_templates import render_email
from .models import (
    AccessCard, Announcement, AuditLog, CardDeviceAccess, Device, DeviceAccess,
    DeviceCommand, DeviceStatusLog, EmailVerificationToken, LoginAttemptLog,
    LoginLockout, NfcLog, NfcReader, NfcReaderConfig, Notification, Permission,
    ShareAccessCode, SupportRequest, SystemSettings, User, fernet,
)

logger = logging.getLogger('smartlock.views')

# ====================== CONSTANTS ======================
# From lấy từ settings.DEFAULT_FROM_EMAIL (Bizfly/Gmail đều yêu cầu From trùng tài khoản gửi)
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
def _send_mail(subject, plain, html, to):
    logger.info("send_mail: to=%s subject=%r plain_preview=%r", to, subject, plain[:200])
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
    active = list(ShareAccessCode.objects.filter(expires_at__gt=timezone.now()))
    for _ in range(20):
        plain = f'{secrets.randbelow(10 ** 6):06d}'
        if not any(c.check_code(plain) for c in active):
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
        _reset_lockout(auth_user)
        login(request, auth_user)
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
    _audit(request, f'CMD_{command}', device=device, metadata={'command_id': str(cmd.id)})
    labels = {'LOCK': 'Khóa', 'UNLOCK': 'Mở khóa', 'REBOOT': 'Khởi động lại'}
    return JsonResponse({'ok': True, 'command_id': str(cmd.id),
                         'message': f'Đã gửi lệnh {labels.get(command, command)} tới "{device.name}".'})


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
        try:
            c.plain = fernet.decrypt(c.code_encrypted.encode()).decode()
        except Exception:
            c.plain = '------'
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
            for c in ShareAccessCode.objects.filter(expires_at__gt=now).select_related('device'):
                if c.check_code(plain):
                    match = c
                    break

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