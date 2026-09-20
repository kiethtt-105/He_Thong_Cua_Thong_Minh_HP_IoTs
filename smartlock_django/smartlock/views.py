# smartlock/views.py
import hashlib
import hmac
import logging
import math
import re
import secrets
import uuid
from datetime import datetime, timedelta

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
FROM_EMAIL = 'no-reply@smartlock.com'
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
        n = send_mail(subject, plain, FROM_EMAIL, [to], html_message=html)
        logger.info("send_mail: OK (%s mail) -> %s", n, to)
        return True
    except Exception:
        logger.exception("send_mail: THẤT BẠI -> %s", to)
        return False

def _hash_token(token) -> str:
    return hashlib.sha256(str(token).encode()).hexdigest()

def _client_ip(request):
    xff = request.META.get('HTTP_X_FORWARDED_FOR')
    ip = xff.split(',')[0].strip() if xff else request.META.get('REMOTE_ADDR')
    return ip or '0.0.0.0'

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

def _pick_device(queryset, raw_id):
    dev_id = _parse_uuid(raw_id)
    device = queryset.filter(id=dev_id).first() if dev_id else None
    return device or queryset.first()

def _ensure_default_permissions():
    if not Permission.objects.exists():
        for code, name, desc, sensitive in DEFAULT_PERMISSIONS:
            Permission.objects.get_or_create(
                code=code, defaults={'name': name, 'description': desc, 'is_sensitive': sensitive},
            )

def _redirect_with(url_name, **params):
    url = reverse(url_name)
    if params:
        url += '?' + '&'.join(f'{k}={v}' for k, v in params.items())
    return redirect(url)

def _register_failure(user, ip):
    st = _settings()
    stages = st.login_lockout_stage_minutes or [5, 10, 30]
    now = timezone.now()
    lock, _ = LoginLockout.objects.get_or_create(user=user)
    lock.failed_attempts += 1
    lock.last_failed_at = now
    lock.last_failed_ip = ip
    if lock.failed_attempts >= MAX_FAILED_ATTEMPTS:
        minutes = stages[min(lock.stage, len(stages) - 1)]
        lock.locked_until = now + timedelta(minutes=minutes)
        lock.stage += 1
        lock.failed_attempts = 0
        _notify(user, 'Tài khoản bị khóa tạm thời',
                f'Đăng nhập sai nhiều lần từ IP {ip}. Tài khoản bị khóa {minutes} phút.',
                severity='critical', type_='LOGIN_LOCKOUT')
    lock.save()

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
        if request.user.is_admin:
            return redirect('smartlock:manage-sys-dashboard')
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

    LoginAttemptLog.objects.create(
        identifier=identifier[:255], user=user, ip_address=ip,
        user_agent=_user_agent(request), success=bool(auth_user),
    )

    if auth_user:
        _reset_lockout(auth_user)
        login(request, auth_user)
        request.session.set_expiry(_settings().session_timeout_hours * 3600)
        _audit(request, 'LOGIN' if not auth_user.is_admin else 'MANAGE_LOGIN', actor=auth_user)
        messages.success(request, 'Đăng nhập thành công!')

        if next_url and url_has_allowed_host_and_scheme(next_url, {request.get_host()}):
            return redirect(next_url)

        if auth_user.is_admin:
            return redirect('smartlock:manage-sys-dashboard')
        return redirect('smartlock:dashboard')

    if user and not user.is_active and user.check_password(password):
        messages.warning(request, 'Tài khoản chưa được kích hoạt. Vui lòng xác thực email.')
    else:
        if user:
            _register_failure(user, ip)
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
        messages.error(request, 'Không thể tạo tài khoản: ' + ' '.join(e.messages))
        return render(request, 'account/base/register.html', ctx)
    except (IntegrityError, ValueError) as e:
        messages.error(request, f'Không thể tạo tài khoản: {e}')
        return render(request, 'account/base/register.html', ctx)

    logger.info("register: tạo user %s", email)
    _audit(request, 'REGISTER', actor=user, target_user=user)
    _send_verification(request, user)
    return render(request, 'account/base/verify_email.html', {'email': email})


def verify_email(request, token):
    try:
        vt = EmailVerificationToken.objects.select_related('user').get(
            token_hash=_hash_token(token), purpose='EMAIL_VERIFY',
            is_used=False, expires_at__gt=timezone.now(),
        )
    except EmailVerificationToken.DoesNotExist:
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
            _send_verification(request, user)
            messages.success(request, 'Đã gửi lại email xác thực.')
    else:
        messages.success(request, 'Nếu tài khoản cần xác thực, email đã được gửi lại.')
    return render(request, 'account/base/verify_email.html', {'email': email})


def password_reset_request(request):
    if request.method == 'POST':
        email = (request.POST.get('email') or '').strip()
        user = User.objects.filter(email__iexact=email, is_active=True).first()
        if user:
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
            _send_mail(subject, plain, html, user.email)
            _audit(request, 'PASSWORD_RESET_REQUEST', actor=None, target_user=user)
        messages.success(request, 'Nếu email tồn tại, link đặt lại mật khẩu đã được gửi.')
    return render(request, 'account/base/reset_password.html', {'mode': 'request'})


def reset_password(request, uidb64, token):
    try:
        user = User.objects.get(pk=force_str(urlsafe_base64_decode(uidb64)))
    except Exception:
        user = None

    if user is None or not user.is_active or not default_token_generator.check_token(user, token):
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
        AuditLog.objects.filter(actor_user=user, created_at__date__gte=days[0])
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
        'recent_logs': AuditLog.objects.filter(actor_user=user).order_by('-created_at')[:6],
        'announcements': Announcement.objects.filter(is_active=True).order_by('-created_at')[:3],
        'chart_data': chart_data,
    }
    return render(request, 'account/base/dashboard.html', context)


# ====================== DEVICES ======================
@auth_required
def device_add(request):
    if request.method == 'POST':
        name = (request.POST.get('name') or '').strip()
        if not name:
            messages.error(request, 'Tên thiết bị không được để trống.')
            return redirect('smartlock:devices-list')

        # Tạo device code tự động (dễ mở rộng)
        device_code = f'DEV-{secrets.token_hex(4).upper()}'
        while Device.objects.filter(device_code=device_code).exists():
            device_code = f'DEV-{secrets.token_hex(4).upper()}'

        device = Device.objects.create(
            name=name,
            device_code=device_code,
            provisioning_secret_hash=secrets.token_hex(32),
            status='provisioning',
            owner=request.user,
            bluetooth_enabled=True,
            wifi_enabled=True,
            nfc_enabled=True,
            battery_level=100,
        )

        _audit(request, 'DEVICE_ADDED', device=device, actor=request.user)
        _notify(request.user, 'Thiết bị mới đã được tạo',
                f'Dữ liệu thiết bị đã được khởi tạo. Vui lòng cấu hình device code: {device_code}')

        messages.success(request, f'Đã thêm thiết bị "{name}" thành công!')
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
            messages.error(request, 'Chỉ chủ thiết bị mới được chỉnh sửa.')
            return redirect('smartlock:device-detail', device_id=device.id)
        name = (request.POST.get('name') or '').strip()
        if not name:
            messages.error(request, 'Tên thiết bị không được để trống.')
        else:
            device.name = name[:100]
            device.location = (request.POST.get('location') or '').strip()[:255] or None
            device.wifi_enabled = 'wifi_enabled' in request.POST
            device.bluetooth_enabled = 'bluetooth_enabled' in request.POST
            device.nfc_enabled = 'nfc_enabled' in request.POST
            device.save()
            _audit(request, 'DEVICE_UPDATED', device=device)
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
        return JsonResponse({'ok': False, 'message': 'Lệnh không hợp lệ.'}, status=400)

    needed = ALLOWED_COMMANDS[command]
    allowed = (device.owner_id == request.user.id) if needed is None \
        else _has_permission(request.user, device, needed)
    if not allowed:
        _audit(request, f'CMD_{command}_DENIED', device=device, success=False, severity='warning')
        return JsonResponse({'ok': False, 'message': 'Bạn không có quyền thực hiện lệnh này.'}, status=403)
    if device.status != 'online':
        return JsonResponse({'ok': False, 'message': 'Thiết bị đang không online.'}, status=409)

    cmd = DeviceCommand.objects.create(
        device=device, issued_by=request.user, command_type=command, status='pending',
        command_token_hash=_hash_token(secrets.token_urlsafe(32)),
        expires_at=timezone.now() + timedelta(seconds=COMMAND_TTL_SECONDS),
    )
    _audit(request, f'CMD_{command}', device=device, metadata={'command_id': str(cmd.id)})
    labels = {'LOCK': 'Khóa', 'UNLOCK': 'Mở khóa', 'REBOOT': 'Khởi động lại'}
    return JsonResponse({'ok': True, 'command_id': str(cmd.id),
                         'message': f'Đã gửi lệnh {labels[command]} tới "{device.name}".'})


# ====================== NFC ======================
@auth_required
def nfc_tags(request):
    if request.method == 'POST':
        action = request.POST.get('action')
        card_id = _parse_uuid(request.POST.get('card_id'))
        card = AccessCard.objects.filter(id=card_id, user=request.user).first() if card_id else None
        if not card:
            messages.error(request, 'Không tìm thấy thẻ.')
        elif action == 'toggle':
            card.is_active = not card.is_active
            card.save()
            _audit(request, 'CARD_ENABLED' if card.is_active else 'CARD_DISABLED')
            messages.success(request, 'Đã kích hoạt thẻ.' if card.is_active else 'Đã vô hiệu hóa thẻ.')
        elif action == 'rename':
            card.name = (request.POST.get('name') or '').strip()[:100] or None
            card.save()
            messages.success(request, 'Đã đổi tên thẻ.')
        elif action == 'delete':
            card.delete()
            _audit(request, 'CARD_DELETED')
            messages.success(request, 'Đã xóa thẻ.')
        return redirect('smartlock:nfc-tags')

    cards = (AccessCard.objects.filter(user=request.user)
             .prefetch_related('carddeviceaccess_set__device').order_by('-created_at'))
    return render(request, 'account/nfc/tags.html', {'access_cards': cards})


@auth_required
def nfc_reader(request):
    devices = Device.objects.filter(owner=request.user).order_by('name')
    device = _pick_device(devices, request.POST.get('device') or request.GET.get('device'))

    if not device or device.owner_id != request.user.id:
        messages.error(request, 'Không tìm thấy thiết bị hoặc bạn không phải chủ.')
        return redirect('smartlock:nfc-reader')

    if request.method == 'POST' and device:
        action = request.POST.get('action')
        back = lambda: _redirect_with('smartlock:nfc-reader', device=device.id)

        if action == 'add_reader':
            name = (request.POST.get('name') or '').strip()[:100] or 'Đầu đọc mô phỏng'
            reader = NfcReader.objects.create(device=device, reader_mode='simulated',
                                              name=name, is_active=True)
            NfcReaderConfig.objects.create(reader=reader)
            NfcLog.objects.create(reader=reader, device=device, user=request.user,
                                  event_type='READER_CONNECTED', ip_address=_client_ip(request),
                                  user_agent=_user_agent(request))
            messages.success(request, 'Đã thêm đầu đọc.')
            return back()

        if action in ('toggle_reader', 'toggle_auto'):
            reader = NfcReader.objects.filter(id=_parse_uuid(request.POST.get('reader_id')),
                                              device=device).first()
            if not reader:
                messages.error(request, 'Không tìm thấy đầu đọc.')
                return back()
            if action == 'toggle_reader':
                reader.is_active = not reader.is_active
                reader.save()
                event = 'READER_CONNECTED' if reader.is_active else 'READER_DISCONNECTED'
            else:
                cfg, _ = NfcReaderConfig.objects.get_or_create(reader=reader)
                cfg.auto_register = not cfg.auto_register
                cfg.save()
                event = 'CONFIG_UPDATED'
            NfcLog.objects.create(reader=reader, device=device, user=request.user, event_type=event,
                                  ip_address=_client_ip(request), user_agent=_user_agent(request))
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
                messages.error(request, 'Thẻ này đã được đăng kỳ.')
                return back()
            reader = NfcReader.objects.filter(device=device, is_active=True).first()
            NfcLog.objects.create(reader=reader, nfc_tag=card, device=device, user=request.user,
                                  event_type='CARD_REGISTER', ip_address=_client_ip(request),
                                  user_agent=_user_agent(request))
            _audit(request, 'CARD_REGISTERED', device=device)
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
    owned = Device.objects.filter(owner=user).order_by('name')

    if request.method == 'POST':
        action = request.POST.get('action')
        if action == 'create':
            device = owned.filter(id=_parse_uuid(request.POST.get('device_id'))).first()
            if not device or device.owner_id != user.id:
                messages.error(request, 'Vui lòng chọn thiết bị của bạn.')
                return redirect('smartlock:share-codes')
            else:
                try:
                    minutes = int(request.POST.get('minutes') or _settings().share_code_expiry_minutes)
                    if not 1 <= minutes <= 1440:
                        raise ValueError
                except ValueError:
                    messages.error(request, 'Thời hạn phải từ 1 đến 1440 phút.')
                    return redirect('smartlock:share-codes')
                perms = Permission.objects.filter(code__in=request.POST.getlist('permissions'))
                code = ShareAccessCode(device=device, created_by=user,
                                       expires_at=timezone.now() + timedelta(minutes=minutes))
                plain = f'{secrets.randbelow(10 ** 6):06d}'
                code.set_code(plain)
                code.save()
                code.permissions.set(perms)
                _audit(request, 'SHARE_CODE_CREATED', device=device)
                messages.success(request, f'Đã tạo mã chia sẻ {plain} (hết hạn sau {minutes} phút).')
        elif action == 'delete':
            deleted, _ = ShareAccessCode.objects.filter(
                id=_parse_uuid(request.POST.get('code_id')), device__owner=user).delete()
            if deleted:
                _audit(request, 'SHARE_CODE_DELETED')
                messages.success(request, 'Đã xóa mã chia sẻ.')
        return redirect('smartlock:share-codes')

    _ensure_default_permissions()
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
        'default_minutes': _settings().share_code_expiry_minutes,
    }
    return render(request, 'account/share/codes.html', context)


@auth_required
def share_request(request):
    user = request.user
    if request.method == 'POST':
        plain = re.sub(r'\D', '', request.POST.get('code') or '')
        window = timezone.now() - timedelta(minutes=15)
        fails = AuditLog.objects.filter(actor_user=user, action='SHARE_CODE_REDEEMED',
                                        created_at__gte=window).count()
        if fails >= 5:
            messages.error(request, 'Bạn nhập sai quá nhiều lần. Vui lòng thử lại sau 15 phút.')
            return redirect('smartlock:share-request')

        match = None
        if len(plain) == 6:
            for c in (ShareAccessCode.objects.filter(expires_at__gt=timezone.now())
                      .select_related('device')):
                if c.check_code(plain):
                    match = c
                    break

        if not match:
            _audit(request, 'SHARE_CODE_REDEEM_FAILED', success=False, severity='warning')
            messages.error(request, 'Mã chia sẻ không đúng hoặc đã hết hạn.')
        elif match.device.owner_id == user.id:
            messages.error(request, 'Đây là thiết bị của chính bạn.')
        else:
            now = timezone.now()
            access = DeviceAccess.objects.create(
                device=match.device, user=user, source='SHARE_CODE', accepted=True,
                valid_from=now, expires_at=now + timedelta(hours=SHARED_ACCESS_HOURS),
                created_by=match.created_by,
            )
            access.permissions.set(match.permissions.all())
            _audit(request, 'SHARE_CODE_REDEEMED', device=match.device, target_user=match.created_by)
            _notify(match.created_by, 'Mã chia sẻ đã được sử dụng',
                    f'{user.username} đã nhận quyền truy cập "{match.device.name}".',
                    device=match.device, type_='SHARE')
            match.delete()
            messages.success(request, f'Đã nhận quyền truy cập thiết bị "{access.device.name}".')
            _reset_lockout(user)
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
    if request.method == 'POST':
        device = Device.objects.filter(id=_parse_uuid(request.POST.get('device_id')), owner=user).first()
        action = request.POST.get('action')
        if not device or device.owner_id != user.id:
            messages.error(request, 'Không phải thiết bị của bạn.')
            return redirect('smartlock:support-requests')

        auth_code = secrets.token_hex(4).upper()
        recovery = secrets.token_hex(4).upper() if action in RECOVERY_ACTIONS else None
        sr = SupportRequest.objects.create(
            device=device, requested_by=user, action=action,
            scope=(request.POST.get('scope') or '').strip()[:100] or None,
            authorization_code_hash=_hash_token(auth_code),
            recovery_code_hash=_hash_token(recovery) if recovery else None,
            expires_at=timezone.now() + timedelta(hours=SUPPORT_TTL_HOURS),
        )
        _audit(request, 'SUPPORT_REQUEST_CREATED', device=device, metadata={'action': action})
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
        if sr.status == 'pending':
            sr.status = 'cancelled'
            sr.completed_at = timezone.now()
            sr.save()
            _audit(request, 'SUPPORT_REQUEST_CANCELLED', device=sr.device)
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
    devices = Device.objects.filter(owner=user).order_by('name')
    device = _pick_device(devices, request.POST.get('device') or request.GET.get('device'))

    if request.method == 'POST' and device:
        if device.owner_id != user.id:
            messages.error(request, 'Chỉ chủ thiết bị mới được cấp quyền.')
            return redirect('smartlock:permissions-manage', device=device.id)
        action = request.POST.get('action')
        back = lambda: _redirect_with('smartlock:permissions-manage', device=device.id)
        perms = Permission.objects.filter(code__in=request.POST.getlist('permissions'))

        if action == 'grant':
            target = _find_user(request.POST.get('identifier'))
            expires = _parse_dt(request.POST.get('expires_at'))
            if not target or not target.is_active:
                messages.error(request, 'Không tìm thấy người dùng (email hoặc username).')
            elif target.id == user.id:
                messages.error(request, 'Bạn đã là chủ thiết bị này.')
            elif expires and expires <= timezone.now():
                messages.error(request, 'Thời điểm hết hạn phải ở tương lai.')
            else:
                access, created = DeviceAccess.objects.get_or_create(
                    device=device, user=target, is_active=True,
                    defaults={'created_by': user, 'accepted': True, 'source': 'DIRECT',
                              'expires_at': expires},
                )
                if not created:
                    access.expires_at = expires
                    access.save()
                access.permissions.set(perms)
                _audit(request, 'ACCESS_GRANTED', device=device, target_user=target,
                       metadata={'permissions': [p.code for p in perms]})
                _notify(target, 'Bạn được cấp quyền thiết bị',
                        f'{user.username} đã cấp quyền cho bạn trên "{device.name}".',
                        device=device, type_='ACCESS')
                messages.success(request, f'Đã cấp quyền cho {target.username}.')
        elif action in ('update', 'revoke'):
            access = DeviceAccess.objects.filter(id=_parse_uuid(request.POST.get('access_id')),
                                                 device=device, is_active=True).first()
            if not access:
                messages.error(request, 'Không tìm thấy quyền truy cập.')
            elif action == 'update':
                access.permissions.set(perms)
                _audit(request, 'ACCESS_UPDATED', device=device, target_user=access.user)
                messages.success(request, 'Đã cập nhật quyền.')
            else:
                access.is_active = False
                access.revoked_at = timezone.now()
                access.save()
                _audit(request, 'ACCESS_REVOKED', device=device, target_user=access.user,
                       severity='warning')
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
        except (TypeError, ValueError):
            messages.error(request, 'Giá trị không hợp lệ. Các số phải là số nguyên dương.')
            return redirect('smartlock:settings-system')

        st.registration_enabled = 'registration_enabled' in request.POST
        st.verification_token_expiry_minutes = expiry
        st.share_code_expiry_minutes = share
        st.session_timeout_hours = timeout
        st.login_lockout_stage_minutes = stages
        st.ip_whitelist = (request.POST.get('ip_whitelist') or '').strip()
        st.ip_blacklist = (request.POST.get('ip_blacklist') or '').strip()
        st.updated_by = request.user
        st.save()
        _audit(request, 'SETTINGS_UPDATED', severity='warning')
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
        return redirect(request.META.get('HTTP_REFERER') or 'smartlock:notifications')

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
            user.full_name = (request.POST.get('full_name') or '').strip()[:100] or None
            user.phone = (request.POST.get('phone') or '').strip()[:20] or None
            user.save()
            _audit(request, 'PROFILE_UPDATED')
            messages.success(request, 'Đã cập nhật thông tin cá nhân.')
        elif action == 'change_password':
            old = request.POST.get('old_password') or ''
            p1 = request.POST.get('new_password1') or ''
            p2 = request.POST.get('new_password2') or ''
            if not user.check_password(old):
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
                    _audit(request, 'PASSWORD_CHANGED', severity='warning')
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
    show_all = _is_admin(request.user) and request.GET.get('all') == '1'
    qs = AuditLog.objects.select_related('device', 'actor_user').order_by('-created_at')
    if not show_all:
        qs = qs.filter(actor_user=request.user)

    status = request.GET.get('status')
    if status == 'ok':
        qs = qs.filter(success=True)
    elif status == 'fail':
        qs = qs.filter(success=False)
    q = (request.GET.get('q') or '').strip()
    if q:
        qs = qs.filter(action__icontains=q)

    extra = ''.join(f'&{k}={v}' for k, v in
                    (('status', status), ('q', q), ('all', '1' if show_all else '')) if v)
    context = {'audit_logs': _page(request, qs), 'show_all': show_all,
               'status': status or '', 'q': q, 'qs': extra, 'can_see_all': _is_admin(request.user)}
    return render(request, 'account/audit/logs.html', context)



@require_POST
def admin_logout(request):
    _audit(request, 'ADMIN_LOGOUT')
    logout(request)
    messages.success(request, 'Đã đăng xuất Admin.')
    return redirect('admin-sys:admin-login')


@auth_required
def admin_dashboard(request):
    if not _is_admin(request.user):
        messages.error(request, 'Bạn không có quyền truy cập Admin.')
        return redirect('smartlock:dashboard')

    devices = Device.objects.all().order_by('name')
    support_reqs = SupportRequest.objects.all().select_related('device').order_by('-created_at')[:6]
    notifications = Notification.objects.filter(user=request.user).order_by('-created_at')[:5]

    context = {
        'title': 'Admin Dashboard',
        'total_devices': Device.objects.count(),
        'online_devices': Device.objects.filter(status='online').count(),
        'support_pending': SupportRequest.objects.filter(status='pending').count(),
        'support_requests': support_reqs,
        'recent_notifications': notifications,
    }
    return render(request, 'admin-sys/base/dashboard.html', context)


@auth_required
def admin_users_list(request):
    if not _is_admin(request.user):
        return redirect('admin-sys:admin-dashboard')
    users = User.objects.all().order_by('-created_at')
    return render(request, 'admin-sys/base/users.html', {'users': users})


@auth_required
def admin_user_detail(request, user_id):
    if not _is_admin(request.user):
        return redirect('admin-sys:admin-dashboard')
    user = get_object_or_404(User, id=user_id)
    return render(request, 'admin-sys/base/user_detail.html', {'user': user})


@auth_required
def admin_devices_list(request):
    if not _is_admin(request.user):
        return redirect('admin-sys:admin-dashboard')
    devices = Device.objects.all().order_by('name')
    return render(request, 'admin-sys/base/devices.html', {'devices': devices})


@auth_required
def admin_device_detail(request, device_id):
    if not _is_admin(request.user):
        return redirect('admin-sys:admin-dashboard')
    device = get_object_or_404(Device, id=device_id)
    return render(request, 'admin-sys/base/device_detail.html', {'device': device})


@auth_required
def admin_support_requests(request):
    if not _is_admin(request.user):
        return redirect('admin-sys:admin-dashboard')
    reqs = SupportRequest.objects.all().select_related('device').order_by('-created_at')
    return render(request, 'admin-sys/support/requests.html', {'support_requests': reqs})


@auth_required
def admin_support_request_detail(request, request_id):
    if not _is_admin(request.user):
        return redirect('admin-sys:admin-dashboard')
    sr = get_object_or_404(SupportRequest, id=request_id)
    return render(request, 'admin-sys/support/request_detail.html', {'support_request': sr})


@auth_required
def admin_audit_logs(request):
    if not _is_admin(request.user):
        return redirect('admin-sys:admin-dashboard')
    logs = AuditLog.objects.all().select_related('actor_user', 'device').order_by('-created_at')
    return render(request, 'admin-sys/base/logs.html', {'audit_logs': logs})


@auth_required
def admin_settings_system(request):
    if not _is_admin(request.user):
        return redirect('admin-sys:admin-dashboard')
    st = _settings()
    if request.method == 'POST':
        st.registration_enabled = 'registration_enabled' in request.POST
        st.ip_whitelist = (request.POST.get('ip_whitelist') or '').strip()
        st.ip_blacklist = (request.POST.get('ip_blacklist') or '').strip()
        st.save()
        messages.success(request, 'Đã lưu cài đặt hệ thống Admin.')
        return redirect('admin-sys:admin-settings-system')
    return render(request, 'admin-sys/base/system.html', {'system_settings': st})


@require_POST
def manage_logout(request):
    _audit(request, 'MANAGE_LOGOUT')
    logout(request)
    messages.success(request, 'Đã đăng xuất Admin.')
    return redirect('smartlock:manage-sys-login')


@auth_required
def manage_dashboard(request):
    if not _is_admin(request.user):
        messages.error(request, 'Bạn không có quyền truy cập Manage Sys.')
        return redirect('smartlock:dashboard')

    devices = Device.objects.all().order_by('name')
    support_reqs = SupportRequest.objects.all().select_related('device').order_by('-created_at')[:6]
    notifications = Notification.objects.filter(user=request.user).order_by('-created_at')[:5]

    context = {
        'title': 'Manage Sys Dashboard',
        'total_devices': Device.objects.count(),
        'online_devices': Device.objects.filter(status='online').count(),
        'support_pending': SupportRequest.objects.filter(status='pending').count(),
        'support_requests': support_reqs,
        'recent_notifications': notifications,
    }
    return render(request, 'admin-sys/base/dashboard.html', context)


@auth_required
def manage_users_list(request):
    if not _is_admin(request.user):
        return redirect('smartlock:manage-sys-dashboard')
    users = User.objects.all().order_by('-created_at')
    return render(request, 'admin-sys/base/users.html', {'users': users})


@auth_required
def manage_user_detail(request, user_id):
    if not _is_admin(request.user):
        return redirect('smartlock:manage-sys-dashboard')
    user = get_object_or_404(User, id=user_id)
    return render(request, 'admin-sys/base/user_detail.html', {'user': user})


@auth_required
def manage_devices_list(request):
    if not _is_admin(request.user):
        return redirect('smartlock:manage-sys-dashboard')
    devices = Device.objects.all().order_by('name')
    return render(request, 'admin-sys/base/devices.html', {'devices': devices})


@auth_required
def manage_device_detail(request, device_id):
    if not _is_admin(request.user):
        return redirect('smartlock:manage-sys-dashboard')
    device = get_object_or_404(Device, id=device_id)
    return render(request, 'admin-sys/base/device_detail.html', {'device': device})


@auth_required
def manage_support_requests(request):
    if not _is_admin(request.user):
        return redirect('smartlock:manage-sys-dashboard')
    reqs = SupportRequest.objects.all().select_related('device').order_by('-created_at')
    return render(request, 'admin-sys/support/requests.html', {'support_requests': reqs})


@auth_required
def manage_support_request_detail(request, request_id):
    if not _is_admin(request.user):
        return redirect('smartlock:manage-sys-dashboard')
    sr = get_object_or_404(SupportRequest, id=request_id)
    return render(request, 'admin-sys/support/request_detail.html', {'support_request': sr})


@auth_required
def manage_audit_logs(request):
    if not _is_admin(request.user):
        return redirect('smartlock:manage-sys-dashboard')
    logs = AuditLog.objects.all().select_related('actor_user', 'device').order_by('-created_at')
    return render(request, 'admin-sys/base/logs.html', {'audit_logs': logs})


@auth_required
def manage_settings_system(request):
    if not _is_admin(request.user):
        return redirect('smartlock:manage-sys-dashboard')
    st = _settings()
    if request.method == 'POST':
        st.registration_enabled = 'registration_enabled' in request.POST
        st.ip_whitelist = (request.POST.get('ip_whitelist') or '').strip()
        st.ip_blacklist = (request.POST.get('ip_blacklist') or '').strip()
        st.save()
        messages.success(request, 'Đã lưu cài đặt hệ thống Manage Sys.')
        return redirect('smartlock:manage-sys-settings-system')
    return render(request, 'admin-sys/base/system.html', {'system_settings': st})