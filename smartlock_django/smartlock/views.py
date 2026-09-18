# smartlock/views.py
import hashlib
import logging
import uuid
from datetime import timedelta

from django.contrib import messages
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
from django.contrib.auth.tokens import default_token_generator
from django.core.exceptions import ValidationError
from django.core.mail import send_mail
from django.db import IntegrityError
from django.shortcuts import get_object_or_404, redirect, render
from django.urls import reverse
from django.utils import timezone
from django.utils.encoding import force_bytes, force_str
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode

from .email_templates import render_email
from .models import (
    AccessCard, AuditLog, Device, EmailVerificationToken, Notification,
    ShareAccessCode, SupportRequest, SystemSettings, User,
)

logger = logging.getLogger('smartlock.views')
FROM_EMAIL = 'no-reply@smartlock.com'
VERIFY_EXPIRY_MINUTES = 30
auth_required = login_required(login_url='smartlock:login')


def _send_mail(subject, plain, html, to):
    """Gửi mail và ghi log chi tiết (không để lỗi SMTP làm sập view)."""
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


# ====================== AUTH ======================
def login_view(request):
    if request.method == 'POST':
        email = (request.POST.get('email') or '').strip()
        password = request.POST.get('password')
        user = authenticate(request, username=email, password=password)
        if user:
            login(request, user)
            messages.success(request, 'Đăng nhập thành công!')
            return redirect('smartlock:dashboard')

        # authenticate() trả None cho cả user chưa active -> báo rõ hơn
        try:
            u = User.objects.get(email__iexact=email)
            if not u.is_active and u.check_password(password):
                messages.error(request, 'Tài khoản chưa xác thực email.')
                return render(request, 'account/base/login.html')
        except User.DoesNotExist:
            pass
        messages.error(request, 'Email hoặc mật khẩu không đúng.')
    return render(request, 'account/base/login.html')


def logout_view(request):
    logout(request)
    messages.success(request, 'Đã đăng xuất.')
    return redirect('smartlock:login')


def register(request):
    if request.method == 'POST':
        email = (request.POST.get('email') or '').strip()
        username = (request.POST.get('username') or '').strip()
        password1 = request.POST.get('password1')
        password2 = request.POST.get('password2')
        full_name = request.POST.get('full_name')

        if password1 != password2:
            messages.error(request, 'Mật khẩu không khớp.')
            return render(request, 'account/base/register.html')

        try:
            user = User.objects.create_user(email=email, username=username, password=password1)
        except (ValidationError, IntegrityError, ValueError) as e:
            messages.error(request, f'Không thể tạo tài khoản: {e}')
            return render(request, 'account/base/register.html')

        user.full_name = full_name
        user.save()

        token = uuid.uuid4()
        EmailVerificationToken.objects.create(
            user=user,
            purpose='EMAIL_VERIFY',
            token_hash=_hash_token(token),
            expires_at=timezone.now() + timedelta(minutes=VERIFY_EXPIRY_MINUTES),
        )

        logger.info("register: tạo user %s, token hết hạn sau %s phút", email, VERIFY_EXPIRY_MINUTES)
        verification_link = request.build_absolute_uri(
            reverse('smartlock:verify_email', args=[token])
        )
        context = {
            'full_name': full_name or username,
            'username': username,
            'verification_link': verification_link,
            'expiry_minutes': VERIFY_EXPIRY_MINUTES,
        }
        subject, html, plain = render_email('user_verification.html', context)
        _send_mail(subject, plain, html, email)

        return render(request, 'account/base/verify_email.html', {'email': email})
    return render(request, 'account/base/register.html')


def verify_email(request, token):
    try:
        vt = EmailVerificationToken.objects.select_related('user').get(
            token_hash=_hash_token(token),
            purpose='EMAIL_VERIFY',
            is_used=False,
            expires_at__gt=timezone.now(),
        )
    except EmailVerificationToken.DoesNotExist:
        messages.error(request, 'Link xác thực không hợp lệ hoặc đã hết hạn.')
        return redirect('smartlock:login')

    vt.user.email_verified = True
    vt.user.is_active = True
    vt.user.save()
    vt.is_used = True
    vt.used_at = timezone.now()
    vt.save()

    messages.success(request, 'Tài khoản đã được kích hoạt thành công!')
    return redirect('smartlock:login')


def password_reset_request(request):
    if request.method == 'POST':
        email = (request.POST.get('email') or '').strip()
        user = User.objects.filter(email__iexact=email, is_active=True).first()
        if user:
            uid = urlsafe_base64_encode(force_bytes(str(user.pk)))
            token = default_token_generator.make_token(user)
            reset_link = request.build_absolute_uri(
                reverse('smartlock:reset_password_confirm', args=[uid, token])
            )
            context = {
                'full_name': user.full_name or user.username,
                'password_reset_link': reset_link,
                'expiry_minutes': 30,
            }
            subject, html, plain = render_email('password_reset.html', context)
            _send_mail(subject, plain, html, user.email)
        # Luôn báo giống nhau để không lộ email nào tồn tại
        messages.success(request, 'Nếu email tồn tại, link đặt lại mật khẩu đã được gửi.')
    return render(request, 'account/base/reset_password.html')


def reset_password(request, uidb64, token):
    try:
        user = User.objects.get(pk=force_str(urlsafe_base64_decode(uidb64)))
    except (User.DoesNotExist, ValueError, TypeError, OverflowError, ValidationError):
        user = None

    if user is None or not default_token_generator.check_token(user, token):
        messages.error(request, 'Link đặt lại mật khẩu không hợp lệ hoặc đã hết hạn.')
        return redirect('smartlock:password_reset')

    if request.method == 'POST':
        p1 = request.POST.get('new_password1')
        p2 = request.POST.get('new_password2')
        if not p1 or p1 != p2:
            messages.error(request, 'Mật khẩu không khớp.')
            return render(request, 'account/base/reset_password.html', {'validlink': True})
        user.set_password(p1)
        user.save()
        messages.success(request, 'Mật khẩu đã được thay đổi thành công!')
        return redirect('smartlock:login')
    return render(request, 'account/base/reset_password.html', {'validlink': True})


# ====================== DASHBOARD ======================
@auth_required
def dashboard(request):
    context = {
        'user': request.user,
        'total_devices': Device.objects.filter(owner=request.user).count(),
        'online_devices': Device.objects.filter(owner=request.user, status='online').count(),
        'unapproved_cards': AccessCard.objects.filter(user=request.user, is_active=False).count(),
        'recent_logs': AuditLog.objects.filter(actor_user=request.user).order_by('-created_at')[:5],
    }
    return render(request, 'account/base/dashboard.html', context)


# ====================== DEVICES ======================
@auth_required
def devices_list(request):
    devices = Device.objects.filter(owner=request.user)
    return render(request, 'account/devices/list.html', {'device_list': devices})


@auth_required
def device_detail(request, device_id):
    device = get_object_or_404(Device, id=device_id, owner=request.user)
    return render(request, 'account/devices/detail.html', {'device': device})


# ====================== NFC ======================
@auth_required
def nfc_tags(request):
    cards = AccessCard.objects.filter(user=request.user)
    return render(request, 'account/nfc/tags.html', {'access_cards': cards})


@auth_required
def nfc_reader(request):
    return render(request, 'account/nfc/reader.html')


# ====================== SHARE & SUPPORT ======================
@auth_required
def share_codes(request):
    codes = ShareAccessCode.objects.filter(device__owner=request.user)
    return render(request, 'account/share/codes.html', {'share_codes': codes})


@auth_required
def share_request(request):
    return render(request, 'account/share/request.html')


@auth_required
def support_requests(request):
    reqs = SupportRequest.objects.filter(requested_by=request.user)
    return render(request, 'account/support/requests.html', {'support_requests': reqs})


@auth_required
def support_request_detail(request, request_id):
    req = get_object_or_404(SupportRequest, id=request_id, requested_by=request.user)
    return render(request, 'account/support/request_detail.html', {'request': req})


# ====================== SETTINGS ======================
@auth_required
def permissions_manage(request):
    return render(request, 'account/permissions/manage.html')


@auth_required
def settings_system(request):
    system_settings = SystemSettings.objects.first()
    return render(request, 'account/settings/system.html', {'settings': system_settings})


@auth_required
def notifications_list(request):
    notifications = Notification.objects.filter(user=request.user).order_by('-created_at')
    return render(request, 'account/base/notifications.html', {'notifications': notifications})


@auth_required
def profile(request):
    return render(request, 'account/base/profile.html', {'user': request.user})


@auth_required
def audit_logs(request):
    logs = AuditLog.objects.filter(actor_user=request.user).order_by('-created_at')
    return render(request, 'account/audit/logs.html', {'audit_logs': logs})