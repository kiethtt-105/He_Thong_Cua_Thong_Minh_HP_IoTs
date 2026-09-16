import hashlib
import random
from datetime import timedelta

from django.conf import settings
from django.contrib import messages
from django.contrib.auth import authenticate, login as auth_login, logout as auth_logout
from django.contrib.auth.decorators import login_required
from django.contrib.auth.hashers import make_password
from django.core.mail import send_mail
from django.shortcuts import redirect, render
from django.utils import timezone

from .forms import LoginForm, RegisterForm, VerifyOtpForm
from .models import AuditLog, PendingRegistration, User

OTP_TTL_MINUTES = 10
OTP_RESEND_COOLDOWN_SECONDS = 60


# ==================== HELPERS ====================

def _generate_otp() -> str:
    return f"{random.randint(0, 999999):06d}"


def _hash_otp(code: str) -> str:
    return hashlib.sha256(code.strip().encode('utf-8')).hexdigest()


def _send_otp_email(email: str, code: str, subject: str):
    message = (
        f"Mã OTP xác thực của bạn là: {code}\n"
        f"Mã có hiệu lực trong {OTP_TTL_MINUTES} phút.\n\n"
        f"Nếu bạn không thực hiện yêu cầu này, hãy bỏ qua email này."
    )
    send_mail(
        subject,
        message,
        settings.DEFAULT_FROM_EMAIL,
        [email],
        fail_silently=False,
    )


def _client_ip(request):
    return request.META.get('REMOTE_ADDR')


# ==================== ĐĂNG KÝ ====================

def register_view(request):
    if request.user.is_authenticated:
        return redirect('smartlock:dashboard')

    if request.method == 'POST':
        form = RegisterForm(request.POST)
        if form.is_valid():
            email = form.cleaned_data['email']
            password = form.cleaned_data['password']
            full_name = form.cleaned_data['full_name']

            code = _generate_otp()

            # update_or_create vì PendingRegistration.email là unique — cho phép
            # đăng ký lại (resend) khi user chưa xác thực xong lần trước.
            PendingRegistration.objects.update_or_create(
                email=email,
                defaults={
                    'otp_code_hash': _hash_otp(code),
                    'temp_data': {
                        'full_name': full_name,
                        'password': make_password(password),
                    },
                    'is_used': False,
                    'expires_at': timezone.now() + timedelta(minutes=OTP_TTL_MINUTES),
                }
            )

            _send_otp_email(email, code, 'Xác thực đăng ký tài khoản Smart Lock')

            request.session['pending_email'] = email
            request.session['otp_last_sent'] = timezone.now().isoformat()

            messages.success(request, f'Đã gửi mã OTP đến {email}. Vui lòng kiểm tra email.')
            return redirect('smartlock:verify_email')
    else:
        form = RegisterForm()

    return render(request, 'accounts/register.html', {'form': form})


# ==================== XÁC THỰC EMAIL OTP ====================

def verify_email_view(request):
    email = request.session.get('pending_email')
    if not email:
        messages.error(request, 'Phiên đăng ký đã hết hạn hoặc không tồn tại. Vui lòng đăng ký lại.')
        return redirect('smartlock:register')

    if request.method == 'POST':
        form = VerifyOtpForm(request.POST)
        if form.is_valid():
            code_hash = _hash_otp(form.cleaned_data['otp_code'])

            pending = (
                PendingRegistration.objects
                .filter(email=email, is_used=False)
                .order_by('-created_at')
                .first()
            )

            if not pending:
                messages.error(request, 'Phiên đăng ký đã hết hạn. Vui lòng đăng ký lại.')
                return redirect('smartlock:register')

            if pending.expires_at < timezone.now():
                form.add_error('otp_code', 'Mã OTP đã hết hạn. Bấm "Gửi lại mã" để nhận mã mới.')
            elif pending.otp_code_hash != code_hash:
                form.add_error('otp_code', 'Mã OTP không đúng.')
            else:
                pending.is_used = True
                pending.save(update_fields=['is_used'])

                user = User(
                    email=email,
                    full_name=pending.temp_data.get('full_name', ''),
                    is_active=True,
                    email_verified=True,
                )
                user.password = pending.temp_data.get('password')  # đã hash sẵn (make_password)
                user.save()

                AuditLog.objects.create(
                    actor_user=user,
                    action='EMAIL_VERIFIED_REGISTER',
                    success=True,
                    ip_address=_client_ip(request),
                    user_agent=request.META.get('HTTP_USER_AGENT', ''),
                )

                del request.session['pending_email']
                messages.success(request, 'Xác thực email thành công! Vui lòng đăng nhập.')
                return redirect('smartlock:login')
    else:
        form = VerifyOtpForm()

    return render(request, 'accounts/verify_email.html', {'form': form, 'email': email})


def resend_otp_view(request):
    email = request.session.get('pending_email')
    if not email:
        messages.error(request, 'Không tìm thấy phiên đăng ký. Vui lòng đăng ký lại.')
        return redirect('smartlock:register')

    last_sent = request.session.get('otp_last_sent')
    if last_sent:
        elapsed = (timezone.now() - timezone.datetime.fromisoformat(last_sent)).total_seconds()
        if elapsed < OTP_RESEND_COOLDOWN_SECONDS:
            wait = int(OTP_RESEND_COOLDOWN_SECONDS - elapsed)
            messages.warning(request, f'Vui lòng đợi {wait} giây trước khi gửi lại mã.')
            return redirect('smartlock:verify_email')

    pending = (
        PendingRegistration.objects
        .filter(email=email, is_used=False)
        .order_by('-created_at')
        .first()
    )
    if not pending:
        messages.error(request, 'Phiên đăng ký đã hết hạn. Vui lòng đăng ký lại.')
        return redirect('smartlock:register')

    code = _generate_otp()
    pending.otp_code_hash = _hash_otp(code)
    pending.expires_at = timezone.now() + timedelta(minutes=OTP_TTL_MINUTES)
    pending.save(update_fields=['otp_code_hash', 'expires_at'])

    _send_otp_email(email, code, 'Mã OTP mới - Smart Lock')
    request.session['otp_last_sent'] = timezone.now().isoformat()

    messages.success(request, 'Đã gửi lại mã OTP mới.')
    return redirect('smartlock:verify_email')


# ==================== ĐĂNG NHẬP / ĐĂNG XUẤT ====================

def login_view(request):
    if request.user.is_authenticated:
        return redirect('smartlock:dashboard')

    if request.method == 'POST':
        form = LoginForm(request.POST)
        if form.is_valid():
            email = form.cleaned_data['email'].strip().lower()
            password = form.cleaned_data['password']

            user = authenticate(request, username=email, password=password)

            if user is None:
                AuditLog.objects.create(
                    action='LOGIN_FAILED',
                    username_attempt=email,
                    success=False,
                    ip_address=_client_ip(request),
                    user_agent=request.META.get('HTTP_USER_AGENT', ''),
                )
                form.add_error(None, 'Email hoặc mật khẩu không đúng.')
            elif not user.email_verified:
                form.add_error(None, 'Email chưa được xác thực. Vui lòng kiểm tra hộp thư.')
            elif not user.is_active:
                form.add_error(None, 'Tài khoản đã bị vô hiệu hóa.')
            else:
                auth_login(request, user)
                AuditLog.objects.create(
                    actor_user=user,
                    action='LOGIN_SUCCESS',
                    username_attempt=email,
                    success=True,
                    ip_address=_client_ip(request),
                    user_agent=request.META.get('HTTP_USER_AGENT', ''),
                )
                messages.success(request, f'Chào mừng {user.full_name or user.email}!')
                return redirect('smartlock:dashboard')
    else:
        form = LoginForm()

    return render(request, 'accounts/login.html', {'form': form})


def logout_view(request):
    auth_logout(request)
    messages.info(request, 'Bạn đã đăng xuất.')
    return redirect('smartlock:login')


@login_required(login_url='smartlock:login')
def dashboard_view(request):
    return render(request, 'smartlock/dashboard.html', {'user': request.user})
