from datetime import timedelta

from django.conf import settings
from django.contrib import messages
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
from django.contrib.auth.hashers import make_password
from django.db import transaction
from django.shortcuts import redirect, render
from django.utils import timezone

from .forms import LoginForm, OtpForm, RegisterForm
from .models import PendingRegistration, User
from .utils import generate_otp, hash_otp, mask_email, send_otp_email


def register_view(request):
    """Bước 1: người dùng nhập thông tin đăng ký -> tạo PendingRegistration + gửi OTP."""
    if request.user.is_authenticated:
        return redirect('smartlock:dashboard')

    if request.method == 'POST':
        form = RegisterForm(request.POST)
        if form.is_valid():
            email = form.cleaned_data['email']
            otp_code = generate_otp()
            expires_at = timezone.now() + timedelta(minutes=settings.OTP_EXPIRY_MINUTES)

            # Lưu tạm thông tin đăng ký (mật khẩu đã băm sẵn, KHÔNG lưu plain-text).
            temp_data = {
                'full_name': form.cleaned_data.get('full_name', ''),
                'phone': form.cleaned_data.get('phone', ''),
                'password_hash': make_password(form.cleaned_data['password1']),
            }

            # Nếu email đã có 1 yêu cầu đăng ký dở dang trước đó -> ghi đè (cho phép thử lại).
            PendingRegistration.objects.update_or_create(
                email=email,
                defaults={
                    'otp_code_hash': hash_otp(otp_code),
                    'temp_data': temp_data,
                    'is_used': False,
                    'expires_at': expires_at,
                }
            )

            try:
                send_otp_email(email, otp_code, purpose="đăng ký tài khoản")
            except Exception:
                messages.error(
                    request,
                    "Không thể gửi email OTP lúc này. Vui lòng kiểm tra lại cấu hình email hoặc thử lại sau."
                )
                return render(request, 'smartlock/register.html', {'form': form})

            request.session['pending_email'] = email
            messages.success(request, "Mã OTP đã được gửi tới email của bạn. Vui lòng kiểm tra hộp thư.")
            return redirect('smartlock:verify_email')
    else:
        form = RegisterForm()

    return render(request, 'smartlock/register.html', {'form': form})


def verify_email_view(request):
    """Bước 2: người dùng nhập OTP -> tạo User thật + tự động đăng nhập vào dashboard."""
    email = request.session.get('pending_email')
    if not email:
        messages.error(request, "Vui lòng đăng ký trước khi xác thực email.")
        return redirect('smartlock:register')

    try:
        pending = PendingRegistration.objects.get(email=email, is_used=False)
    except PendingRegistration.DoesNotExist:
        messages.error(request, "Không tìm thấy yêu cầu đăng ký hợp lệ. Vui lòng đăng ký lại.")
        request.session.pop('pending_email', None)
        return redirect('smartlock:register')

    # Gửi lại mã OTP mới.
    if request.method == 'POST' and 'resend' in request.POST:
        otp_code = generate_otp()
        pending.otp_code_hash = hash_otp(otp_code)
        pending.expires_at = timezone.now() + timedelta(minutes=settings.OTP_EXPIRY_MINUTES)
        pending.save(update_fields=['otp_code_hash', 'expires_at'])
        try:
            send_otp_email(email, otp_code, purpose="đăng ký tài khoản")
            messages.success(request, "Đã gửi lại mã OTP mới tới email của bạn.")
        except Exception:
            messages.error(request, "Không thể gửi lại email OTP. Vui lòng thử lại sau.")
        return redirect('smartlock:verify_email')

    if request.method == 'POST':
        form = OtpForm(request.POST)
        if form.is_valid():
            if pending.expires_at < timezone.now():
                pending.delete()
                request.session.pop('pending_email', None)
                messages.error(request, "Mã OTP đã hết hạn. Vui lòng đăng ký lại.")
                return redirect('smartlock:register')

            if hash_otp(form.cleaned_data['otp']) != pending.otp_code_hash:
                form.add_error('otp', "Mã OTP không chính xác. Vui lòng thử lại.")
            else:
                # OTP đúng -> tạo tài khoản thật, đã active + đã xác thực email.
                with transaction.atomic():
                    user = User(
                        email=email,
                        full_name=pending.temp_data.get('full_name', ''),
                        phone=pending.temp_data.get('phone', ''),
                        is_active=True,
                        email_verified=True,
                    )
                    # password_hash đã được make_password() ở bước đăng ký -> gán thẳng,
                    # KHÔNG gọi set_password() lần nữa (tránh băm 2 lần).
                    user.password = pending.temp_data['password_hash']
                    user.save()
                    pending.delete()

                # Đăng nhập ngay cho người dùng -> vào thẳng dashboard, không cần login lại.
                login(request, user)
                request.session.pop('pending_email', None)
                messages.success(request, "Xác thực email thành công! Chào mừng bạn đến với SmartLock.")
                return redirect('smartlock:dashboard')
    else:
        form = OtpForm()

    return render(request, 'smartlock/verify_otp.html', {
        'form': form,
        'email': mask_email(email),
    })


def login_view(request):
    if request.user.is_authenticated:
        return redirect('smartlock:dashboard')

    if request.method == 'POST':
        form = LoginForm(request.POST)
        if form.is_valid():
            user = authenticate(
                request,
                username=form.cleaned_data['email'],
                password=form.cleaned_data['password'],
            )
            if user is not None:
                login(request, user)
                return redirect('smartlock:dashboard')
            form.add_error(None, "Email hoặc mật khẩu không đúng.")
    else:
        form = LoginForm()

    return render(request, 'smartlock/login.html', {'form': form})


def logout_view(request):
    logout(request)
    messages.success(request, "Bạn đã đăng xuất.")
    return redirect('smartlock:login')


@login_required(login_url='smartlock:login')
def dashboard_view(request):
    return render(request, 'smartlock/dashboard.html', {})
