import hmac
from django.contrib import messages
from django.contrib.auth import authenticate, login as auth_login, logout as auth_logout
from django.contrib.auth.decorators import login_required
from django.contrib.auth.hashers import make_password
from django.shortcuts import redirect, render
from django.utils import timezone

from .forms import LoginForm, OTPForm, RegisterForm
from .models import PendingRegistration, User
from .utils import generate_otp, hash_otp, send_otp_email


def register_view(request):
    if request.method == 'POST':
        form = RegisterForm(request.POST)
        if form.is_valid():
            email = form.cleaned_data['email']

            if User.objects.filter(email=email).exists():
                form.add_error('email', 'Email này đã có tài khoản.')
                return render(request, 'accounts/register.html', {'form': form})

            otp = generate_otp()
            temp_data = {
                'full_name': form.cleaned_data['full_name'],
                'phone': form.cleaned_data.get('phone', ''),
                'password_hash': make_password(form.cleaned_data['password']),
            }

            PendingRegistration.objects.update_or_create(
                email=email,
                defaults={
                    'otp_code_hash': hash_otp(otp),
                    'temp_data': temp_data,
                    'is_used': False,
                    'expires_at': timezone.now() + timezone.timedelta(minutes=10),
                },
            )

            send_otp_email(email, otp)
            request.session['pending_email'] = email
            messages.success(request, f'Đã gửi mã OTP tới {email}. Kiểm tra email (hoặc console log lúc dev).')
            return redirect('accounts:verify_otp')
    else:
        form = RegisterForm()

    return render(request, 'accounts/register.html', {'form': form})


def verify_otp_view(request):
    email = request.session.get('pending_email')
    if not email:
        messages.error(request, 'Chưa có yêu cầu đăng ký nào đang chờ xác thực.')
        return redirect('accounts:register')

    if request.method == 'POST':
        form = OTPForm(request.POST)
        if form.is_valid():
            otp = form.cleaned_data['otp']
            try:
                pending = PendingRegistration.objects.get(email=email, is_used=False)
            except PendingRegistration.DoesNotExist:
                messages.error(request, 'Không tìm thấy yêu cầu đăng ký, vui lòng đăng ký lại.')
                return redirect('accounts:register')

            if pending.expires_at < timezone.now():
                messages.error(request, 'Mã OTP đã hết hạn, vui lòng đăng ký lại.')
                pending.delete()
                del request.session['pending_email']
                return redirect('accounts:register')

            if not hmac.compare_digest(pending.otp_code_hash, hash_otp(otp)):
                messages.error(request, 'Mã OTP không đúng.')
                return render(request, 'accounts/verify_otp.html', {'form': form, 'email': email})

            data = pending.temp_data
            user = User(
                email=email,
                full_name=data.get('full_name'),
                phone=data.get('phone') or None,
                is_active=True,
                email_verified=True,
            )
            user.password = data['password_hash']
            user.save()

            pending.is_used = True
            pending.save(update_fields=['is_used'])

            del request.session['pending_email']
            messages.success(request, 'Xác thực thành công! Đăng nhập để tiếp tục.')
            return redirect('accounts:login')
    else:
        form = OTPForm()

    return render(request, 'accounts/verify_otp.html', {'form': form, 'email': email})


def login_view(request):
    if request.user.is_authenticated:
        return redirect('accounts:dashboard')

    if request.method == 'POST':
        form = LoginForm(request.POST)
        if form.is_valid():
            user = authenticate(
                request,
                username=form.cleaned_data['email'],
                password=form.cleaned_data['password'],
            )
            if user is not None:
                auth_login(request, user)
                # Ghi last_login
                user.last_login = timezone.now()
                user.save(update_fields=['last_login'])
                return redirect('accounts:dashboard')
            messages.error(request, 'Email hoặc mật khẩu không đúng.')
    else:
        form = LoginForm()

    return render(request, 'accounts/login.html', {'form': form})


@login_required(login_url='accounts:login')
def dashboard_view(request):
    return render(request, 'accounts/dashboard.html')


def logout_view(request):
    auth_logout(request)
    messages.success(request, 'Đã đăng xuất.')
    return redirect('accounts:login')


# ==================== VIEWS MỚI (BE tự xử lý) ====================

@login_required(login_url='accounts:login')
def settings_view(request):
    # TODO: BE tự làm logic (lấy thông tin user, form cập nhật, v.v.)
    # Hiện tại chỉ render giao diện đẹp (FE tự làm sau)
    context = {
        'user': request.user,
        'form': None,  # BE sẽ thay bằng form thực tế
    }
    return render(request, 'accounts/settings.html', context)


@login_required(login_url='accounts:login')
def devices_view(request):
    # TODO: BE tự làm logic (lấy devices của user, form claim/reset, v.v.)
    # Hiện tại chỉ render giao diện đẹp
    context = {
        'user': request.user,
        'devices': [],  # BE sẽ thay bằng queryset thực tế
    }
    return render(request, 'accounts/devices.html', context)


@login_required(login_url='accounts:login')
def notifications_view(request):
    # TODO: BE tự làm logic (lấy thông báo của user, đánh dấu đọc, v.v.)
    # Hiện tại chỉ render giao diện đẹp
    context = {
        'user': request.user,
        'notifications': [],  # BE sẽ thay bằng queryset thực tế
    }
    return render(request, 'accounts/notifications.html', context)


@login_required(login_url='accounts:login')
def dashboard_view(request):
    return render(request, 'accounts/dashboard.html')


@login_required(login_url='accounts:login')
def settings_view(request):
    # TODO: BE tự làm logic (form cập nhật user, v.v.)
    context = {
        'user': request.user,
    }
    return render(request, 'accounts/settings.html', context)


@login_required(login_url='accounts:login')
def devices_view(request):
    # TODO: BE tự làm logic (lấy devices của user)
    context = {
        'user': request.user,
        'devices': [],  # BE sẽ thay bằng queryset thực tế
    }
    return render(request, 'accounts/devices.html', context)


@login_required(login_url='accounts:login')
def notifications_view(request):
    # TODO: BE tự làm logic (lấy notifications của user)
    context = {
        'user': request.user,
        'notifications': [],  # BE sẽ thay bằng queryset thực tế
    }
    return render(request, 'accounts/notifications.html', context)