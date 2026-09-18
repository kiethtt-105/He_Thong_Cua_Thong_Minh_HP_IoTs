# smartlock/views.py
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth import login, logout, authenticate
from django.contrib import messages
from django.utils import timezone
from django.core.mail import send_mail
import uuid

from .models import (
    User, Device, AccessCard, ShareAccessCode,
    SupportRequest, Notification, AuditLog, EmailVerificationToken
)
from .email_templates import render_email

# ====================== AUTH ======================
def login_view(request):
    if request.method == 'POST':
        email = request.POST.get('email')
        password = request.POST.get('password')
        user = authenticate(request, username=email, password=password)
        if user:
            login(request, user)
            messages.success(request, 'Đăng nhập thành công!')
            return redirect('smartlock:dashboard')
        messages.error(request, 'Email hoặc mật khẩu không đúng.')
    return render(request, 'account/base/login.html')

def logout_view(request):
    logout(request)
    return redirect('smartlock:login')

def register(request):
    if request.method == 'POST':
        email = request.POST.get('email')
        username = request.POST.get('username')
        password1 = request.POST.get('password1')
        password2 = request.POST.get('password2')
        full_name = request.POST.get('full_name')

        if password1 != password2:
            messages.error(request, 'Mật khẩu không khớp.')
            return render(request, 'account/base/register.html')

        user = User.objects.create_user(email=email, username=username, password=password1)
        user.full_name = full_name
        user.save()

        token = uuid.uuid4()
        EmailVerificationToken.objects.create(
            user=user, purpose='EMAIL_VERIFY', token_hash=token,
            expires_at=timezone.now() + timezone.timedelta(minutes=30)
        )

        context = {'full_name': full_name or username}
        subject, html, plain = render_email('user_verification.html', context)
        send_mail(subject, plain, 'no-reply@smartlock.com', [email])

        messages.success(request, 'Đăng ký thành công! Kiểm tra email.')
        return redirect('smartlock:login')
    return render(request, 'account/base/register.html')

def verify_email(request, token):
    try:
        vt = EmailVerificationToken.objects.get(token_hash=token, is_used=False)
        vt.user.email_verified = True
        vt.user.is_active = True
        vt.user.save()
        vt.is_used = True
        vt.save()
        messages.success(request, 'Tài khoản đã được kích hoạt thành công!')
    except:
        messages.error(request, 'Link xác thực không hợp lệ.')
    return redirect('smartlock:login')

def password_reset_request(request):
    if request.method == 'POST':
        email = request.POST.get('email')
        try:
            user = User.objects.get(email=email)
            token = uuid.uuid4()
            context = {'full_name': user.full_name or user.username, 'expiry_minutes': 30}
            subject, html, plain = render_email('password_reset.html', context)
            send_mail(subject, plain, 'no-reply@smartlock.com', [email])
            messages.success(request, 'Link đặt lại mật khẩu đã được gửi!')
        except:
            messages.error(request, 'Email không tồn tại.')
    return render(request, 'account/base/reset_password.html')   # form đặt lại (sau khi nhận link)

def reset_password(request):
    # Form đặt lại mật khẩu (có thể dùng django.contrib.auth.views.PasswordResetConfirmView)
    if request.method == 'POST':
        messages.success(request, 'Mật khẩu đã được thay đổi thành công!')
        return redirect('smartlock:login')
    return render(request, 'account/base/reset_password.html')

# ====================== DASHBOARD ======================
def dashboard(request):
    if not request.user.is_authenticated:
        return redirect('smartlock:login')
    context = {
        'user': request.user,
        'total_devices': Device.objects.filter(owner=request.user).count(),
        'online_devices': Device.objects.filter(owner=request.user, status='online').count(),
        'unapproved_cards': AccessCard.objects.filter(user=request.user, is_active=False).count(),
        'recent_logs': AuditLog.objects.filter(actor_user=request.user).order_by('-created_at')[:5],
    }
    return render(request, 'account/base/dashboard.html', context)

# ====================== DEVICES ======================
def devices_list(request):
    devices = Device.objects.filter(owner=request.user)
    return render(request, 'account/devices/list.html', {'device_list': devices})

def device_detail(request, device_id):
    device = get_object_or_404(Device, id=device_id, owner=request.user)
    return render(request, 'account/devices/detail.html', {'device': device})

# ====================== NFC ======================
def nfc_tags(request):
    cards = AccessCard.objects.filter(user=request.user)
    return render(request, 'account/nfc/tags.html', {'access_cards': cards})

def nfc_reader(request):
    return render(request, 'account/nfc/reader.html')

# ====================== SHARE & SUPPORT ======================
def share_codes(request):
    codes = ShareAccessCode.objects.filter(device__owner=request.user)
    return render(request, 'account/share/codes.html', {'share_codes': codes})

def share_request(request):
    return render(request, 'account/share/request.html')

def support_requests(request):
    requests = SupportRequest.objects.filter(requested_by=request.user)
    return render(request, 'account/support/requests.html', {'support_requests': requests})

def support_request_detail(request, request_id):
    req = get_object_or_404(SupportRequest, id=request_id, requested_by=request.user)
    return render(request, 'account/support/request_detail.html', {'request': req})

# ====================== SETTINGS ======================
def permissions_manage(request):
    return render(request, 'account/permissions/manage.html')

def settings_system(request):
    settings = SystemSettings.objects.first()
    return render(request, 'account/settings/system.html', {'settings': settings})

def notifications_list(request):
    notifications = Notification.objects.filter(user=request.user).order_by('-created_at')
    return render(request, 'account/base/notifications.html', {'notifications': notifications})

def profile(request):
    return render(request, 'account/base/profile.html', {'user': request.user})

def audit_logs(request):
    logs = AuditLog.objects.filter(actor_user=request.user).order_by('-created_at')
    return render(request, 'account/audit/logs.html', {'audit_logs': logs})