# smartlock/views.py
import base64
import hashlib
import hmac
import io
import json
import logging
import math
import re
import secrets
from datetime import timedelta
from decimal import Decimal, InvalidOperation
from urllib.parse import urlencode
from .models import DoorPinCode, FaceProfile, AccessEvent
from . import services
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
from django.core.paginator import Paginator
from django.db import IntegrityError, transaction
from django.db.models import Avg, Count, OuterRef, Q, Subquery
from django.db.models.functions import TruncDate, TruncMinute
from django.http import Http404, HttpResponse, JsonResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.urls import reverse
from django.utils import timezone
from django.utils.dateparse import parse_datetime
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

from .services import (
    accessible_devices as _accessible_devices, admins as _admins, audit as _audit,
    client_ip as _client_ip, find_user as _find_user, has_permission as _has_permission,
    hash_card_uid as _hash_card_uid, hash_token as _hash_token, is_admin as _is_admin,
    notify as _notify, parse_dt as _parse_dt, parse_uuid as _parse_uuid, pick_device as _pick_device,
    register_failure as _register_failure, render_email, reset_lockout as _reset_lockout,
    send_mail as _send_mail, send_verification as _send_verification,
    system_settings as _settings, user_agent as _user_agent, valid_ip as _valid_ip,
    issue_ble_ticket, notify_login as _notify_login,
)
from .models import (
    AccessCard, Announcement, AuditLog, CardDeviceAccess,
    Device, DeviceAccess, DeviceCommand, DeviceStatusLog, OneTimeCode, Fido2Credential,
    NfcLog, NfcReader, Notification, Permission,
    TwoFactorConfig,
    User, fernet, sync_two_fa_flag,
)

logger = logging.getLogger('smartlock.views')

# ====================== CONSTANTS ======================
COMMAND_TTL_SECONDS = 120
PAGE_SIZE = 20
# lệnh -> quyền cần có (None = chỉ chủ khoá)
ALLOWED_COMMANDS = {'LOCK': 'LOCK', 'UNLOCK': 'UNLOCK', 'REBOOT': None}

# ====================== AUTH REQUIRED DECORATOR (đưa lên đầu) ======================
auth_required = login_required(login_url='smartlock:login')

# ====================== RENDER: mỗi nhóm trang gộp 1 template, chọn trang bằng biến `page` ======================
PAGE_TEMPLATE = {
    "login": "auth",
    "register": "auth",
    "reset_password": "auth",
    "verify_email": "auth",
    "verify_2fa": "auth",
    "devices_list": "devices",
    "device_detail": "devices",
    "device_add": "devices",
    "device_claim": "devices",
    "nfc_tags": "access",
    "nfc_reader": "access",
    "shares": "access",
    "door_pins": "access",
    "face_profiles": "access",
    "access_history": "access",
    "audit_logs": "admin",
    "dashboard": "home",
    "profile": "home",
    "notifications": "home",
}


def _render(request, page, context=None, **kwargs):
    """render('login') -> account/auth.html với page='login' (xem PAGE_TEMPLATE)."""
    ctx = dict(context or {})
    ctx['page'] = page
    return render(request, f'account/{PAGE_TEMPLATE[page]}.html', ctx, **kwargs)


# ====================== HELPERS ======================

def _visible_logs(user):
    """Log user được phép xem: mình làm, mình là đối tượng (bị admin/người khác tác động,
    bị đăng nhập sai...), hoặc xảy ra trên thiết bị của mình."""
    return AuditLog.objects.filter(
        Q(actor_user=user) | Q(target_user=user) | Q(device__owner=user)
    )






def _parse_int(value):
    try:
        return int(str(value).strip())
    except (ValueError, TypeError):
        return None

def _redirect_with(url_name, **params):
    url = reverse(url_name)
    if params:
        url += '?' + urlencode(params)
    return redirect(url)

def _ensure_sync_key(request):
    """Cấp (mỗi lần login mới) một khoá ngẫu nhiên gắn với session hiện tại. Client dùng khoá
    này để suy ra (HKDF) AES key mã hoá cache dashboard lưu trong IndexedDB của trình duyệt.
    Vì khoá đổi mỗi khi có session mới và bị xoá khi logout (Django logout() flush session),
    cache cũ mã hoá bằng khoá cũ vĩnh viễn không đọc được nữa dù còn sót lại trong IndexedDB."""
    request.session['sync_key'] = secrets.token_urlsafe(32)

def _page(request, queryset):
    return Paginator(queryset, PAGE_SIZE).get_page(request.GET.get('page'))

# ====================== AUTH ======================
def login_view(request):
    if request.user.is_authenticated:
        return redirect('smartlock:dashboard')

    next_url = request.POST.get('next') or request.GET.get('next') or ''
    ctx = {'next': next_url}

    if request.method != 'POST':
        return _render(request, 'login', ctx)

    identifier = (request.POST.get('identifier') or '').strip()
    password = request.POST.get('password') or ''

    if not identifier or not password:
        messages.error(request, 'Vui lòng điền đầy đủ thông tin.')
        return _render(request, 'login', ctx)

    ip = _client_ip(request)   # chỉ để ghi nhận IP lượt sai (không còn chặn/giới hạn theo IP)
    user = _find_user(identifier)
    now = timezone.now()

    if user:
        if user.login_locked_until and user.login_locked_until > now:
            remaining = math.ceil((user.login_locked_until - now).total_seconds() / 60)
            messages.error(request, f'Tài khoản đang bị khóa tạm thời. Thử lại sau {remaining} phút.')
            _audit(request, 'LOGIN_LOCKED', success=False, severity='warning',
                   actor=None, target_user=user, username_attempt=identifier[:150])
            return _render(request, 'login', ctx)

    auth_user = authenticate(request, username=user.email, password=password) if user else None

    # Tài khoản quản trị chỉ được đăng nhập ở cổng quản trị riêng (app manage_sys).
    if auth_user and _is_admin(auth_user):
        _audit(request, 'LOGIN_ADMIN_REJECTED', success=False, severity='warning',
               actor=None, target_user=user, username_attempt=identifier[:150])
        messages.error(request, 'Email/Username hoặc mật khẩu không đúng.')
        return _render(request, 'login', ctx)

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
        _notify_login(request, auth_user)      # trước audit LOGIN: so với lịch sử IP cũ
        _audit(request, 'LOGIN', actor=auth_user)
        messages.success(request, 'Đăng nhập thành công!')

        if next_url and url_has_allowed_host_and_scheme(next_url, {request.get_host()}, require_https=request.is_secure()):
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
    return _render(request, 'login', ctx)


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
        return _render(request, 'register', {'disabled': True})

    if request.method != 'POST':
        return _render(request, 'register')

    email = (request.POST.get('email') or '').strip()
    username = (request.POST.get('username') or '').strip()
    full_name = (request.POST.get('full_name') or '').strip()
    password1 = request.POST.get('password1') or ''
    password2 = request.POST.get('password2') or ''
    ctx = {'form': {'email': email, 'username': username, 'full_name': full_name}}

    if '@' in username:
        messages.error(request, 'Tên đăng nhập không được chứa ký tự @.')
        return _render(request, 'register', ctx)
    if password1 != password2:
        messages.error(request, 'Mật khẩu không khớp.')
        return _render(request, 'register', ctx)
    try:
        validate_password(password1)
    except ValidationError as e:
        messages.error(request, ' '.join(e.messages))
        return _render(request, 'register', ctx)

    # Kiểm tra trùng TRƯỚC khi tạo, để xử lý rõ ràng từng trường hợp thay vì chỉ báo lỗi
    # chung chung "đã được sử dụng" rồi dừng lại (khiến người đăng ký thật sự bị bế tắc
    # nếu lần gửi email xác thực trước đó thất bại - họ không có cách nào "đăng ký lại").
    existing_email_user = User.objects.filter(email__iexact=email).first()
    username_taken = User.objects.filter(username__iexact=username).exclude(
        pk=existing_email_user.pk if existing_email_user else None).exists()

    if username_taken:
        messages.error(request, 'Tên đăng nhập đã được sử dụng.')
        return _render(request, 'register', ctx)

    if existing_email_user:
        if existing_email_user.is_active or existing_email_user.email_verified:
            # Email đã có tài khoản đang hoạt động -> KHÔNG tạo trùng, báo rõ hướng xử lý
            # (khác với trước đây chỉ ném lỗi "đã được sử dụng" chung chung).
            _audit(request, 'REGISTER_DUPLICATE_ACTIVE', actor=None, target_user=existing_email_user,
                   success=False, severity='warning', username_attempt=email[:150])
            messages.error(request, 'Email này đã có tài khoản đang hoạt động. Vui lòng đăng nhập, '
                                    'hoặc dùng "Quên mật khẩu" nếu bạn không nhớ mật khẩu.')
        else:
            # Email đã đăng ký nhưng CHƯA xác thực (có thể do lần trước gửi mail xác thực bị lỗi,
            # hoặc người dùng bỏ dở) -> đừng để họ kẹt vĩnh viễn (không tạo được tài khoản mới,
            # cũng không biết cách kích hoạt tài khoản cũ) -> tự động gửi lại email xác thực.
            recent = OneTimeCode.objects.filter(
                user=existing_email_user, purpose='EMAIL_VERIFY',
                created_at__gt=timezone.now() - timedelta(seconds=60)).exists()
            if not recent:
                sent = _send_verification(request, existing_email_user)
                _audit(request, 'VERIFY_MAIL_RESENT', actor=None, target_user=existing_email_user,
                       success=sent, metadata={'reason': 'duplicate_register_unverified'})
            messages.info(request, 'Email này đã được đăng ký nhưng chưa xác thực. Mình vừa gửi lại '
                                   'email xác thực, vui lòng kiểm tra hộp thư (kể cả mục Spam).')
        return _render(request, 'verify_email', {'email': email})

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
        return _render(request, 'register', ctx)
    except IntegrityError:
        _audit(request, 'REGISTER_FAILED', actor=None, success=False, username_attempt=email[:150],
               metadata={'reason': 'duplicate'})
        messages.error(request, 'Email hoặc tên đăng nhập đã được sử dụng.')
        return _render(request, 'register', ctx)
    except ValueError as e:
        _audit(request, 'REGISTER_FAILED', actor=None, success=False, username_attempt=email[:150],
               metadata={'reason': 'invalid'})
        messages.error(request, f'Không thể tạo tài khoản: {e}')
        return _render(request, 'register', ctx)

    logger.info("register: tạo user %s", email)
    _audit(request, 'REGISTER', actor=user, target_user=user)
    if not _send_verification(request, user):
        _audit(request, 'VERIFY_MAIL_FAILED', actor=user, target_user=user, success=False,
               severity='warning')
        messages.warning(request, 'Chưa gửi được email xác thực. Vui lòng bấm "Gửi lại" sau ít phút.')
    return _render(request, 'verify_email', {'email': email})


def verify_email(request, token):
    try:
        vt = OneTimeCode.objects.select_related('user').get(
            token_hash=_hash_token(token), purpose='EMAIL_VERIFY',
            is_used=False, expires_at__gt=timezone.now(),
        )
    except OneTimeCode.DoesNotExist:
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
        recent = OneTimeCode.objects.filter(
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
    return _render(request, 'verify_email', {'email': email})


RESET_NEUTRAL_MSG = ('Nếu email này đã đăng ký, chúng tôi đã gửi link đặt lại mật khẩu. '
                     'Vui lòng kiểm tra hộp thư (kể cả mục Spam).')


def password_reset_request(request):
    if request.method != 'POST':
        return _render(request, 'reset_password', {'mode': 'request'})

    email = (request.POST.get('email') or '').strip()
    ctx = {'mode': 'request', 'email': email}
    user = User.objects.filter(email__iexact=email).first()

    def _neutral():
        # Mọi nhánh đều trả CÙNG một thông báo -> không lộ email nào đã đăng ký (chống user enumeration).
        messages.success(request, RESET_NEUTRAL_MSG)
        return _render(request, 'reset_password', ctx)

    if not user:
        _audit(request, 'PASSWORD_RESET_UNKNOWN_EMAIL', actor=None, success=False,
               severity='warning', username_attempt=email[:150])
        return _neutral()

    if not user.is_active or not user.email_verified:
        _audit(request, 'PASSWORD_RESET_UNVERIFIED', actor=None, success=False,
               severity='warning', target_user=user)
        return _neutral()

    if AuditLog.objects.filter(action='PASSWORD_RESET_REQUEST', target_user=user,
                               created_at__gte=timezone.now() - timedelta(seconds=60)).exists():
        _audit(request, 'PASSWORD_RESET_THROTTLED', actor=None, success=False, target_user=user)
        return _neutral()

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
    sent = _send_mail(subject, plain, html, user.email, log_body=False)   # link reset chứa token: không ghi log
    _audit(request, 'PASSWORD_RESET_REQUEST', actor=None, target_user=user, success=sent,
           severity='info' if sent else 'warning',
           metadata=None if sent else {'error': 'send_mail_failed'})
    return _neutral()   # gửi lỗi cũng không báo ra ngoài; đã có audit log


def reset_password(request, uidb64, token):
    try:
        user = User.objects.get(pk=force_str(urlsafe_base64_decode(uidb64)))
    except Exception:
        user = None

    if user is None or not user.is_active or not default_token_generator.check_token(user, token):
        _audit(request, 'PASSWORD_RESET_INVALID', actor=None, success=False, severity='warning',
               target_user=user)
        messages.error(request, 'Yêu cầu không hợp lệ')
        return _render(request, 'reset_password', {'mode': 'expired'})

    ctx = {'mode': 'confirm'}
    if request.method == 'POST':
        p1 = request.POST.get('new_password1') or ''
        p2 = request.POST.get('new_password2') or ''
        if not p1 or p1 != p2:
            messages.error(request, 'Mật khẩu không khớp.')
            return _render(request, 'reset_password', ctx)
        try:
            validate_password(p1, user)
        except ValidationError as e:
            messages.error(request, ' '.join(e.messages))
            return _render(request, 'reset_password', ctx)
        user.set_password(p1)
        user.save()
        from .api.mobile_auth import revoke_all_sessions
        revoke_all_sessions(user)
        _reset_lockout(user)
        _audit(request, 'PASSWORD_RESET_DONE', actor=user, target_user=user)
        _notify(user, 'Mật khẩu đã thay đổi', 'Mật khẩu tài khoản vừa được đặt lại.',
                severity='warning', type_='SECURITY')
        messages.success(request, 'Mật khẩu đã được thay đổi thành công!')
        return redirect('smartlock:login')
    return _render(request, 'reset_password', ctx)




# ====================== SYNC: bootstrap toàn bộ dữ liệu dashboard cho client cache ======================
@auth_required
def sync_bootstrap(request):
    """Trả JSON gộp mọi thứ user thấy trên dashboard - client mã hoá (AES-GCM, khoá suy ra từ
    session hiện tại, xem _ensure_sync_key) rồi lưu vào IndexedDB để tải nhanh + auto refresh
    nền. KHÔNG cấp thêm quyền xem dữ liệu nào ngoài những gì các view khác đã cho phép."""
    user = request.user
    _latest_lock = (DeviceStatusLog.objects.filter(device=OuterRef('pk'))
                    .order_by('-recorded_at').values('lock_state')[:1])
    devices = list(_accessible_devices(user).annotate(last_lock_state=Subquery(_latest_lock))
                   .order_by('name'))
    perms = services.permission_map(user, devices)        # 1 truy vấn cho mọi khoá (trước: 1 truy vấn/khoá)

    devices_json = [{
        'id': str(d.id), 'name': d.name, 'device_code': d.device_code,
        'status': d.status, 'status_display': d.get_status_display(),
        'battery_level': d.battery_level,
        'lock_state': d.last_lock_state or 'unknown',
        'location': d.location or '', 'is_owner': d.owner_id == user.id,
        'permissions': sorted(perms[d.id]),
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
    """Đã đóng: CHỈ quản trị viên được tạo khoá mới (/manage-sys/devices/new/ hoặc Django admin).
    Quản trị đăng ký khoá vào hệ thống rồi (a) gán thẳng cho chủ, hoặc (b) chủ tự thêm bằng mã thiết bị + secret
    ở trang \"Thêm khoá\" (device_claim). Giữ route này để link/nút cũ không gây lỗi."""
    _audit(request, 'DEVICE_ADD_BLOCKED', success=False, severity='warning',
           metadata={'method': request.method})
    messages.info(request, 'Khoá mới do quản trị viên đăng ký. Nếu quản trị đã đăng ký khoá cho bạn, '
                           'hãy nhập mã thiết bị + secret để thêm vào tài khoản.')
    return redirect('smartlock:device-claim')


@auth_required
def devices_list(request):
    devices = _accessible_devices(request.user).order_by('name')
    return _render(request, 'devices_list', {'device_list': devices})








def _mqtt_webhook_authorized(request) -> bool:
    """Broker phải gửi header X-Webhook-Secret khớp settings.MQTT_WEBHOOK_SECRET.
    Chưa cấu hình secret: chỉ bỏ qua kiểm tra khi DEBUG, còn lại từ chối (fail-closed)."""
    secret = getattr(dj_settings, 'MQTT_WEBHOOK_SECRET', None)
    if not secret:
        # Fail-closed: chỉ cho qua khi DEBUG (dev/test). Production thiếu secret -> từ chối.
        if dj_settings.DEBUG:
            logger.warning('MQTT_WEBHOOK_SECRET chưa được đặt: webhook MQTT không được bảo vệ (DEBUG).')
            return True
        logger.error('MQTT_WEBHOOK_SECRET chưa được đặt: từ chối mọi webhook MQTT.')
        return False
    return hmac.compare_digest(str(request.META.get('HTTP_X_WEBHOOK_SECRET', '')), str(secret))


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
    if not _mqtt_webhook_authorized(request):
        return JsonResponse({'ok': False}, status=403)
    username = (request.POST.get('username') or '').strip()
    password = request.POST.get('password') or ''
    if not username or not password:
        return JsonResponse({'ok': False}, status=401)

    # Tài khoản server (publisher/subscriber của Django): so với MQTT_PUBLISHER_PASSWORD.
    if username in getattr(dj_settings, 'MQTT_TRUSTED_USERNAMES', []):
        expected = services.MQTT_PUBLISHER_PASSWORD
        if expected and hmac.compare_digest(password, expected):
            return JsonResponse({'ok': True})
        _audit(request, 'MQTT_AUTH_DENIED', success=False, severity='warning',
               username_attempt=username[:150])
        return JsonResponse({'ok': False}, status=401)

    device = Device.objects.filter(device_code=username).first()
    if not device or not hmac.compare_digest(device.provisioning_secret_hash, _hash_token(password)):
        _audit(request, 'MQTT_AUTH_DENIED', success=False, severity='warning',
               username_attempt=username[:150])
        return JsonResponse({'ok': False}, status=401)

    return JsonResponse({'ok': True})


@csrf_exempt
@require_POST
def mqtt_acl_webhook(request):
    """ACL cho broker (mosquitto-go-auth: acc 1=read, 2=write, 3=readwrite, 4=subscribe).
    Thiết bị chỉ được: đọc/subscribe smartlock/<device_code>/cmd và ghi vào
    smartlock/<device_code>/{status,ack,event}. Không được đụng topic của thiết bị khác.
    Các tài khoản tin cậy (publisher/subscriber của server) khai báo trong MQTT_TRUSTED_USERNAMES."""
    if not _mqtt_webhook_authorized(request):
        return JsonResponse({'ok': False}, status=403)
    username = (request.POST.get('username') or '').strip()
    topic = (request.POST.get('topic') or '').strip()
    try:
        acc = int(request.POST.get('acc') or 0)
    except ValueError:
        acc = 0
    if not username or not topic:
        return JsonResponse({'ok': False}, status=403)

    if username in getattr(dj_settings, 'MQTT_TRUSTED_USERNAMES', []):
        return JsonResponse({'ok': True})

    if not Device.objects.filter(device_code=username).exists():
        return JsonResponse({'ok': False}, status=403)

    parts = topic.split('/')
    if len(parts) != 3 or parts[0] != 'smartlock' or parts[1] != username:
        return JsonResponse({'ok': False}, status=403)
    channel = parts[2]
    can_read = acc in (1, 3, 4) and channel == 'cmd'
    can_write = acc in (2, 3) and channel in ('status', 'ack', 'event')
    if (acc in (1, 4) and can_read) or (acc == 2 and can_write):
        return JsonResponse({'ok': True})
    return JsonResponse({'ok': False}, status=403)






















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
        if nxt and url_has_allowed_host_and_scheme(nxt, {request.get_host()}, require_https=request.is_secure()):
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
    return _render(request, 'notifications', context)


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
    return _render(request, 'profile', context)


@auth_required
def audit_logs(request):
    user = request.user
    # Tài khoản quản trị không dùng trang user; xem log toàn hệ thống chỉ ở cổng manage_sys.
    base = _visible_logs(user)
    qs = base.select_related('device', 'actor_user', 'target_user').order_by('-created_at')

    status = request.GET.get('status')
    if status == 'ok':
        qs = qs.filter(success=True)
    elif status == 'fail':
        qs = qs.filter(success=False)
    q = (request.GET.get('q') or '').strip()
    if q:
        qs = qs.filter(action__icontains=q)

    extra = ''.join('&' + urlencode({k: v}) for k, v in (('status', status), ('q', q)) if v)
    context = {'audit_logs': _page(request, qs), 'show_all': False,
               'status': status or '', 'q': q, 'qs': extra, 'can_see_all': False}
    return _render(request, 'audit_logs', context)


# ====================== PUBLIC DEMO: SYSTEM LOGS REAL-TIME (KHÔNG YÊU CẦU ĐĂNG NHẬP) ======================
# CẢNH BÁO BẢO MẬT: view này show TOÀN BỘ log của TOÀN HỆ THỐNG (mọi user, mọi thiết bị),
# cho bất kỳ ai có URL - KHÔNG cần đăng nhập, KHÔNG lọc theo owner. Chỉ dùng khi demo/bảo
# vệ đồ án trên máy local.
#
# "Real-time" ở đây = JS phía client fetch() JSON endpoint bên dưới mỗi 2 giây rồi tự vẽ
# lại DOM/biểu đồ (KHÔNG F5 trang) - không dùng WebSocket/Django Channels vì project đang
# chạy WSGI (runserver bình thường), không cần đổi sang ASGI + thêm Redis chỉ để demo.
# Polling 2s là đủ "độ trễ thấp" cho mục đích trình bày, không cần hạ tầng phức tạp hơn.

def _bucketed_counts(queryset, dt_field, minutes=20):
    """Đếm số bản ghi theo từng phút trong `minutes` phút gần nhất, KHÔNG bị hụt phút nào
    (phút không có dữ liệu vẫn trả về 0) - dùng để vẽ biểu đồ đường theo thời gian."""
    since = timezone.now() - timedelta(minutes=minutes)
    rows = (
        queryset.filter(**{f'{dt_field}__gte': since})
        .annotate(minute=TruncMinute(dt_field)).values('minute')
        .annotate(n=Count('id')).order_by('minute')
    )
    counts = {r['minute']: r['n'] for r in rows}
    now_minute = timezone.now().replace(second=0, microsecond=0)
    labels, data = [], []
    for i in range(minutes - 1, -1, -1):
        m = now_minute - timedelta(minutes=i)
        labels.append(m.strftime('%H:%M'))
        data.append(counts.get(m, 0))
    return labels, data


def _bucketed_avg(queryset, dt_field, value_field, minutes=20):
    """Giống _bucketed_counts nhưng lấy TRUNG BÌNH của value_field theo từng phút
    (vd: pin trung bình, nhiệt độ trung bình). Phút không có dữ liệu -> None (Chart.js
    tự bỏ qua điểm đó, không vẽ về 0 gây hiểu nhầm)."""
    since = timezone.now() - timedelta(minutes=minutes)
    rows = (
        queryset.filter(**{f'{dt_field}__gte': since, f'{value_field}__isnull': False})
        .annotate(minute=TruncMinute(dt_field)).values('minute')
        .annotate(avg=Avg(value_field)).order_by('minute')
    )
    avgs = {r['minute']: r['avg'] for r in rows}
    now_minute = timezone.now().replace(second=0, microsecond=0)
    labels, data = [], []
    for i in range(minutes - 1, -1, -1):
        m = now_minute - timedelta(minutes=i)
        labels.append(m.strftime('%H:%M'))
        v = avgs.get(m)
        data.append(round(v, 1) if v is not None else None)
    return labels, data


def _require_demo_logs(request):
    """Trang log công khai chỉ bật khi settings.DEMO_LOGS_ENABLED = True (mặc định = DEBUG).
    Khi DEBUG=False (production) mà vẫn bật cờ này thì chỉ quản trị viên đã đăng nhập mới xem được,
    tránh lộ log toàn hệ thống cho người lạ."""
    if not getattr(dj_settings, 'DEMO_LOGS_ENABLED', False):
        raise Http404()
    if not dj_settings.DEBUG:
        user = getattr(request, 'user', None)
        if not (user and user.is_authenticated and _is_admin(user)):
            raise Http404()


def public_system_logs(request):
    """Trang khung (shell) - không truyền dữ liệu log qua context. Toàn bộ số liệu/log/
    biểu đồ được JS nạp qua public_system_logs_api() và tự làm mới liên tục."""
    _require_demo_logs(request)
    return render(request, 'public/system_logs.html', {})


_LOGIN_OK_ACTIONS = ('LOGIN',)
_LOGIN_FAIL_ACTIONS = ('LOGIN_FAILED', 'LOGIN_ADMIN_REJECTED')


def _login_attempts():
    """Lượt đăng nhập lấy từ AuditLog (bảng LoginAttemptLog cũ đã gộp vào AuditLog)."""
    return AuditLog.objects.filter(action__in=_LOGIN_OK_ACTIONS + _LOGIN_FAIL_ACTIONS)


LOG_ROW_LIMIT = 100  # số dòng gần nhất trả về mỗi loại log (tăng từ 40 -> 100 để trang demo hiển thị nhiều hơn)


def public_system_logs_api(request):
    """JSON snapshot mới nhất của TOÀN BỘ log trong hệ thống - client gọi lại mỗi 2s.
    Chỉ đọc (GET), không có tham số nào làm thay đổi dữ liệu."""
    _require_demo_logs(request)
    _ls = DeviceStatusLog.objects.filter(device=OuterRef('pk')).order_by('-recorded_at')
    devices = (Device.objects.select_related('owner')
               .annotate(l_lock=Subquery(_ls.values('lock_state')[:1]),
                         l_tamper=Subquery(_ls.values('tamper_detected')[:1]),
                         l_temp=Subquery(_ls.values('temperature')[:1]),
                         l_sig=Subquery(_ls.values('signal_strength')[:1]))
               .order_by('name'))
    device_rows = []
    for d in devices:
        device_rows.append({
            'id': str(d.id), 'name': d.name, 'code': d.device_code, 'status': d.status,
            'battery_level': d.battery_level,
            'lock_state': d.l_lock,
            'tamper_detected': bool(d.l_tamper),
            'temperature': str(d.l_temp) if d.l_temp is not None else None,
            'signal_strength': d.l_sig,
            'last_seen_at': d.last_seen_at.isoformat() if d.last_seen_at else None,
            'owner': d.owner.username if d.owner else None,
            'bluetooth_enabled': d.bluetooth_enabled, 'wifi_enabled': d.wifi_enabled,
            'nfc_enabled': d.nfc_enabled,
        })

    commands = (DeviceCommand.objects.select_related('device', 'issued_by')
                .order_by('-created_at')[:LOG_ROW_LIMIT])
    command_rows = [{
        'time': c.created_at.isoformat(), 'device': c.device.name if c.device else '—',
        'command_type': c.command_type, 'status': c.status,
        'issued_by': c.issued_by.username if c.issued_by else '—',
        'expires_at': c.expires_at.isoformat() if c.expires_at else None,
        'acknowledged_at': c.acknowledged_at.isoformat() if c.acknowledged_at else None,
    } for c in commands]

    status_logs = DeviceStatusLog.objects.select_related('device').order_by('-recorded_at')[:LOG_ROW_LIMIT]
    status_rows = [{
        'time': s.recorded_at.isoformat(), 'device': s.device.name if s.device else '—',
        'battery_level': s.battery_level, 'lock_state': s.lock_state,
        'tamper_detected': s.tamper_detected,
        'temperature': str(s.temperature) if s.temperature is not None else None,
        'signal_strength': s.signal_strength,
    } for s in status_logs]

    nfc_logs = NfcLog.objects.select_related('device', 'user', 'reader').order_by('-created_at')[:LOG_ROW_LIMIT]
    nfc_rows = [{
        'time': n.created_at.isoformat(), 'device': n.device.name if n.device else '—',
        'user': n.user.username if n.user else '—', 'event_type': n.event_type,
        'success': n.success, 'ip': n.ip_address,
        'reader': n.reader.id and str(n.reader) if n.reader else '—',
    } for n in nfc_logs]

    audit_logs = (AuditLog.objects.select_related('device', 'actor_user', 'target_user')
                  .order_by('-created_at')[:LOG_ROW_LIMIT])
    audit_rows = [{
        'time': a.created_at.isoformat(), 'action': a.action,
        'actor': a.actor_user.username if a.actor_user else (a.username_attempt or '—'),
        'target': a.target_user.username if a.target_user else '—',
        'device': a.device.name if a.device else '—',
        'severity': a.severity, 'success': a.success, 'ip': a.ip_address,
    } for a in audit_logs]

    login_attempts = (_login_attempts().select_related('actor_user', 'target_user')
                      .order_by('-created_at')[:LOG_ROW_LIMIT])
    login_rows = []
    for la in login_attempts:
        who = la.target_user or la.actor_user
        login_rows.append({
            'time': la.created_at.isoformat(),
            'identifier': la.username_attempt or (who.email if who else '—'),
            'user': who.username if who else '—', 'success': la.action in _LOGIN_OK_ACTIONS,
            'ip': la.ip_address,
        })

    labels, lock_series = _bucketed_counts(DeviceCommand.objects.filter(command_type='LOCK'), 'created_at')
    _, unlock_series = _bucketed_counts(DeviceCommand.objects.filter(command_type='UNLOCK'), 'created_at')
    _, nfc_ok_series = _bucketed_counts(NfcLog.objects.filter(success=True), 'created_at')
    _, nfc_fail_series = _bucketed_counts(NfcLog.objects.filter(success=False), 'created_at')
    _, audit_total_series = _bucketed_counts(AuditLog.objects.all(), 'created_at')
    _, audit_fail_series = _bucketed_counts(AuditLog.objects.filter(success=False), 'created_at')
    _, login_ok_series = _bucketed_counts(AuditLog.objects.filter(action__in=_LOGIN_OK_ACTIONS), 'created_at')
    _, login_fail_series = _bucketed_counts(AuditLog.objects.filter(action__in=_LOGIN_FAIL_ACTIONS), 'created_at')
    _, status_report_series = _bucketed_counts(DeviceStatusLog.objects.all(), 'recorded_at')
    _, tamper_series = _bucketed_counts(DeviceStatusLog.objects.filter(tamper_detected=True), 'recorded_at')
    _, avg_battery_series = _bucketed_avg(DeviceStatusLog.objects.all(), 'recorded_at', 'battery_level')
    _, avg_temp_series = _bucketed_avg(DeviceStatusLog.objects.all(), 'recorded_at', 'temperature')

    since_24h = timezone.now() - timedelta(hours=24)
    stats = {
        'total_devices': devices.count(),
        'devices_online': devices.filter(status='online').count(),
        'total_users': User.objects.count(),
        'total_commands': DeviceCommand.objects.count(),
        'total_status_logs': DeviceStatusLog.objects.count(),
        'total_nfc_logs': NfcLog.objects.count(),
        'total_audit_logs': AuditLog.objects.count(),
        'total_login_attempts': _login_attempts().count(),
        'failed_audit_24h': AuditLog.objects.filter(success=False, created_at__gte=since_24h).count(),
        'failed_nfc_24h': NfcLog.objects.filter(success=False, created_at__gte=since_24h).count(),
        'failed_login_24h': AuditLog.objects.filter(action__in=_LOGIN_FAIL_ACTIONS, created_at__gte=since_24h).count(),
    }

    return JsonResponse({
        'server_time': timezone.now().isoformat(),
        'stats': stats,
        'devices': device_rows,
        'commands': command_rows,
        'status_logs': status_rows,
        'nfc_logs': nfc_rows,
        'rule_logs': [],      # đã bỏ tự động hoá - xoá panel này trong public/system_logs.html
        'audit_logs': audit_rows,
        'login_attempts': login_rows,
        'chart': {
            'labels': labels, 'lock': lock_series, 'unlock': unlock_series,
            'nfc_ok': nfc_ok_series, 'nfc_fail': nfc_fail_series,
            'audit_total': audit_total_series, 'audit_fail': audit_fail_series,
            'login_ok': login_ok_series, 'login_fail': login_fail_series,
            'rule_fires': [0] * len(labels), 'status_reports': status_report_series,
            'tamper_events': tamper_series,
            'avg_battery': avg_battery_series, 'avg_temp': avg_temp_series,
        },
    })


# ====================== 2FA: CONSTANTS ======================
SESSION_KEY = 'pending_2fa'            # {user_id, purpose, backend, next, ts, fails}
PENDING_TTL = 10 * 60                  # 10 phút để hoàn tất bước 2
MAX_PENDING_FAILS = 5                  # sai quá 5 lần trong 1 phiên -> hủy phiên, phải nhập lại mật khẩu
EMAIL_CODE_TTL_MIN = 10
EMAIL_CODE_COOLDOWN = 60               # giây giữa 2 lần gửi mã
EMAIL_CODE_MAX_ATTEMPTS = 5
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


# ====================== HÀM PHỤ (mã hóa / TOTP / email) ======================
def _pepper_hash(user, value: str) -> str:
    """HMAC-SHA256 gắn với SECRET_KEY + user để lưu hash của mã OTP."""
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


def _send_email_code(user, purpose):
    """purpose: 'SETUP' (thiết lập Email OTP) hoặc 'VERIFY' (login/enable/disable).
    Trả về 'sent' | 'cooldown' | 'failed'."""
    now = timezone.now()
    if OneTimeCode.objects.filter(
            user=user, purpose__in=('TF_SETUP', 'TF_VERIFY'),
            created_at__gt=now - timedelta(seconds=EMAIL_CODE_COOLDOWN)).exists():
        return 'cooldown'
    code = f'{secrets.randbelow(10 ** 6):06d}'
    OneTimeCode.objects.filter(user=user, purpose__in=('TF_SETUP', 'TF_VERIFY'),
                               is_used=False).update(is_used=True)
    OneTimeCode.objects.create(
        user=user, purpose='TF_' + purpose, token_hash=_pepper_hash(user, 'em:' + code),
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
        ok = hmac.compare_digest(rec.token_hash, _pepper_hash(user, 'em:' + code))
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
    locked_until = User.objects.filter(pk=user.pk).values_list('login_locked_until', flat=True).first()
    now = timezone.now()
    if locked_until and locked_until > now:
        return math.ceil((locked_until - now).total_seconds() / 60)
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
        _notify_login(request, user)
        _audit(request, 'LOGIN', actor=user, metadata={'two_factor': method})
        messages.success(request, 'Đăng nhập thành công!')
        nxt = p.get('next') or ''
        if nxt and url_has_allowed_host_and_scheme(nxt, {request.get_host()}, require_https=request.is_secure()):
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
    if tab not in methods:
        tab = default_tab
    title, subtitle = PURPOSE_TEXT.get(p['purpose'], PURPOSE_TEXT['login'])
    return _render(request, 'verify_2fa', {
        'purpose': p['purpose'], 'title': title, 'subtitle': subtitle,
        'has_totp': 'totp' in methods, 'has_fido2': 'fido2' in methods, 'has_email': 'email' in methods,
        'tab': tab,
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
    """Ghi log, thông báo."""
    _audit(request, 'TWO_FACTOR_METHOD_ADDED', target_user=user, severity='warning', metadata={'method': method})
    _notify(user, 'Đã thêm phương thức 2FA', f'Phương thức {method.upper()} vừa được thêm vào tài khoản.',
            severity='info', type_='SECURITY')
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
    sync_two_fa_flag(user)
    _audit(request, 'TWO_FACTOR_METHOD_REMOVED', target_user=user, severity='warning', metadata={'method': method})
    _notify(user, 'Đã gỡ phương thức 2FA', f'Phương thức {method.upper()} vừa được gỡ khỏi tài khoản.',
            severity='warning', type_='SECURITY')
    messages.success(request, 'Đã gỡ phương thức xác thực.')


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
        'tf_email_pending': False,
        'tf_totp_setup': None,
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

 
 
 
 


# ====================== DEVICES: USER TỰ THÊM KHOÁ (gộp từ views_device.py) ======================
# User tự thêm khoá (kể cả khoá đã bị gỡ chủ / chủ cũ) bằng mã thiết bị + secret.
# Mọi nhánh (kể cả từ chối/lỗi) đều ghi AuditLog.
@auth_required
@require_http_methods(['GET', 'POST'])
def device_claim(request):
    if request.method == 'POST':
        code = (request.POST.get('device_code') or '').strip()[:50]
        secret = request.POST.get('secret') or ''
        try:
            device = services.user_claim_device(request.user, code, secret, request)
        except services.ClaimError as exc:
            services.audit(request, 'DEVICE_CLAIM_FAILED', success=False, severity='warning',
                           metadata={'device_code_input': code.upper(), 'code': exc.code})
            messages.error(request, exc.message)
            return redirect('smartlock:device-claim')
        services.audit(request, 'DEVICE_CLAIMED', device=device, target_user=request.user,
                       severity='warning', metadata={'by': 'user'})
        services.notify(request.user, 'Đã thêm khoá vào tài khoản',
                        f'Khoá "{device.name}" ({device.device_code}) đã được gán cho bạn.',
                        device=device, type_='DEVICE')
        messages.success(request, f'Đã thêm khoá "{device.name}".')
        return redirect('smartlock:device-detail', device_id=device.id)
    return _render(request, 'device_claim')


# ====================== FACE: XOÁ HẲN HỒ SƠ KHUÔN MẶT (dữ liệu sinh trắc - NĐ 13/2023) ======================
@auth_required
@require_POST
def face_profile_delete(request, profile_id):
    pid = services.parse_uuid(profile_id)
    profile = FaceProfile.objects.select_related('device').filter(id=pid).first() if pid else None
    # Chủ khoá xoá được mọi hồ sơ của khoá; người khác chỉ xoá hồ sơ của chính mình.
    if profile and profile.user_id != request.user.id and profile.device.owner_id != request.user.id:
        profile = None
    if not profile:
        services.audit(request, 'FACE_PROFILE_DELETE_DENIED', success=False, severity='warning',
                       metadata={'profile_id': str(profile_id)[:64]})
        messages.error(request, 'Không tìm thấy hồ sơ khuôn mặt.')
        return redirect('smartlock:face-profiles')
    device, owner_of_profile, info = profile.device, profile.user, {'face_profile_id': str(profile.id)}
    profile.delete()
    services.audit(request, 'FACE_PROFILE_DELETED', device=device, target_user=owner_of_profile,
                   severity='warning', metadata=info)
    messages.success(request, 'Đã xoá hồ sơ khuôn mặt.')
    return redirect(f"{reverse('smartlock:face-profiles')}?device={device.id}")


# =====================================================================================================
#  PHẦN TÍNH NĂNG KHOÁ (viết lại) - dành cho USER thường (chủ khoá + người được chia sẻ)
#
#  Kênh thao tác:
#    * TRÌNH DUYỆT  -> qua Wi-Fi/Internet: mở/khoá từ xa (device_command), quản lý thẻ, PIN, khuôn mặt,
#                      chia sẻ, xem lịch sử. KHÔNG dùng Bluetooth/NFC.
#    * ĐIỆN THOẠI   -> app xin "vé" qua mạng, rồi dùng Bluetooth (BLE) hoặc NFC giả lập thẻ (HCE)
#                      để mở khi đứng gần cửa. Quyền BLE/NFC là quyền của hệ điều hành điện thoại.
#  Mỗi tính năng có 1 quyền riêng (services.PERMISSION_CATALOG); chủ khoá có đủ, người được chia sẻ
#  chỉ có quyền chủ đã chọn. Giao diện dùng `caps` (services.capabilities) để hiện/ẩn từng khối.
# =====================================================================================================

# ====================== DASHBOARD ======================
@auth_required
def dashboard(request):
    user = request.user
    devices_qs = _accessible_devices(user).order_by('name')
    devices = list(devices_qs)       # tải 1 lần; chọn/đếm bằng Python (trước: 4 truy vấn). QuerySet đã có cache kết quả
    wanted = _parse_uuid(request.GET.get('device'))
    current = next((d for d in devices if d.id == wanted), None) or (devices[0] if devices else None)

    caps = None
    if current:
        last_log = DeviceStatusLog.objects.filter(device=current).order_by('-recorded_at').first()
        current.lock_state = last_log.lock_state if last_log else 'unknown'
        caps = services.capabilities(user, current)

    today = timezone.localdate()
    days = [today - timedelta(days=i) for i in range(6, -1, -1)]
    counts = {
        r['d']: r['c'] for r in
        _visible_logs(user).filter(created_at__date__gte=days[0])
        .annotate(d=TruncDate('created_at')).values('d').annotate(c=Count('id'))
    }
    context = {
        'devices': devices_qs,           # giữ kiểu QuerySet (template cũ có thể gọi .count); đã cache nên không truy vấn lại
        'current_device': current,
        'caps': caps,
        'total_devices': len(devices),
        'online_devices': sum(1 for d in devices if d.status == 'online'),
        'unread_count': Notification.objects.filter(user=user, is_read=False).count(),
        'recent_notifications': list(Notification.objects.filter(user=user).order_by('-created_at')[:4]),
        'recent_logs': list(_visible_logs(user).select_related('device').order_by('-created_at')[:6]),
        'announcements': list(Announcement.objects.filter(is_active=True).order_by('-created_at')[:3]),
        'chart_data': {'labels': [d.strftime('%d/%m') for d in days],
                       'values': [counts.get(d, 0) for d in days]},
    }
    return _render(request, 'dashboard', context)


# ====================== DEVICE DETAIL ======================
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
    caps = services.capabilities(request.user, device)
    accesses = []
    if is_owner:
        accesses = (DeviceAccess.objects.filter(device=device, is_active=True)
                    .select_related('user').prefetch_related('permissions'))
    context = {
        'device': device,
        'is_owner': is_owner,
        'caps': caps,
        'last_log': last_log,
        'recent_commands': DeviceCommand.objects.filter(device=device)
                           .select_related('issued_by').order_by('-created_at')[:6],
        'accesses': accesses,
    }
    return _render(request, 'device_detail', context)


# ====================== MỞ / KHOÁ TỪ XA (trình duyệt, qua Wi-Fi/Internet) ======================
COMMAND_LABELS = {'LOCK': 'Khóa', 'UNLOCK': 'Mở khóa', 'REBOOT': 'Khởi động lại'}


def _command_reply(ok, message, status=200, **extra):
    """JSON cho JS: `popup` để hiện popup trong trang (SmartLockPopup.show), không dùng thông báo trình duyệt."""
    popup = {'title': 'Thành công' if ok else 'Không thực hiện được', 'message': message,
             'severity': 'info' if ok else 'warning'}
    return JsonResponse({'ok': ok, 'message': message, 'popup': popup, **extra}, status=status)


@auth_required
@require_POST
def device_command(request, device_id):
    device = get_object_or_404(_accessible_devices(request.user), id=device_id)
    command = (request.POST.get('command') or '').upper()
    if command not in ALLOWED_COMMANDS:
        _audit(request, 'CMD_INVALID', device=device, success=False, severity='warning',
               metadata={'command': command[:30]})
        return _command_reply(False, 'Lệnh không hợp lệ.', 400)

    needed = ALLOWED_COMMANDS[command]
    allowed = (device.owner_id == request.user.id) if needed is None \
        else _has_permission(request.user, device, needed)
    if not allowed:
        _audit(request, f'CMD_{command}_DENIED', device=device, success=False, severity='warning')
        return _command_reply(False, 'Bạn không có quyền thực hiện lệnh này.', 403)
    if not device.wifi_enabled:
        return _command_reply(False, 'Wi-Fi của khoá đang tắt nên không điều khiển từ xa được.', 409)
    if device.status != 'online':
        _audit(request, f'CMD_{command}_FAILED', device=device, success=False,
               metadata={'reason': 'device_not_online', 'status': device.status})
        return _command_reply(False, 'Thiết bị đang không online.', 409)

    now = timezone.now()
    # 'sent' cũng là trạng thái chưa xong (đã publish, chờ ack) -> phải tính vào hết hạn & chống trùng.
    DeviceCommand.objects.filter(device=device, status__in=('pending', 'sent'),
                                 expires_at__lte=now).update(status='expired')
    if DeviceCommand.objects.filter(device=device, status__in=('pending', 'sent'), command_type=command,
                                    created_at__gte=now - timedelta(seconds=10)).exists():
        _audit(request, f'CMD_{command}_FAILED', device=device, success=False,
               metadata={'reason': 'duplicate_pending'})
        return _command_reply(False, 'Lệnh này vừa được gửi, vui lòng chờ vài giây.', 429)

    cmd = services.dispatch_command(device, command, source='web', issued_by=request.user,
                                    ttl=COMMAND_TTL_SECONDS)
    if cmd.status != 'sent':
        _audit(request, f'CMD_{command}_FAILED', device=device, success=False,
               metadata={'reason': 'mqtt_publish_failed', 'error': cmd.publish_error})
        return _command_reply(False, 'Không kết nối được tới thiết bị. Vui lòng thử lại.', 502)

    _audit(request, f'CMD_{command}', device=device, metadata={'command_id': str(cmd.id)})
    return _command_reply(True, f'Đã gửi lệnh {COMMAND_LABELS.get(command, command)} tới "{device.name}".',
                          command_id=str(cmd.id))


# ====================== ĐIỆN THOẠI: VÉ BLUETOOTH / NFC GIẢ LẬP THẺ ======================
def _phone_ticket(request, device_id, kind):
    """App (đang có mạng) xin vé; đến gần cửa thì đưa vé cho khoá qua BLE hoặc qua NFC (HCE).
    Khoá tự kiểm tra chữ ký + hạn, không cần mạng (xem services.issue_phone_ticket)."""
    cfg = services.PHONE_CHANNELS[kind]
    device = get_object_or_404(_accessible_devices(request.user), id=device_id)
    if not getattr(device, cfg['flag']) or device.status not in ('online', 'offline'):
        return JsonResponse({'ok': False, 'message': f"Thiết bị không dùng được {cfg['name']} lúc này."},
                            status=409)
    if not _has_permission(request.user, device, cfg['permission']):
        _audit(request, f"{cfg['prefix']}_TICKET_DENIED", device=device, success=False, severity='warning')
        return JsonResponse({'ok': False, 'message': f"Bạn không có quyền mở khóa bằng {cfg['name']}."},
                            status=403)
    ticket, exp = services.issue_phone_ticket(device, request.user, kind)
    _audit(request, f"{cfg['prefix']}_TICKET_ISSUED", device=device, metadata={'expires_at': exp})
    return JsonResponse({'ok': True, 'ticket': ticket, 'expires_at': exp, 'device_code': device.device_code})


@auth_required
@require_POST
def device_ble_ticket(request, device_id):
    return _phone_ticket(request, device_id, 'ble')


@auth_required
@require_POST
def device_nfc_ticket(request, device_id):
    return _phone_ticket(request, device_id, 'nfc')


# ====================== THẺ NFC ======================
@auth_required
def nfc_tags(request):
    """Thẻ của MÌNH (đổi tên/bật-tắt/xoá) + thẻ đang gắn vào các khoá mình có quyền manage_nfc
    (chủ khoá hoặc người được chia sẻ quyền này được bật/tắt thẻ đó TRÊN KHOÁ của họ)."""
    user = request.user
    managed = list(services.devices_with_permission(user, 'manage_nfc').values_list('id', 'owner_id'))
    managed_ids = {i for i, _ in managed}                       # khoá mình được dùng tính năng thẻ
    owned_ids = {i for i, o in managed if o == user.id}         # khoá mình là CHỦ (mới thấy thẻ của người khác)

    if request.method == 'POST':
        action = request.POST.get('action')
        card = AccessCard.objects.filter(id=_parse_uuid(request.POST.get('card_id'))).first()
        mine = bool(card and card.user_id == user.id)
        if not card:
            _audit(request, 'CARD_NOT_FOUND', success=False, severity='warning',
                   metadata={'card_id': str(request.POST.get('card_id'))[:64], 'action': str(action)[:30]})
            messages.error(request, 'Không tìm thấy thẻ.')
        elif action in ('toggle', 'rename', 'delete') and not mine:
            _audit(request, 'CARD_ACTION_DENIED', success=False, severity='warning',
                   metadata={'card_id': str(card.id), 'action': action})
            messages.error(request, 'Đây không phải thẻ của bạn.')
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
            _audit(request, 'CARD_RENAMED', metadata={'card_id': str(card.id), 'from': old_name, 'to': card.name})
            messages.success(request, 'Đã đổi tên thẻ.')
        elif action == 'delete':
            info = {'card_id': str(card.id), 'name': card.name,
                    'devices': [str(d) for d in card.carddeviceaccess_set.values_list('device_id', flat=True)]}
            card.delete()
            _audit(request, 'CARD_DELETED', metadata=info)
            messages.success(request, 'Đã xóa thẻ.')
        elif action == 'toggle_link':
            # Bật/tắt thẻ trên MỘT khoá cụ thể - dành cho người quản lý khoá đó.
            device_id = _parse_uuid(request.POST.get('device_id'))
            link = (CardDeviceAccess.objects.select_related('device')
                    .filter(access_card=card, device_id=device_id).first())
            # Chủ khoá bật/tắt được thẻ của mọi người trên khoá của mình; người khác chỉ thẻ CỦA MÌNH.
            if not link or not (link.device_id in owned_ids or (mine and link.device_id in managed_ids)):
                _audit(request, 'CARD_LINK_DENIED', success=False, severity='warning',
                       metadata={'card_id': str(card.id), 'device_id': str(device_id)})
                messages.error(request, 'Bạn không có quyền quản lý thẻ trên khoá này.')
            else:
                link.is_active = not link.is_active
                link.save(update_fields=['is_active'])
                _audit(request, 'CARD_LINK_ENABLED' if link.is_active else 'CARD_LINK_DISABLED',
                       device=link.device, target_user=card.user, metadata={'card_id': str(card.id)})
                messages.success(request, 'Đã bật thẻ trên khoá này.' if link.is_active
                                 else 'Đã tắt thẻ trên khoá này.')
        return redirect('smartlock:nfc-tags')

    cards = list(AccessCard.objects
                 .filter(Q(user=user) | Q(carddeviceaccess__device_id__in=owned_ids)).distinct()
                 .select_related('user').prefetch_related('carddeviceaccess_set__device')
                 .order_by('-created_at'))
    for c in cards:
        c.is_mine = c.user_id == user.id
        # Thẻ của người khác: chỉ hiện các khoá mà mình quản lý, không lộ khoá khác của họ.
        c.visible_links = [l for l in c.carddeviceaccess_set.all() if c.is_mine or l.device_id in owned_ids]
    return _render(request, 'nfc_tags', {'access_cards': cards, 'can_manage_any': bool(managed_ids)})


@auth_required
def nfc_reader(request):
    """Đăng ký thẻ NFC cho khoá. Chủ khoá còn quản lý đầu đọc + bật chế độ đăng ký bằng quẹt thẻ
    (chế độ này gắn thẻ cho CHỦ khoá nên người được chia sẻ không được bật)."""
    user = request.user
    is_post = request.method == 'POST'
    devices = services.devices_with_permission(user, 'manage_nfc').order_by('name')
    device = _pick_device(devices, request.POST.get('device') or request.GET.get('device'), strict=is_post)
    is_owner = bool(device and device.owner_id == user.id)

    if is_post:
        if not device:
            _audit(request, 'NFC_DEVICE_NOT_FOUND', success=False, severity='warning',
                   metadata={'device': str(request.POST.get('device') or request.GET.get('device'))[:64]})
            messages.error(request, 'Không tìm thấy thiết bị hoặc bạn không có quyền quản lý thẻ NFC.')
            return redirect('smartlock:devices-list')

        action = request.POST.get('action')
        back = lambda: _redirect_with('smartlock:nfc-reader', device=device.id)

        if not device.nfc_enabled:
            messages.error(request, 'NFC của khoá đang tắt.')
            return back()

        if action in ('add_reader', 'toggle_reader', 'toggle_auto') and not is_owner:
            _audit(request, 'NFC_READER_DENIED', device=device, success=False, severity='warning',
                   metadata={'action': action})
            messages.error(request, 'Chỉ chủ khoá mới được cấu hình đầu đọc.')
            return back()

        if action == 'add_reader':
            name = (request.POST.get('name') or '').strip()[:100] or 'Đầu đọc mô phỏng'
            with transaction.atomic():
                reader = NfcReader.objects.create(device=device, reader_mode='simulated',
                                                  name=name, is_active=True)
                NfcLog.objects.create(reader=reader, device=device, user=user,
                                      event_type='READER_CONNECTED', ip_address=_client_ip(request),
                                      user_agent=_user_agent(request))
            _audit(request, 'NFC_READER_ADDED', device=device, metadata={'reader_id': str(reader.id), 'name': name})
            messages.success(request, 'Đã thêm đầu đọc.')
            return back()

        if action in ('toggle_reader', 'toggle_auto'):
            reader = NfcReader.objects.filter(id=_parse_uuid(request.POST.get('reader_id')), device=device).first()
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
                reader.auto_register = not reader.auto_register
                reader.save()
                event = 'CONFIG_UPDATED'
                audit_action = 'NFC_AUTO_REGISTER_ON' if reader.auto_register else 'NFC_AUTO_REGISTER_OFF'
            NfcLog.objects.create(reader=reader, device=device, user=user, event_type=event,
                                  ip_address=_client_ip(request), user_agent=_user_agent(request))
            _audit(request, audit_action, device=device, metadata={'reader_id': str(reader.id)})
            messages.success(request, 'Đã cập nhật đầu đọc.')
            return back()

        if action == 'register_card':
            uid = services.normalize_uid(request.POST.get('uid'))
            name = (request.POST.get('name') or '').strip()[:100] or None
            if len(uid) < 4:
                messages.error(request, 'UID thẻ không hợp lệ.')
                return back()
            try:
                with transaction.atomic():
                    if AccessCard.objects.filter(card_uid_hash=_hash_token(uid)).exists():
                        raise IntegrityError('card uid already registered (legacy hash)')
                    card = AccessCard.objects.create(
                        card_uid_hash=_hash_card_uid(uid), user=user, name=name, is_active=True)
                    CardDeviceAccess.objects.create(access_card=card, device=device)
            except IntegrityError:
                _audit(request, 'CARD_REGISTER_FAILED', device=device, success=False,
                       severity='warning', metadata={'reason': 'duplicate'})
                messages.error(request, 'Thẻ này đã được đăng ký.')
                return back()
            reader = NfcReader.objects.filter(device=device, is_active=True).first()
            NfcLog.objects.create(reader=reader, nfc_tag=card, device=device, user=user,
                                  event_type='CARD_REGISTER', ip_address=_client_ip(request),
                                  user_agent=_user_agent(request))
            _audit(request, 'CARD_REGISTERED', device=device, metadata={'card_id': str(card.id), 'name': name})
            if not is_owner:      # người được chia sẻ thêm thẻ -> báo chủ khoá (popup + push)
                _notify(device.owner, 'Có thẻ NFC mới trên khoá của bạn',
                        f'{user.username} vừa đăng ký thẻ "{name or "không tên"}" cho "{device.name}".',
                        device=device, type_='CARD')
            messages.success(request, 'Đã đăng ký thẻ NFC.')
            return back()
        return back()

    context = {
        'device_list': devices,
        'device': device,
        'is_owner': is_owner,
        'readers': NfcReader.objects.filter(device=device).order_by('-created_at') if device else [],
        'nfc_logs': (NfcLog.objects.filter(device=device).select_related('nfc_tag', 'reader')
                     .filter(**({} if is_owner else {'user': user}))      # không phải chủ: chỉ log của chính mình
                     .order_by('-created_at')[:10]) if device else [],
    }
    return _render(request, 'nfc_reader', context)


# ====================== CHIA SẺ KHOÁ (thay cho tab "mã chia sẻ 6 số" + trang cấp quyền) ======================
# Chủ khoá nhập email/username người nhận + chọn quyền + (tuỳ chọn) hạn dùng -> quyền có hiệu lực NGAY,
# KHÔNG cần người nhận xác nhận. Người nhận được báo bằng EMAIL + thông báo/popup trong app.
# Mã 6 số trước đây không còn: đó là PIN bấm trên bàn phím, nay nằm ở trang "Mã PIN" (door_pins).
@auth_required
def shares_manage(request):
    user = request.user
    services.ensure_default_permissions()
    is_post = request.method == 'POST'
    owned = Device.objects.filter(owner=user).order_by('name')
    device = _pick_device(owned, request.POST.get('device') or request.GET.get('device'), strict=is_post)

    if is_post:
        action = request.POST.get('action')

        # Người được chia sẻ tự rời khỏi 1 khoá (không cần là chủ).
        if action == 'leave':
            access = (DeviceAccess.objects.select_related('device', 'device__owner')
                      .filter(id=_parse_uuid(request.POST.get('access_id')), user=user, is_active=True).first())
            if not access:
                messages.error(request, 'Không tìm thấy quyền truy cập.')
            else:
                access.is_active = False
                access.revoked_at = timezone.now()
                access.save(update_fields=['is_active', 'revoked_at'])
                _audit(request, 'ACCESS_LEFT', device=access.device, target_user=access.device.owner,
                       metadata={'access_id': str(access.id)})
                if access.device.owner_id:
                    _notify(access.device.owner, 'Người dùng đã rời khỏi khoá được chia sẻ',
                            f'{user.username} không còn dùng khoá "{access.device.name}" nữa.',
                            device=access.device, type_='SHARE')
                messages.success(request, 'Bạn đã rời khỏi khoá này.')
            return redirect('smartlock:shares')

        if not device:
            _audit(request, 'ACCESS_DEVICE_NOT_FOUND', success=False, severity='warning',
                   metadata={'device': str(request.POST.get('device') or request.GET.get('device'))[:64]})
            messages.error(request, 'Không tìm thấy thiết bị của bạn.')
            return redirect('smartlock:shares')

        back = lambda: _redirect_with('smartlock:shares', device=device.id)
        # Chọn vai trò mẫu (preset) thì dùng bộ quyền của vai trò đó; không chọn thì dùng các ô tích tay.
        preset = (request.POST.get('preset') or '').strip()
        if preset and services.preset_codes(preset) is None:
            messages.error(request, 'Vai trò mẫu không hợp lệ.')
            return back()
        wanted_codes = services.preset_codes(preset) if preset else request.POST.getlist('permissions')
        perms = list(Permission.objects.filter(code__in=wanted_codes))
        perm_codes = sorted(p.code for p in perms)

        if action == 'grant':
            identifier = request.POST.get('identifier')
            target = _find_user(identifier)
            raw_exp = (request.POST.get('expires_at') or '').strip()
            expires = _parse_dt(raw_exp)
            now = timezone.now()
            if raw_exp and expires is None:
                messages.error(request, 'Định dạng thời điểm hết hạn không hợp lệ.')
            elif not target or not target.is_active:
                _audit(request, 'ACCESS_GRANT_FAILED', device=device, success=False,
                       username_attempt=(identifier or '')[:150], metadata={'reason': 'user_not_found'})
                messages.error(request, 'Không tìm thấy người dùng (email hoặc username).')
            elif target.id == user.id:
                messages.error(request, 'Bạn đã là chủ thiết bị này.')
            elif expires and expires <= now:
                messages.error(request, 'Thời điểm hết hạn phải ở tương lai.')
            elif not perms:
                messages.error(request, 'Hãy chọn ít nhất một quyền để chia sẻ.')
            else:
                access, created = services.grant_access(device, user, target, perms, expires)
                _audit(request, 'ACCESS_GRANTED' if created else 'ACCESS_UPDATED', device=device,
                       target_user=target,
                       metadata={'access_id': str(access.id), 'permissions': perm_codes,
                                 'expires_at': expires.isoformat() if expires else None})
                emailed = services.notify_access_shared(request, access, created)
                msg = f'Đã chia sẻ khoá "{device.name}" cho {target.username}'
                messages.success(request, msg + (' và gửi email thông báo.' if emailed else '.'))
                if not emailed:
                    messages.warning(request, 'Không gửi được email cho người nhận (họ vẫn thấy thông báo trong app).')

        elif action in ('update', 'revoke'):
            access = (DeviceAccess.objects.select_related('user')
                      .filter(id=_parse_uuid(request.POST.get('access_id')), device=device, is_active=True).first())
            if not access:
                _audit(request, 'ACCESS_NOT_FOUND', device=device, success=False, severity='warning',
                       metadata={'action': str(action)})
                messages.error(request, 'Không tìm thấy quyền truy cập.')
            elif action == 'update':
                old_codes = sorted(p.code for p in access.permissions.all())
                access.permissions.set(perms)
                _audit(request, 'ACCESS_UPDATED', device=device, target_user=access.user,
                       metadata={'access_id': str(access.id), 'from': old_codes, 'to': perm_codes})
                services.notify_access_shared(request, access, created=False)
                messages.success(request, 'Đã cập nhật quyền.')
            else:
                access.is_active = False
                access.revoked_at = timezone.now()
                access.save(update_fields=['is_active', 'revoked_at'])
                # Lệnh đang chờ do người bị thu hồi gửi không được phép chạy tiếp.
                cancelled = DeviceCommand.objects.filter(
                    device=device, issued_by=access.user, status='pending').update(status='failed')
                _audit(request, 'ACCESS_REVOKED', device=device, target_user=access.user, severity='warning',
                       metadata={'access_id': str(access.id), 'cancelled_commands': cancelled})
                _notify(access.user, 'Quyền truy cập bị thu hồi',
                        f'Quyền của bạn trên "{device.name}" đã bị thu hồi.',
                        severity='warning', device=device, type_='SHARE')
                messages.success(request, 'Đã thu hồi quyền.')
        return back()

    accesses = []
    if device:
        accesses = list(DeviceAccess.objects.filter(device=device, is_active=True)
                        .select_related('user').prefetch_related('permissions').order_by('-created_at'))
        for a in accesses:
            a.perm_codes = [p.code for p in a.permissions.all()]

    now = timezone.now()
    my_accesses = (DeviceAccess.objects.filter(user=user, is_active=True)
                   .filter(Q(expires_at__isnull=True) | Q(expires_at__gt=now))
                   .select_related('device', 'created_by').prefetch_related('permissions').order_by('-created_at'))
    context = {
        'device_list': owned,
        'device': device,
        'permissions': Permission.objects.order_by('name'),
        'accesses': accesses,          # những người ĐANG được mình chia sẻ (khoá đang chọn)
        'my_accesses': my_accesses,    # những khoá được CHIA SẺ CHO mình
        **services.permission_form_context(),   # permission_groups, role_presets, owner_only_actions
    }
    return _render(request, 'shares', context)


# ====================== MÃ PIN (bấm trực tiếp trên bàn phím của khoá) ======================
@auth_required
def door_pins(request):
    """Chủ khoá (hoặc người có quyền manage_pins) cấp PIN cho khách; khách bấm PIN trên bàn phím
    ma trận của khoá để mở cửa. PIN KHÔNG phải thứ để nhập vào web/app."""
    devices = services.devices_with_permission(request.user, 'manage_pins').order_by('name')
    device = _pick_device(devices, request.POST.get('device') or request.GET.get('device'),
                          strict=request.method == 'POST')

    if request.method == 'POST':
        if not device:
            _audit(request, 'DOOR_PIN_CREATE_DENIED', success=False, severity='warning')
            messages.error(request, 'Không tìm thấy thiết bị hoặc bạn không có quyền quản lý mã PIN.')
            return redirect('smartlock:door-pins')

        action = request.POST.get('action')
        if action == 'issue':
            try:
                ttl_minutes = max(1, min(int(request.POST.get('ttl_minutes') or 1440), 43200))  # tối đa 30 ngày
                max_uses = max(0, int(request.POST.get('max_uses') or 1))
            except (TypeError, ValueError):
                messages.error(request, 'Thời hạn hoặc số lần dùng không hợp lệ.')
                return _redirect_with('smartlock:door-pins', device=device.id)

            label = (request.POST.get('label') or '').strip()[:100]
            try:
                pin, plain_pin = services.issue_unique_door_pin(
                    device=device, created_by=request.user,
                    ttl_minutes=ttl_minutes, label=label, max_uses=max_uses)
            except RuntimeError as exc:
                messages.error(request, str(exc))
                return _redirect_with('smartlock:door-pins', device=device.id)
            _audit(request, 'DOOR_PIN_CREATED', device=device, metadata={'pin_id': str(pin.id), 'label': label})
            # plain_pin CHỈ hiện 1 lần ở đây - không lưu, không log dạng thô.
            messages.success(request, f'Mã PIN mới: {plain_pin} — khách bấm trên bàn phím của khoá '
                                      f'(hết hạn sau {ttl_minutes} phút).')
            return _redirect_with('smartlock:door-pins', device=device.id)

        if action == 'revoke':
            pin_qs = DoorPinCode.objects.filter(id=_parse_uuid(request.POST.get('pin_id')), device=device)
            if device.owner_id != request.user.id:
                pin_qs = pin_qs.filter(created_by=request.user)     # không phải chủ: chỉ thu hồi mã mình tạo
            pin = pin_qs.first()
            if not pin:
                messages.error(request, 'Không tìm thấy mã PIN.')
            else:
                pin.revoke()
                _audit(request, 'DOOR_PIN_REVOKED', device=device, metadata={'pin_id': str(pin.id)})
                messages.success(request, 'Đã thu hồi mã PIN.')
            return _redirect_with('smartlock:door-pins', device=device.id)
        return _redirect_with('smartlock:door-pins', device=device.id)

    pins = DoorPinCode.objects.none()
    if device:
        pins = DoorPinCode.objects.filter(device=device).select_related('created_by')
        if device.owner_id != request.user.id:
            pins = pins.filter(created_by=request.user)             # không phải chủ: chỉ thấy mã mình tạo
        pins = pins.order_by('-created_at')[:50]
    return _render(request, 'door_pins', {'device_list': devices, 'device': device, 'door_pins': pins})


# ====================== KHUÔN MẶT ======================
@auth_required
def face_profiles(request):
    """Đăng ký/quản lý khuôn mặt được phép mở cửa. Embedding do client/dịch vụ suy luận tính sẵn;
    view chỉ nhận rồi lưu mã hoá (NĐ 13/2023). Người có quyền manage_face_profiles thấy mọi hồ sơ
    trên khoá đó; người khác chỉ thấy hồ sơ của chính mình."""
    user = request.user
    devices = services.devices_with_permission(user, 'manage_face_profiles').order_by('name')
    device = _pick_device(devices, request.POST.get('device') or request.GET.get('device'),
                          strict=request.method == 'POST')

    if request.method == 'POST':
        if not device:
            _audit(request, 'FACE_PROFILE_CREATE_DENIED', success=False, severity='warning')
            messages.error(request, 'Không tìm thấy thiết bị hoặc bạn không có quyền quản lý khuôn mặt.')
            return redirect('smartlock:face-profiles')
        action = request.POST.get('action')

        if action == 'register':
            # Luồng cũ (người dùng dán vector đặc trưng) đã bỏ: vector phải do camera trích xuất, người dùng
            # không nhìn thấy/không nhập. Đăng ký bằng nút "Quét khuôn mặt" (gọi smartlock:face-enroll).
            messages.error(request, 'Hãy dùng nút "Quét khuôn mặt" để đăng ký bằng camera.')
            return _redirect_with('smartlock:face-profiles', device=device.id)

        if action == 'toggle':
            profile = FaceProfile.objects.filter(id=_parse_uuid(request.POST.get('profile_id')),
                                                 device=device).first()
            # Chủ khoá bật/tắt được hồ sơ của mọi người; người khác chỉ hồ sơ của chính mình.
            if profile and profile.user_id != user.id and device.owner_id != user.id:
                profile = None
            if not profile:
                messages.error(request, 'Không tìm thấy hồ sơ khuôn mặt.')
            else:
                profile.is_active = not profile.is_active
                profile.save(update_fields=['is_active', 'updated_at'])
                _audit(request, 'FACE_PROFILE_TOGGLED', device=device, target_user=profile.user,
                       metadata={'face_profile_id': str(profile.id), 'is_active': profile.is_active})
                messages.success(request, 'Đã cập nhật trạng thái.')
            return _redirect_with('smartlock:face-profiles', device=device.id)
        return _redirect_with('smartlock:face-profiles', device=device.id)

    profiles = FaceProfile.objects.none()
    if device:
        profiles = FaceProfile.objects.filter(device=device).select_related('user').order_by('-created_at')
        if device.owner_id != user.id:
            profiles = profiles.filter(user=user)
    return _render(request, 'face_profiles', {
        'device_list': devices, 'device': device, 'face_profiles': profiles,
        'face_enroll_url': reverse('smartlock:face-enroll'),
        'face_min_frames': services.FACE_MIN_FRAMES,
    })


@auth_required
@require_POST
def face_enroll(request):
    """Nhận kết quả QUÉT khuôn mặt (JSON) từ trình duyệt/app: {device, name, consent_confirmed, embeddings:[[128 số] x N]}.
    Camera + trích vector chạy ở phía client (ảnh không rời máy, không lưu ảnh); server kiểm tra chất lượng, lấy
    trung bình, mã hoá rồi lưu (NĐ 13/2023). Người dùng không thấy và không nhập vector."""
    if len(request.body) > 64 * 1024:
        return JsonResponse({'ok': False, 'message': 'Dữ liệu quá lớn.'}, status=413)
    data = _json_body(request)
    if not isinstance(data, dict):
        return JsonResponse({'ok': False, 'message': 'Yêu cầu không hợp lệ.'}, status=400)
    user = request.user
    devices = services.devices_with_permission(user, 'manage_face_profiles')
    device = _pick_device(devices, data.get('device'), strict=True)
    if not device:
        _audit(request, 'FACE_PROFILE_CREATE_DENIED', success=False, severity='warning')
        return JsonResponse({'ok': False, 'message': 'Không tìm thấy khoá hoặc bạn không có quyền đăng ký khuôn mặt.'},
                            status=403)
    if data.get('consent_confirmed') is not True:
        return JsonResponse({'ok': False, 'message': 'Cần xác nhận người được đăng ký đã đồng ý thu thập dữ liệu khuôn mặt.'},
                            status=400)
    name = str(data.get('name') or user.full_name or user.username)[:100]
    try:
        profile = services.enroll_face(device, user, data.get('embeddings'), name=name, request=request)
    except services.FaceEnrollError as exc:
        _audit(request, 'FACE_PROFILE_ENROLL_FAILED', device=device, success=False, severity='warning',
               metadata={'code': exc.code})
        return JsonResponse({'ok': False, 'message': exc.message, 'code': exc.code}, status=422)
    if device.owner_id != user.id:
        _notify(device.owner, 'Có khuôn mặt mới trên khoá của bạn',
                f'{user.username} vừa đăng ký khuôn mặt cho "{device.name}".', device=device, type_='FACE')
    return JsonResponse({'ok': True, 'message': 'Đã đăng ký khuôn mặt.', 'profile_id': str(profile.id)})


# ====================== LỊCH SỬ RA VÀO ======================
@auth_required
def access_events_history(request):
    """Lịch sử mở cửa hợp nhất mọi kênh (thẻ, PIN, khuôn mặt, Bluetooth, NFC điện thoại).
    Chỉ chủ khoá hoặc người có quyền view_history."""
    devices = services.devices_with_permission(request.user, 'view_history').order_by('name')
    device = _pick_device(devices, request.GET.get('device'))
    qs = AccessEvent.objects.filter(device__in=devices).select_related(
        'device', 'user', 'access_card', 'door_pin', 'face_profile').order_by('-created_at')
    if device:
        qs = qs.filter(device=device)
    method = request.GET.get('method')
    if method in dict(AccessEvent.METHOD_CHOICES):
        qs = qs.filter(method=method)
    context = {'device_list': devices, 'device': device, 'method': method or '',
               'method_choices': AccessEvent.METHOD_CHOICES, 'access_events': _page(request, qs)}
    return _render(request, 'access_history', context)


# ====================== POPUP TRÊN MÀN HÌNH (poll) ======================
EVENTS_MAX_BACKLOG_SECONDS = 300     # tab mở lại sau lâu: không dội cả đống popup cũ
EVENTS_BATCH = 10


@auth_required
def events_poll(request):
    """JS (static/smartlock/js/popup.js) gọi mỗi vài giây. Trả các Notification MỚI của user kể từ
    `cursor` để hiện popup trong trang. Lần đầu (chưa có cursor) chỉ trả cursor, không trả popup cũ."""
    now = timezone.now()
    raw = (request.GET.get('cursor') or '').strip()
    since = parse_datetime(raw) if raw else None
    if since is not None and timezone.is_naive(since):
        since = timezone.make_aware(since)
    unread = Notification.objects.filter(user=request.user, is_read=False).count()
    if since is None:
        resp = JsonResponse({'events': [], 'cursor': now.isoformat(), 'unread_count': unread})
        resp['Cache-Control'] = 'no-store'
        return resp
    since = max(since, now - timedelta(seconds=EVENTS_MAX_BACKLOG_SECONDS))

    rows = list(Notification.objects.filter(user=request.user, created_at__gt=since)
                .order_by('created_at')[:EVENTS_BATCH])
    cursor = rows[-1].created_at if rows else since
    events = [{
        'id': str(n.id), 'type': n.type, 'title': n.title, 'message': n.message, 'severity': n.severity,
        'device_id': str(n.device_id) if n.device_id else None, 'created_at': n.created_at.isoformat(),
    } for n in rows]
    resp = JsonResponse({'events': events, 'cursor': cursor.isoformat(), 'unread_count': unread})
    resp['Cache-Control'] = 'no-store'
    return resp