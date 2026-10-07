# manage_sys/views.py
"""
Trang quản trị (Manage Sys) - tách hoàn toàn khỏi views của user thường. Chỉ dùng chung MODELS/services với smartlock.

Một file duy nhất (trước đây: helpers.py + decorators.py + views.py). Bố cục:
  1. Hằng số + phân quyền + xác nhận lại mật khẩu + secret hiển thị 1 lần + phân trang   (trước là helpers.py)
  2. manage_required                                                                      (trước là decorators.py)
  3. Views: auth, dashboard, users, devices, logs, announcements, settings
Ghi log / thông báo / khóa đăng nhập / lấy IP dùng CHUNG bản ở smartlock.services (một nguồn duy nhất).
Mail cảnh báo cho user (đổi quyền, vô hiệu hóa, gán/gỡ chủ khóa, xoay secret...) do services.audit() tự gửi.
"""
import logging
import math
import re
import secrets
import uuid
from datetime import timedelta
from functools import wraps
from types import SimpleNamespace

from cryptography.fernet import InvalidToken
from django.conf import settings as dj_settings
from django.contrib import messages
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.hashers import check_password, make_password
from django.contrib.auth.views import redirect_to_login
from django.core.paginator import Paginator
from django.db import transaction
from django.db.models import Count, Q
from django.db.models.functions import TruncDate
from django.http import JsonResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.urls import reverse
from django.utils import timezone
from django.utils.http import url_has_allowed_host_and_scheme
from django.views.decorators.cache import never_cache
from django.views.decorators.http import require_http_methods, require_POST

from smartlock import services
from smartlock.models import (
    AccessEvent, Announcement, AuditLog, CardDeviceAccess, Device, DeviceAccess,
    DeviceCommand, DeviceStatusLog, DoorPinCode, FaceProfile, NfcReader, User, fernet,
)
from smartlock.services import (
    audit, client_ip, is_admin as _services_is_admin, notify, register_failure, reset_lockout,
)

logger = logging.getLogger('smartlock.manage_sys')

# =====================================================================================================
# 1. HELPERS
# =====================================================================================================
PAGE_SIZE = 20

# Lượt đăng nhập nay lấy từ AuditLog (bảng LoginAttemptLog cũ đã gộp vào AuditLog).
LOGIN_ACTIONS = ('LOGIN', 'LOGIN_FAILED', 'LOGIN_ADMIN_REJECTED',
                 'MANAGE_LOGIN', 'MANAGE_LOGIN_DENIED', 'MANAGE_LOGIN_FAILED',
                 'MANAGE_LOGIN_LOCKED')
LOGIN_FAIL_ACTIONS = ('LOGIN_FAILED', 'LOGIN_ADMIN_REJECTED', 'MANAGE_LOGIN_DENIED', 'MANAGE_LOGIN_FAILED',
                      'MANAGE_LOGIN_LOCKED')

# Xác nhận lại mật khẩu cho thao tác nguy hiểm: tên trường POST.
REAUTH_FIELD = 'current_password'


def login_attempts_qs():
    return AuditLog.objects.filter(action__in=LOGIN_ACTIONS)


def decorate_login_attempt(a):
    """Gắn thêm thuộc tính giống LoginAttemptLog cũ (identifier, user) để template cũ vẫn chạy."""
    who = a.target_user or a.actor_user
    ident = a.username_attempt or (who.email if who else '—')
    a.identifier = f'[manage] {ident}' if a.action.startswith('MANAGE_') else ident
    a.user = who
    return a


# ---------- Phân quyền ----------
def has_manage_role(user):
    """Tài khoản có cờ quản trị (không xét đăng nhập)."""
    return bool(user and _services_is_admin(user))   # MỘT nguồn duy nhất: smartlock.services.is_admin


def is_manager(user):
    return bool(user and user.is_authenticated and user.is_active and has_manage_role(user))


# Thao tác NHẠY CẢM (cấp/thu hồi quyền quản trị, đổi secret thiết bị, gỡ chủ khoá, đổi cài đặt).
# settings.ADMIN_FULL_POWER = True (mặc định): MỌI tài khoản quản trị có quyền cao nhất, làm được tất cả
# (has_full_power đọc cờ này mỗi lần gọi).
# Đặt ADMIN_FULL_POWER=False để quay lại chính sách cũ: các thao tác này chỉ dành cho Superuser.
# Các lớp bảo vệ KHÔNG đổi: nhập lại mật khẩu + gõ xác nhận, audit strict, không tự thao tác lên chính mình,
# không để hệ thống mất superuser cuối cùng.
SUPERUSER_ONLY_ACTIONS = frozenset({'grant_admin', 'revoke_admin', 'rotate_secret', 'remove_owner',
                                     'update_settings'})


def is_superuser_role(user):
    return bool(user and user.is_authenticated and user.is_active and user.is_superuser)


def admin_full_power_enabled():
    """settings.ADMIN_FULL_POWER (mặc định True). Đọc lúc gọi để đổi cấu hình/test có hiệu lực ngay."""
    return bool(getattr(dj_settings, 'ADMIN_FULL_POWER', True))


def has_full_power(user):
    """Quyền cao nhất: Superuser luôn có; admin đang hoạt động chỉ có khi ADMIN_FULL_POWER bật."""
    if is_superuser_role(user):
        return True
    return admin_full_power_enabled() and is_manager(user)


def admin_caps(user):
    """Một nguồn duy nhất cho template: quyền của người đang đăng nhập + chính sách hiện hành."""
    return {
        'full_power': has_full_power(user),
        'admin_full_power': admin_full_power_enabled(),   # chính sách cho cột "Admin" ở ma trận quyền
        'role': 'superuser' if is_superuser_role(user) else ('admin' if is_manager(user) else 'user'),
    }


def action_denied_reason(actor, action):
    """Lý do KHÔNG được làm `action` (thao tác nhạy cảm), hoặc None nếu được phép."""
    if action in SUPERUSER_ONLY_ACTIONS and not has_full_power(actor):
        return 'Thao tác nhạy cảm: tài khoản không có quyền quản trị.'
    return None


def modify_denied_reason(actor, target):
    """Trả về lý do KHÔNG được sửa target, hoặc None nếu được phép.
    Admin quản lý được mọi tài khoản (kể cả admin khác); tài khoản Superuser cần quyền cao nhất (has_full_power)."""
    if actor.pk == target.pk:
        return 'Không thể tự thao tác lên chính tài khoản của bạn.'
    if target.is_superuser and not has_full_power(actor):
        return 'Chỉ Superuser mới được thao tác lên tài khoản Superuser.'
    return None


# ---------- Đăng nhập / xác nhận lại ----------
def lock_remaining_minutes(user):
    locked_until = User.objects.filter(pk=user.pk).values_list('login_locked_until', flat=True).first()
    now = timezone.now()
    if locked_until and locked_until > now:
        return math.ceil((locked_until - now).total_seconds() / 60)
    return 0


_DUMMY_HASH = None


def burn_password_hash(password):
    """Chạy 1 phép băm mật khẩu giả để thời gian phản hồi khi email KHÔNG tồn tại / tài khoản đang khóa
    xấp xỉ khi đăng nhập sai thật -> không dò được email nào là admin qua độ trễ."""
    global _DUMMY_HASH
    if _DUMMY_HASH is None:
        _DUMMY_HASH = make_password('dummy-' + secrets.token_hex(8))
    check_password(password, _DUMMY_HASH)


def is_new_login_ip(user, ip):
    """True nếu user ĐÃ từng đăng nhập quản trị nhưng chưa từng từ IP này (gọi TRƯỚC khi ghi MANAGE_LOGIN mới).
    Lần đăng nhập đầu tiên không tính để tránh thông báo thừa."""
    logins = AuditLog.objects.filter(action='MANAGE_LOGIN', actor_user=user)
    return logins.exists() and not logins.filter(ip_address=ip).exists()


def check_reauth(request):
    """Xác nhận lại mật khẩu của CHÍNH admin đang đăng nhập cho thao tác nguy hiểm (cấp/thu hồi admin,
    gỡ chủ khoá, xoay secret) -> chiếm được phiên cũng chưa làm được việc nặng. Sai mật khẩu bị ghi log và
    tính vào bộ đếm khóa tài khoản (không cho dò mật khẩu qua phiên đang mở)."""
    user = request.user
    if lock_remaining_minutes(user):
        return False
    password = request.POST.get(REAUTH_FIELD) or ''
    if password and user.check_password(password):
        return True
    ip = client_ip(request)
    register_failure(user, ip)
    audit(request, 'MANAGE_REAUTH_FAILED', success=False, severity='warning')
    return False


def confirm_sensitive(request, expected, *, upper=False):
    """Gộp 2 lớp xác nhận của thao tác nguy hiểm: (1) gõ đúng `expected` (email / mã thiết bị) vào ô `confirm`,
    (2) nhập lại mật khẩu. Trả (ok, lỗi) - lỗi là 'confirm' hoặc 'reauth' để view chọn thông báo."""
    typed = (request.POST.get('confirm') or '').strip()
    exp = (expected or '').strip()
    if (typed.upper() != exp.upper()) if upper else (typed.lower() != exp.lower()):
        return False, 'confirm'
    return (True, None) if check_reauth(request) else (False, 'reauth')


# ---------- Phiên app di động ----------
def revoke_mobile_sessions(user):
    """Thu hồi mọi MobileSession còn hiệu lực của user (và xoá fcm_token để ngừng push). Trả về số phiên.

    Hàm này chỉ vô hiệu hóa phía DB. API di động (smartlock/api) phải tự từ chối khi `not user.is_active`
    hoặc MobileSession đã bị thu hồi / hết hạn ở MỖI request; access token đã phát hành chỉ hết hiệu lực
    khi hết hạn (MOBILE_ACCESS_TOKEN_SECONDS).
    """
    from smartlock.models import MobileSession
    return MobileSession.objects.filter(user=user, revoked_at__isnull=True).update(
        revoked_at=timezone.now(), fcm_token='')


# ---------- Secret hiển thị 1 lần (Post/Redirect/Get) ----------
SECRET_SESSION_KEY = 'manage_pending_secret'
SECRET_TTL_SECONDS = 300


def stash_secret(request, device, secret, *, rotated=False, pending_owner_email=None):
    """Cất secret gốc vào session ADMIN, đã mã hoá Fernet (không lưu plaintext trong bảng session).
    Sau đó view redirect sang trang hiển thị -> F5 chỉ tải lại GET, không lặp lại thao tác (xoay secret...)."""
    request.session[SECRET_SESSION_KEY] = {
        'device_id': str(device.pk),
        'blob': fernet.encrypt(secret.encode()).decode(),
        'rotated': bool(rotated),
        'owner': pending_owner_email or '',
    }


def pop_secret(request, device_id):
    """Lấy và XOÁ secret đã cất (dùng 1 lần). Trả về dict {secret, rotated, owner} hoặc None
    (không có / sai thiết bị / quá SECRET_TTL_SECONDS / giải mã lỗi)."""
    data = request.session.get(SECRET_SESSION_KEY)
    if not data or data.get('device_id') != str(device_id):
        return None
    request.session.pop(SECRET_SESSION_KEY, None)
    try:
        secret = fernet.decrypt(data['blob'].encode(), ttl=SECRET_TTL_SECONDS).decode()
    except (InvalidToken, KeyError):
        return None
    return {'secret': secret, 'rotated': data.get('rotated', False), 'owner': data.get('owner') or None}


# ---------- Phân trang ----------
def paginate(request, queryset, per_page=PAGE_SIZE):
    """Trả về (page_obj, qs) - qs là query string giữ lại bộ lọc, dạng '&a=b'."""
    page_obj = Paginator(queryset, per_page).get_page(request.GET.get('page'))
    params = request.GET.copy()
    params.pop('page', None)
    encoded = params.urlencode()
    return page_obj, ('&' + encoded if encoded else '')


# =====================================================================================================
# 2. DECORATOR
# =====================================================================================================
def manage_required(view_func):
    """Chỉ cho tài khoản quản trị đã đăng nhập ở cổng quản trị riêng."""
    @wraps(view_func)
    @never_cache
    def wrapper(request, *args, **kwargs):
        user = request.user
        if not user.is_authenticated:
            return redirect_to_login(request.get_full_path(), reverse('manage_sys:login'))
        if not is_manager(user):
            logout(request)  # chỉ hủy phiên admin, không đụng phiên user
            messages.error(request, 'Tài khoản không còn quyền quản trị.')
            return redirect_to_login(request.get_full_path(), reverse('manage_sys:login'))
        return view_func(request, *args, **kwargs)
    return wrapper


# =====================================================================================================
# 3. VIEWS
# =====================================================================================================
# MỘT thông báo duy nhất cho mọi kiểu thất bại (sai mật khẩu, không phải admin, tài khoản đang khóa)
# để người ngoài không dò được email nào là admin / đang bị khóa.
LOGIN_ERROR = ('Đăng nhập không thành công. Kiểm tra lại thông tin hoặc thử lại sau ít phút '
               '(đăng nhập có thể đang bị hạn chế tạm thời).')
REAUTH_ERROR = 'Mật khẩu xác nhận không đúng. Thao tác chưa được thực hiện.'
AUDIT_ERROR = 'Không ghi được nhật ký nên thao tác đã bị huỷ. Vui lòng thử lại.'
RESET_LINK_COOLDOWN = 60          # giây giữa 2 lần gửi link reset cho cùng 1 user
ADMIN_OWNER_ERROR = 'Tài khoản quản trị không được làm chủ khoá. Hãy dùng tài khoản người dùng thường.'
SESSION_SECONDS = getattr(dj_settings, 'MANAGE_SYS_SESSION_SECONDS', 2 * 3600)
URL_PREFIX = getattr(dj_settings, 'MANAGE_SYS_URL_PREFIX', '/manage-sys/')


# Mỗi nhóm trang gộp 1 template, chọn trang bằng biến `page`.
PAGE_TEMPLATE = {
    "user_list": "users",
    "user_detail": "users",
    "device_list": "devices",
    "device_create": "devices",
    "device_created": "devices",
    "device_detail": "devices",
    "dashboard": "ops",
    "audit_logs": "ops",
    "audit_logins": "ops",
    "announcements": "ops",
    "settings": "ops",
    "login": "base"
}

# Tiêu đề tĩnh của từng trang (tab trình duyệt + h4). Trang chi tiết tự override block page_title trong template.
PAGE_TITLES = {
    "user_list": "Quản lý Người dùng", "user_detail": "Người dùng",
    "device_list": "Quản lý Thiết bị", "device_create": "Thêm thiết bị",
    "device_created": "Đã tạo thiết bị", "device_detail": "Thiết bị",
    "dashboard": "Tổng quan hệ thống", "audit_logs": "Nhật ký hệ thống",
    "audit_logins": "Lượt đăng nhập", "announcements": "Thông báo hệ thống",
    "settings": "Cài đặt hệ thống",
}


def _render(request, page, context=None, **kwargs):
    """_render(request, 'user_list', ctx) -> manage_sys/users.html với page='user_list'."""
    ctx = dict(context or {})
    ctx['page'] = page
    if page != 'login' and request.user.is_authenticated:
        ctx.setdefault('caps', admin_caps(request.user))
    ctx.setdefault('page_heading', PAGE_TITLES.get(page, ''))
    return render(request, f'manage_sys/{PAGE_TEMPLATE[page]}.html', ctx, **kwargs)


def _parse_uuid(value):
    try:
        return uuid.UUID(str(value))
    except (ValueError, AttributeError, TypeError):
        return None


def _find_user(identifier):
    identifier = (identifier or '').strip()
    if not identifier:
        return None
    return User.objects.filter(Q(email__iexact=identifier) | Q(username__iexact=identifier)).first()


# ====================== AUTH ======================
@never_cache
def login_view(request):
    if is_manager(request.user):
        return redirect('manage_sys:dashboard')

    next_url = request.POST.get('next') or request.GET.get('next') or ''
    ctx = {'next': next_url}

    if request.method != 'POST':
        return _render(request, 'login', ctx)

    identifier = (request.POST.get('identifier') or '').strip()
    password = request.POST.get('password') or ''
    if not identifier or not password:
        messages.error(request, 'Vui lòng điền đầy đủ thông tin.')
        return _render(request, 'login', ctx)

    ip = client_ip(request)

    user = _find_user(identifier)
    is_manager_account = bool(user and has_manage_role(user))

    # Tài khoản quản trị đang bị khóa: KHÔNG tiết lộ (cùng thông báo + cùng độ trễ như sai mật khẩu).
    # Người bị khóa vẫn nhận thông báo riêng (notify trong register_failure) và admin khác thấy ở trang người dùng.
    if is_manager_account and lock_remaining_minutes(user):
        burn_password_hash(password)
        audit(request, 'MANAGE_LOGIN_LOCKED', actor=None, target_user=user, success=False,
              severity='warning', username_attempt=identifier[:150])
        messages.error(request, LOGIN_ERROR)
        return _render(request, 'login', ctx)

    if user:
        auth_user = authenticate(request, username=user.email, password=password)
    else:
        burn_password_hash(password)   # email không tồn tại: vẫn tốn thời gian băm như bình thường
        auth_user = None
    ok = bool(auth_user and has_manage_role(auth_user))

    # Lưu ý: cổng quản trị CHỦ ĐỘNG không dùng 2FA (chạy trên tên miền riêng, không dùng chung với trang user).
    if ok:
        new_ip = is_new_login_ip(auth_user, ip)      # phải tính TRƯỚC khi ghi MANAGE_LOGIN của lần này
        reset_lockout(auth_user)
        login(request, auth_user)
        request.session.set_expiry(SESSION_SECONDS)
        audit(request, 'MANAGE_LOGIN', actor=auth_user)
        if new_ip:
            notify(auth_user, 'Đăng nhập quản trị từ IP mới',
                   f'Tài khoản vừa đăng nhập trang quản trị từ IP {ip} (chưa từng thấy). '
                   'Nếu không phải bạn, hãy đổi mật khẩu ngay.', severity='warning', type_='SECURITY')
        messages.success(request, 'Đăng nhập trang quản trị thành công.')
        if (next_url and next_url.startswith(URL_PREFIX)
                and url_has_allowed_host_and_scheme(next_url, {request.get_host()},
                                                    require_https=request.is_secure())):
            return redirect(next_url)
        return redirect('manage_sys:dashboard')

    # Thất bại. Chỉ đếm khóa với tài khoản quản trị, để cổng này không bị dùng
    # để khóa tài khoản user thường.
    if is_manager_account and not auth_user:
        register_failure(user, ip)
    action = 'MANAGE_LOGIN_DENIED' if auth_user else 'MANAGE_LOGIN_FAILED'
    audit(request, action, actor=None, target_user=user, success=False,
          severity='warning', username_attempt=identifier[:150])
    messages.error(request, LOGIN_ERROR)
    return _render(request, 'login', ctx)


@require_POST
def logout_view(request):
    if request.user.is_authenticated:
        audit(request, 'MANAGE_LOGOUT')
    logout(request)
    messages.success(request, 'Đã đăng xuất khỏi trang quản trị.')
    return redirect('manage_sys:login')


# ====================== DASHBOARD ======================
@manage_required
def dashboard(request):
    now = timezone.now()
    day_ago = now - timedelta(hours=24)

    # Gộp thành 4 truy vấn aggregate (trước đây ~10 count() riêng lẻ).
    u = User.objects.aggregate(
        total=Count('id'), active=Count('id', filter=Q(is_active=True)),
        unverified=Count('id', filter=Q(is_active=False, email_verified=False)),
        locked=Count('id', filter=Q(login_locked_until__gt=now)))
    d = Device.objects.aggregate(
        total=Count('id'), online=Count('id', filter=Q(status='online')),
        maintenance=Count('id', filter=Q(status='maintenance')))
    a24 = AuditLog.objects.filter(created_at__gte=day_ago).aggregate(
        failed=Count('id', filter=Q(action__in=LOGIN_FAIL_ACTIONS)),
        critical=Count('id', filter=Q(severity='critical')))
    stats = {
        'total_users': u['total'], 'active_users': u['active'], 'unverified_users': u['unverified'],
        'total_devices': d['total'], 'online_devices': d['online'], 'maintenance_devices': d['maintenance'],
        'failed_logins_24h': a24['failed'], 'locked_accounts': u['locked'], 'critical_24h': a24['critical'],
    }

    today = timezone.localdate()
    days = [today - timedelta(days=i) for i in range(6, -1, -1)]
    counts = {
        r['d']: r['c'] for r in
        AuditLog.objects.filter(created_at__date__gte=days[0])
        .annotate(d=TruncDate('created_at')).values('d').annotate(c=Count('id'))
    }
    peak = max([counts.get(d, 0) for d in days] + [1])
    chart = [{'label': d.strftime('%d/%m'), 'count': counts.get(d, 0),
              'pct': int(counts.get(d, 0) / peak * 100)} for d in days]

    context = {
        'stats': stats,
        'chart': chart,
        'alert_logs': (AuditLog.objects.filter(severity__in=['warning', 'critical'])
                       .select_related('actor_user', 'device').order_by('-created_at')[:8]),
    }
    return _render(request, 'dashboard', context)


# ====================== USERS ======================
def _would_orphan_superusers(target):
    """True nếu bỏ quyền / vô hiệu hóa `target` làm hệ thống KHÔNG còn superuser active nào khác.
    PHẢI gọi trong transaction.atomic() cùng chỗ ghi: khóa dòng các superuser để 2 superuser không thể
    đồng thời thu hồi của nhau (race) và để lại hệ thống không ai quản trị được."""
    if not target.is_superuser:
        return False
    others = list(User.objects.select_for_update()
                  .filter(is_superuser=True, is_active=True).exclude(pk=target.pk).values_list('pk', flat=True))
    return not others


@manage_required
def users_list(request):
    qs = User.objects.annotate(device_count=Count('device', distinct=True)).order_by('-created_at')

    q = (request.GET.get('q') or '').strip()
    if q:
        qs = qs.filter(Q(email__icontains=q) | Q(username__icontains=q)
                       | Q(full_name__icontains=q) | Q(phone__icontains=q))

    if q and not request.GET.get('page'):   # tìm kiếm lộ email/SĐT -> ghi vết (chuyển trang không ghi)
        audit(request, 'MANAGE_SEARCH_USERS', metadata={'q': q[:80]})

    status = request.GET.get('status') or ''
    now = timezone.now()
    if status == 'active':
        qs = qs.filter(is_active=True)
    elif status == 'inactive':
        qs = qs.filter(is_active=False)
    elif status == 'unverified':
        qs = qs.filter(is_active=False, email_verified=False)
    elif status == 'locked':
        qs = qs.filter(login_locked_until__gt=now)
    elif status == 'admin':
        qs = qs.filter(Q(is_admin=True) | Q(is_staff=True) | Q(is_superuser=True))

    page_obj, qs_str = paginate(request, qs)
    locked_ids = set(User.objects.filter(
        pk__in=[u.pk for u in page_obj], login_locked_until__gt=now).values_list('pk', flat=True))
    for u in page_obj:
        u.is_locked = u.pk in locked_ids
        u.is_manager_role = has_manage_role(u)
        u.role = 'superuser' if u.is_superuser else ('admin' if u.is_manager_role else 'user')

    return _render(request, 'user_list', {
        'page_obj': page_obj, 'qs': qs_str, 'q': q, 'status': status,
    })


@manage_required
@require_http_methods(['GET', 'POST'])
def user_detail(request, user_id):
    target = get_object_or_404(User, id=user_id)
    back = redirect('manage_sys:user-detail', user_id=target.id)

    if request.method == 'POST':
        action = request.POST.get('action')
        reason = modify_denied_reason(request.user, target)
        if reason:
            messages.error(request, reason)
            return back

        denied = action_denied_reason(request.user, action)
        if denied:
            audit(request, 'MANAGE_ACTION_DENIED', target_user=target, success=False, severity='warning',
                  metadata={'action': action})
            messages.error(request, denied)
            return back

        if action in ('grant_admin', 'revoke_admin'):
            # Gõ lại đúng email của tài khoản đích (chống bấm nhầm người) + nhập lại mật khẩu.
            ok, err = confirm_sensitive(request, target.email)
            if not ok:
                messages.error(request, REAUTH_ERROR if err == 'reauth'
                               else 'Nhập đúng email của tài khoản này vào ô xác nhận.')
                return back

        if action == 'toggle_active':
            with transaction.atomic():
                if target.is_active and _would_orphan_superusers(target):
                    messages.error(request, 'Không thể vô hiệu hóa superuser cuối cùng của hệ thống.')
                    return back
                target.is_active = not target.is_active
                target.save(update_fields=['is_active', 'updated_at'])
            revoked = 0
            if not target.is_active:
                # Phiên web hết hiệu lực tự động (backend từ chối user inactive). Phiên app di động phải thu hồi
                # tường minh. TODO: khi làm smartlock/api, API vẫn phải tự kiểm tra user.is_active (xem helpers).
                revoked = revoke_mobile_sessions(target)
            audit(request, 'MANAGE_USER_ACTIVATED' if target.is_active else 'MANAGE_USER_DEACTIVATED',
                  target_user=target, severity='info' if target.is_active else 'warning',
                  metadata={'mobile_sessions_revoked': revoked} if not target.is_active else None)
            messages.success(request, 'Đã kích hoạt tài khoản.' if target.is_active
                             else 'Đã vô hiệu hóa tài khoản và thu hồi phiên app di động.')

        elif action == 'unlock':
            reset_lockout(target)
            audit(request, 'MANAGE_USER_UNLOCKED', target_user=target)
            notify(target, 'Tài khoản đã được mở khóa',
                   'Quản trị viên đã mở khóa đăng nhập cho tài khoản của bạn.', type_='SECURITY')
            messages.success(request, 'Đã mở khóa đăng nhập.')

        elif action == 'send_reset_link':
            # User yêu cầu đặt lại mật khẩu (qua admin) -> admin chỉ GỬI LINK tới email của user.
            # Admin không thấy link, không đặt/đổi mật khẩu trực tiếp (không có hành động nào ghi vào trường mật khẩu).
            if not target.is_active or not target.email_verified:
                messages.error(request, 'Chỉ gửi được cho tài khoản đang hoạt động và đã xác thực email.')
            elif not request.POST.get('user_requested'):
                messages.error(request, 'Hãy xác nhận người dùng đã yêu cầu đặt lại mật khẩu.')
            elif AuditLog.objects.filter(action='MANAGE_RESET_LINK_SENT', target_user=target,
                                         created_at__gte=timezone.now() - timedelta(seconds=RESET_LINK_COOLDOWN)).exists():
                messages.error(request, f'Vừa gửi link cho người này. Vui lòng chờ {RESET_LINK_COOLDOWN} giây rồi thử lại.')
            else:
                sent = services.send_password_reset(request, target, by_admin=request.user)
                audit(request, 'MANAGE_RESET_LINK_SENT', target_user=target, success=sent,
                      severity='warning', metadata=None if sent else {'error': 'send_mail_failed'})
                if sent:
                    notify(target, 'Đã gửi liên kết đặt lại mật khẩu',
                           'Quản trị viên đã gửi liên kết đặt lại mật khẩu tới email của bạn theo yêu cầu. '
                           'Nếu bạn không yêu cầu, hãy bỏ qua email đó và liên hệ quản trị viên.',
                           severity='warning', type_='SECURITY')
                    messages.success(request, f'Đã gửi liên kết đặt lại mật khẩu tới {services.mask_email(target.email)}.')
                else:
                    messages.error(request, 'Không gửi được email. Kiểm tra cấu hình SMTP rồi thử lại.')

        elif action in ('grant_admin', 'revoke_admin'):
            if action == 'grant_admin':
                if not target.is_active:
                    messages.error(request, 'Hãy kích hoạt tài khoản trước khi cấp quyền quản trị.')
                    return back
                owned = Device.objects.filter(owner=target).count()
                if owned:
                    messages.error(request, f'Tài khoản đang là chủ của {owned} khoá. Tài khoản quản trị không được '
                                            'làm chủ khoá nên hãy gỡ chủ các khoá đó trước khi cấp quyền.')
                    return back
                try:
                    with transaction.atomic():
                        target.is_admin = target.is_staff = target.is_superuser = True   # quyền cao nhất (như /admin)
                        target.save(update_fields=['is_admin', 'is_staff', 'is_superuser', 'updated_at'])
                        audit(request, 'MANAGE_ROLE_GRANTED', target_user=target, severity='critical', strict=True)
                except services.AuditWriteError:
                    messages.error(request, AUDIT_ERROR)
                    return back
                notify(target, 'Bạn được cấp quyền quản trị',
                       'Tài khoản của bạn vừa được cấp quyền quản trị cao nhất. Nếu bạn không biết việc này, '
                       'hãy liên hệ Superuser ngay.', severity='warning', type_='SECURITY')
                messages.success(request, 'Đã cấp quyền quản trị.')
            else:
                if not has_manage_role(target):
                    messages.info(request, 'Tài khoản này không có quyền quản trị để thu hồi.')
                    return back
                try:
                    with transaction.atomic():
                        if _would_orphan_superusers(target):
                            messages.error(request, 'Không thể thu hồi quyền của superuser cuối cùng của hệ thống.')
                            return back
                        target.is_admin = target.is_staff = target.is_superuser = False
                        target.save(update_fields=['is_admin', 'is_staff', 'is_superuser', 'updated_at'])
                        audit(request, 'MANAGE_ROLE_REVOKED', target_user=target, severity='critical', strict=True)
                except services.AuditWriteError:
                    messages.error(request, AUDIT_ERROR)
                    return back
                revoked = revoke_mobile_sessions(target)   # cắt luôn phiên app di động đang mở
                notify(target, 'Quyền quản trị đã bị thu hồi',
                       'Tài khoản của bạn không còn quyền quản trị.', severity='warning', type_='SECURITY')
                messages.success(request, f'Đã thu hồi quyền quản trị (thu hồi {revoked} phiên app).')
        else:
            messages.error(request, 'Hành động không hợp lệ.')
        return back

    audit(request, 'MANAGE_VIEW_USER', target_user=target)   # admin xem hồ sơ user cũng được ghi
    now = timezone.now()
    # Giữ nguyên tên thuộc tính cũ (failed_attempts, stage, locked_until...) cho template.
    lock = SimpleNamespace(
        failed_attempts=target.login_failed_attempts, stage=target.login_lock_stage,
        locked_until=target.login_locked_until, last_failed_at=target.login_last_failed_at,
        last_failed_ip=target.login_last_failed_ip,
    )
    context = {
        'target': target,
        'lock': lock,
        'is_locked': bool(lock.locked_until and lock.locked_until > now),
        'target_is_manager': has_manage_role(target),
        'target_role': 'superuser' if target.is_superuser else ('admin' if has_manage_role(target) else 'user'),
        'owned_count': Device.objects.filter(owner=target).count(),
        'deny_reason': modify_denied_reason(request.user, target),
        'can_sensitive': has_full_power(request.user),   # template ẩn nút cấp/thu hồi admin nếu False
        'devices': Device.objects.filter(owner=target).order_by('name'),
        'accesses': (DeviceAccess.objects.filter(user=target, is_active=True)
                     .select_related('device').order_by('-created_at')[:10]),
        'login_attempts': [decorate_login_attempt(a) for a in (
            login_attempts_qs().filter(Q(actor_user=target) | Q(target_user=target))
            .select_related('actor_user', 'target_user').order_by('-created_at')[:10])],
        'logs': (AuditLog.objects.filter(Q(actor_user=target) | Q(target_user=target))
                 .select_related('device').order_by('-created_at')[:10]),
    }
    return _render(request, 'user_detail', context)


# ====================== DEVICES ======================
_DEVICE_CODE_RE = re.compile(r'^[A-Z0-9][A-Z0-9_-]{2,49}$')
_MAC_RE = re.compile(r'^([0-9A-F]{2}:){5}[0-9A-F]{2}$')


@manage_required
@require_http_methods(['GET', 'POST'])
def device_create(request):
    """Admin thêm thiết bị MỚI. Khoá luôn được tạo ở trạng thái 'provisioning' (chưa có chủ);
    việc gán chủ làm sau ở trang chi tiết (nút Claim) và CHỈ được khi khoá đã kết nối thật."""
    if request.method == 'POST':
        form = {k: (request.POST.get(k) or '').strip() for k in
                ('device_code', 'name', 'device_mode', 'owner_email', 'mac_address')}
    else:
        form = {'device_mode': 'physical'}

    if request.method == 'POST':
        code = form['device_code'].upper()
        mode = form['device_mode']
        mac = form['mac_address'].upper().replace('-', ':')
        owner = _find_user(form['owner_email']) if form['owner_email'] else None
        error = None
        if not _DEVICE_CODE_RE.match(code):
            error = 'Mã thiết bị 3-50 ký tự (A-Z, 0-9, _ hoặc -).'
        elif not form['name']:
            error = 'Vui lòng nhập tên thiết bị.'
        elif mode not in ('physical', 'simulated'):
            error = 'Loại thiết bị không hợp lệ.'
        elif mac and not _MAC_RE.match(mac):
            error = 'Địa chỉ MAC không hợp lệ (dạng AA:BB:CC:DD:EE:FF).'
        elif form['owner_email'] and not owner:
            error = 'Không tìm thấy người dùng với email/username này.'
        elif owner and not owner.is_active:
            error = 'Tài khoản chủ sở hữu đang bị vô hiệu hóa.'
        elif owner and has_manage_role(owner):
            error = ADMIN_OWNER_ERROR
        elif Device.objects.filter(device_code=code).exists():
            error = 'Mã thiết bị đã tồn tại.'

        if error:
            messages.error(request, error)
        else:
            secret = secrets.token_urlsafe(24)
            device = Device.objects.create(
                device_code=code, name=form['name'][:100], device_mode=mode,
                mac_address=mac or None, owner=None, status='provisioning',
                # PHẢI cùng kiểu hash với mqtt_auth_webhook/BLE (SHA-256). Trước đây dùng make_password
                # nên thiết bị do admin tạo không bao giờ đăng nhập được broker.
                provisioning_secret_hash=services.hash_token(secret),
            )
            audit(request, 'MANAGE_DEVICE_CREATED', device=device, severity='warning',
                  metadata={'device_code': code, 'mode': mode, 'pending_owner': owner.email if owner else None})
            # Secret chỉ hiển thị 1 lần (DB chỉ lưu hash). Cất (mã hoá) vào session rồi REDIRECT sang trang
            # hiển thị: F5 không POST lại (không tạo trùng thiết bị / không xoay secret lần nữa).
            stash_secret(request, device, secret, pending_owner_email=owner.email if owner else None)
            return redirect('manage_sys:device-secret', device_id=device.id)

    return _render(request, 'device_create', {'form': form})


@manage_required
def devices_list(request):
    qs = Device.objects.select_related('owner').order_by('name')

    q = (request.GET.get('q') or '').strip()
    if q:
        qs = qs.filter(Q(name__icontains=q) | Q(device_code__icontains=q)
                       | Q(mac_address__icontains=q) | Q(owner__email__icontains=q)
                       | Q(owner__username__icontains=q))
        if not request.GET.get('page'):
            audit(request, 'MANAGE_SEARCH_DEVICES', metadata={'q': q[:80]})
    status = request.GET.get('status') or ''
    if status in dict(Device._meta.get_field('status').choices):
        qs = qs.filter(status=status)
    mode = request.GET.get('mode') or ''
    if mode in ('physical', 'simulated'):
        qs = qs.filter(device_mode=mode)

    page_obj, qs_str = paginate(request, qs)
    return _render(request, 'device_list', {
        'page_obj': page_obj, 'qs': qs_str, 'q': q, 'status': status, 'mode': mode,
        'status_choices': Device._meta.get_field('status').choices,
    })


def _device_actions(request, device):
    """Xử lý POST ở trang chi tiết thiết bị. Trả về response (redirect/render) hoặc None."""
    back = redirect('manage_sys:device-detail', device_id=device.id)
    action = request.POST.get('action')

    denied = action_denied_reason(request.user, action)
    if denied:
        audit(request, 'MANAGE_ACTION_DENIED', device=device, success=False, severity='warning',
              metadata={'action': action})
        messages.error(request, denied)
        return back

    if action in ('maintenance_on', 'maintenance_off'):
        if not device.owner_id:
            messages.error(request, 'Thiết bị chưa có chủ sở hữu nên không thể đổi trạng thái.')
            return back
        if action == 'maintenance_on' and device.status != 'maintenance':
            device.status = 'maintenance'
            title, msg = 'Thiết bị vào chế độ bảo trì', f'Thiết bị "{device.name}" đang được quản trị viên đặt ở chế độ bảo trì.'
            log_action = 'MANAGE_DEVICE_MAINTENANCE_ON'
        elif action == 'maintenance_off' and device.status == 'maintenance':
            device.status = 'offline'  # thiết bị tự báo 'online' khi kết nối lại
            title, msg = 'Thiết bị hết bảo trì', f'Thiết bị "{device.name}" đã kết thúc chế độ bảo trì.'
            log_action = 'MANAGE_DEVICE_MAINTENANCE_OFF'
        else:
            messages.info(request, 'Trạng thái không thay đổi.')
            return back
        device.save(update_fields=['status', 'updated_at'])
        audit(request, log_action, device=device, target_user=device.owner, severity='warning')
        notify(device.owner, title, msg, severity='warning', device=device, type_='DEVICE')
        messages.success(request, 'Đã cập nhật trạng thái thiết bị.')
        return back

    if action == 'ping':
        cmd = services.ping_device(device, issued_by=request.user)
        ok = cmd.status == 'sent'
        audit(request, 'MANAGE_DEVICE_PING', device=device, success=ok,
              metadata={'command_id': str(cmd.id), 'error': getattr(cmd, 'publish_error', '') or None})
        messages.success(request, 'Đã gửi PING, chờ thiết bị phản hồi (xem chỉ báo kết nối).') if ok else \
            messages.error(request, 'Không gửi được PING tới broker MQTT.')
        return back

    if action == 'claim':
        owner = _find_user(request.POST.get('owner'))
        if not owner:
            messages.error(request, 'Không tìm thấy người dùng để gán làm chủ.')
            return back
        try:
            with transaction.atomic():
                services.claim_device(device.id, owner, by_admin=True)   # tự từ chối tài khoản quản trị
                audit(request, 'MANAGE_DEVICE_CLAIMED', device=device, target_user=owner, severity='critical',
                      metadata={'owner_email': owner.email}, strict=True)
        except services.ClaimError as exc:
            audit(request, 'MANAGE_DEVICE_CLAIM_FAILED', device=device, target_user=owner, success=False,
                  severity='warning', metadata={'code': exc.code})
            messages.error(request, exc.message)
            return back
        except services.AuditWriteError:
            messages.error(request, AUDIT_ERROR)
            return back
        notify(owner, 'Bạn đã trở thành chủ khoá',
               f'Quản trị viên đã gán khoá "{device.name}" cho tài khoản của bạn.', device=device, type_='DEVICE')
        messages.success(request, f'Đã gán khoá cho {owner.email}.')
        return back

    if action == 'remove_owner':
        ok, err = confirm_sensitive(request, device.device_code, upper=True)
        if not ok:
            messages.error(request, REAUTH_ERROR if err == 'reauth'
                           else 'Nhập đúng mã thiết bị vào ô xác nhận để gỡ chủ.')
            return back
        try:
            with transaction.atomic():
                _dev, previous, counts = services.release_device(device.id)
                audit(request, 'MANAGE_DEVICE_OWNER_REMOVED', device=device, target_user=previous,
                      severity='critical', metadata={'previous_owner': previous.email, 'revoked': counts},
                      strict=True)
        except services.ClaimError as exc:
            messages.error(request, exc.message)
            return back
        except services.AuditWriteError:
            messages.error(request, AUDIT_ERROR)
            return back
        notify(previous, 'Khoá đã bị gỡ khỏi tài khoản của bạn',
               f'Quản trị viên đã gỡ chủ sở hữu khoá "{device.name}". Mọi quyền truy cập, thẻ, mã PIN và '
               'khuôn mặt của khoá đã bị vô hiệu hoá. Bạn có thể tự thêm lại bằng mã thiết bị + secret.',
               severity='critical', device=device, type_='DEVICE')
        messages.success(request, 'Đã gỡ chủ. Chỉ người dùng mới tự thêm lại được khoá này (admin không gán lại).')
        return back

    if action == 'rotate_secret':
        ok, err = confirm_sensitive(request, device.device_code, upper=True)
        if not ok:
            messages.error(request, REAUTH_ERROR if err == 'reauth'
                           else 'Nhập đúng mã thiết bị vào ô xác nhận để xoay secret.')
            return back
        try:
            with transaction.atomic():
                dev, secret = services.rotate_secret(device.id)
                audit(request, 'MANAGE_DEVICE_SECRET_ROTATED', device=dev, target_user=dev.owner,
                      severity='critical', strict=True)
        except services.AuditWriteError:
            messages.error(request, AUDIT_ERROR)
            return back
        if dev.owner_id:
            notify(dev.owner, 'Secret thiết bị đã được đổi',
                   f'Quản trị viên đã đổi secret kết nối của "{dev.name}". Thiết bị cần được nạp lại secret mới.',
                   severity='warning', device=dev, type_='DEVICE')
        stash_secret(request, dev, secret, rotated=True)
        return redirect('manage_sys:device-secret', device_id=dev.id)

    messages.error(request, 'Hành động không hợp lệ.')
    return back


@manage_required
@require_http_methods(['GET', 'POST'])
def device_detail(request, device_id):
    device = get_object_or_404(Device.objects.select_related('owner'), id=device_id)

    if request.method == 'POST':
        return _device_actions(request, device)

    audit(request, 'MANAGE_VIEW_DEVICE', device=device, target_user=device.owner)   # admin xem dữ liệu cũng được ghi
    link = services.link_status(device)
    context = {
        'device': device,
        'link': link,
        # Toàn bộ thông tin thiết lập khoá để admin xem (secret gốc không lưu, chỉ có dấu vân tay hash).
        'setup': {
            'device_code': device.device_code, 'mqtt_username': device.device_code,
            'secret_fingerprint': (device.provisioning_secret_hash or '')[:8],
            'mac': device.mac_address, 'firmware': device.firmware_version, 'mode': device.device_mode,
            'cmd_topic': f'smartlock/{device.device_code}/cmd',
            'publish_topics': [f'smartlock/{device.device_code}/{c}' for c in ('status', 'ack', 'event')],
        },
        # Admin chỉ được gán chủ cho khoá MỚI (provisioning). Khoá revoked => chỉ user tự thêm.
        'admin_can_claim': (not device.owner_id) and device.status == 'provisioning',
        'user_must_claim': (not device.owner_id) and device.status == 'revoked',
        'last_log': DeviceStatusLog.objects.filter(device=device).order_by('-recorded_at').first(),
        'commands': (DeviceCommand.objects.filter(device=device)
                     .select_related('issued_by').order_by('-created_at')[:10]),
        'accesses': (DeviceAccess.objects.filter(device=device, is_active=True)
                     .select_related('user').prefetch_related('permissions').order_by('-created_at')),
        'readers': NfcReader.objects.filter(device=device).order_by('-created_at'),
        'logs': (AuditLog.objects.filter(device=device)
                 .select_related('actor_user').order_by('-created_at')[:10]),
        'can_sensitive': has_full_power(request.user),   # template ẩn nút xoay secret / gỡ chủ nếu False
        # ---- Admin xem được toàn bộ: chỉ METADATA, không bao giờ đưa hash PIN / UID thẻ / embedding / ảnh ra ----
        'cards': (CardDeviceAccess.objects.filter(device=device)
                  .select_related('access_card', 'access_card__user')
                  .only('is_active', 'created_at', 'access_card__name', 'access_card__is_active',
                        'access_card__user__email').order_by('-created_at')),
        'pins': (DoorPinCode.objects.filter(device=device).select_related('created_by')
                 .only('label', 'valid_from', 'expires_at', 'max_uses', 'use_count', 'is_revoked',
                       'created_at', 'created_by__email').order_by('-created_at')[:50]),
        'faces': (FaceProfile.objects.filter(device=device).select_related('user')
                  .only('name', 'is_active', 'consent_confirmed', 'created_at', 'user__email')
                  .order_by('-created_at')),
        'access_events': (AccessEvent.objects.filter(device=device).select_related('user')
                          .only('method', 'success', 'reason', 'created_at', 'user__email')
                          .order_by('-created_at')[:30]),
    }
    return _render(request, 'device_detail', context)


@manage_required
@require_http_methods(['GET'])
def device_secret(request, device_id):
    """Hiển thị secret MỘT LẦN sau khi tạo thiết bị / xoay secret. Chỉ là GET (an toàn khi F5);
    secret được lấy ra khỏi session (mã hoá) và xoá ngay, nên tải lại trang sẽ không còn secret."""
    device = get_object_or_404(Device, id=device_id)
    data = pop_secret(request, device.id)
    if not data:
        messages.info(request, 'Secret chỉ hiển thị một lần và đã được xem / hết hạn. '
                               'Nếu chưa chép kịp, hãy dùng "Xoay secret" để tạo secret mới.')
        return redirect('manage_sys:device-detail', device_id=device.id)
    audit(request, 'MANAGE_DEVICE_SECRET_REVEALED', device=device, severity='warning')   # không ghi giá trị secret
    resp = _render(request, 'device_created', {
        'device': device, 'secret': data['secret'], 'rotated': data['rotated'],
        'pending_owner': _find_user(data['owner']) if data['owner'] else None,
        'claim_url': reverse('manage_sys:device-detail', args=[device.id]),
        'api_base': request.build_absolute_uri('/').rstrip('/'),
    })
    resp['Cache-Control'] = 'no-store, private'
    return resp


@manage_required
def device_link_status(request, device_id):
    """JSON cho chỉ báo 'đã kết nối?' ở trang chi tiết (trang tự gọi lặp mỗi vài giây). Chỉ đọc."""
    device = get_object_or_404(Device, id=device_id)
    st = services.link_status(device)
    resp = JsonResponse({
        'connected': st['connected'], 'seconds_ago': st['seconds_ago'],
        'last_seen_at': st['last_seen_at'].isoformat() if st['last_seen_at'] else None,
        'firmware': st['firmware'], 'battery': st['battery'], 'status': st['status'],
        'has_owner': st['has_owner'], 'ping_status': st['ping_status'],
        'ping_at': st['ping_at'].isoformat() if st['ping_at'] else None,
    })
    resp['Cache-Control'] = 'no-store'
    return resp


# ====================== AUDIT ======================
@manage_required
def audit_logs(request):
    qs = AuditLog.objects.select_related('actor_user', 'target_user', 'device').order_by('-created_at')

    q = (request.GET.get('q') or '').strip()
    if q:
        qs = qs.filter(Q(action__icontains=q) | Q(actor_user__email__icontains=q)
                       | Q(target_user__email__icontains=q) | Q(username_attempt__icontains=q)
                       | Q(ip_address__icontains=q))
    status = request.GET.get('status') or ''
    if status == 'ok':
        qs = qs.filter(success=True)
    elif status == 'fail':
        qs = qs.filter(success=False)
    severity = request.GET.get('severity') or ''
    if severity in ('info', 'warning', 'critical'):
        qs = qs.filter(severity=severity)
    scope = request.GET.get('scope') or ''
    if scope == 'manage':
        qs = qs.filter(action__startswith='MANAGE_')
    elif scope == 'mail':
        qs = qs.filter(action__startswith='MAIL_')

    if not request.GET.get('page'):   # chuyển trang không ghi thêm, tránh log tự phình
        audit(request, 'MANAGE_VIEW_AUDIT_LOGS', metadata={'q': q[:80], 'status': status, 'severity': severity})
    page_obj, qs_str = paginate(request, qs)
    return _render(request, 'audit_logs', {
        'page_obj': page_obj, 'qs': qs_str, 'q': q, 'status': status,
        'severity': severity, 'scope': scope,
    })


@manage_required
def login_attempts(request):
    qs = login_attempts_qs().select_related('actor_user', 'target_user').order_by('-created_at')
    q = (request.GET.get('q') or '').strip()
    if q:
        qs = qs.filter(Q(username_attempt__icontains=q) | Q(ip_address__icontains=q)
                       | Q(target_user__email__icontains=q) | Q(actor_user__email__icontains=q))
    status = request.GET.get('status') or ''
    if status == 'ok':
        qs = qs.filter(success=True)
    elif status == 'fail':
        qs = qs.filter(success=False)
    page_obj, qs_str = paginate(request, qs)
    for a in page_obj:
        decorate_login_attempt(a)
    return _render(request, 'audit_logins', {
        'page_obj': page_obj, 'qs': qs_str, 'q': q, 'status': status,
    })


# ====================== ANNOUNCEMENTS ======================
@manage_required
@require_http_methods(['GET', 'POST'])
def announcements(request):
    if request.method == 'POST':
        action = request.POST.get('action')
        if action == 'create':
            title = (request.POST.get('title') or '').strip()[:200]
            body = (request.POST.get('body') or '').strip()
            level = request.POST.get('level')
            if not title or not body:
                messages.error(request, 'Tiêu đề và nội dung không được để trống.')
            elif level not in ('info', 'warning', 'danger'):
                messages.error(request, 'Mức độ không hợp lệ.')
            else:
                ann = Announcement.objects.create(title=title, body=body, level=level,
                                                  created_by=request.user)
                audit(request, 'MANAGE_ANNOUNCE_CREATED', metadata={'announcement_id': str(ann.id)})
                messages.success(request, 'Đã đăng thông báo hệ thống.')
        elif action in ('toggle', 'delete'):
            ann_id = _parse_uuid(request.POST.get('id'))
            ann = Announcement.objects.filter(id=ann_id).first() if ann_id else None
            if not ann:
                messages.error(request, 'Không tìm thấy thông báo.')
            elif action == 'toggle':
                ann.is_active = not ann.is_active
                ann.save(update_fields=['is_active'])
                audit(request, 'MANAGE_ANNOUNCE_TOGGLED', metadata={'announcement_id': str(ann.id),
                                                                    'is_active': ann.is_active})
                messages.success(request, 'Đã bật thông báo.' if ann.is_active else 'Đã ẩn thông báo.')
            else:
                ann.delete()
                audit(request, 'MANAGE_ANNOUNCE_DELETED', severity='warning',
                      metadata={'announcement_id': str(ann_id)})
                messages.success(request, 'Đã xóa thông báo.')
        return redirect('manage_sys:announcements')

    qs = Announcement.objects.select_related('created_by').order_by('-created_at')
    page_obj, qs_str = paginate(request, qs, per_page=10)
    return _render(request, 'announcements', {'page_obj': page_obj, 'qs': qs_str})


# ====================== SETTINGS ======================
@manage_required
@require_http_methods(['GET', 'POST'])
def settings_system(request):
    st = services.SystemSettings.objects.get_or_create(pk=1)[0]   # bản tươi (không dùng bản cache để sửa)

    if request.method == 'POST':
        denied = action_denied_reason(request.user, 'update_settings')
        if denied:
            audit(request, 'MANAGE_ACTION_DENIED', success=False, severity='warning',
                  metadata={'action': 'update_settings'})
            messages.error(request, denied)
            return redirect('manage_sys:settings')
        try:
            expiry = int(request.POST.get('verification_token_expiry_minutes'))
            share = int(request.POST.get('share_code_expiry_minutes'))
            timeout = int(request.POST.get('session_timeout_hours'))
            stages = [int(x) for x in
                      re.split(r'[,\s]+', (request.POST.get('lockout_stages') or '').strip()) if x]
        except (TypeError, ValueError):
            messages.error(request, 'Giá trị không hợp lệ. Các số phải là số nguyên.')
            return redirect('manage_sys:settings')

        errors = []
        if not 1 <= expiry <= 10080:
            errors.append('Token xác thực email phải từ 1 đến 10080 phút.')
        if not 1 <= share <= 1440:
            errors.append('Thời hạn mã chia sẻ phải từ 1 đến 1440 phút.')
        if not 1 <= timeout <= 720:
            errors.append('Thời gian phiên user phải từ 1 đến 720 giờ.')
        if not stages or len(stages) > 10 or any(not 1 <= s <= 10080 for s in stages):
            errors.append('Lockout stages: 1–10 mốc, mỗi mốc từ 1 đến 10080 phút.')


        if errors:
            for e in errors:
                messages.error(request, e)
            return redirect('manage_sys:settings')

        before = {'expiry': st.verification_token_expiry_minutes, 'share': st.share_code_expiry_minutes,
                  'timeout': st.session_timeout_hours, 'stages': st.login_lockout_stage_minutes}
        was_registration = st.registration_enabled
        try:
            with transaction.atomic():
                st.registration_enabled = 'registration_enabled' in request.POST
                st.verification_token_expiry_minutes = expiry
                st.share_code_expiry_minutes = share
                st.session_timeout_hours = timeout
                st.login_lockout_stage_minutes = stages
                st.updated_by = request.user
                st.save()
                services.invalidate_system_settings()
                audit(request, 'MANAGE_SETTINGS_UPDATED', severity='warning', strict=True,
                      metadata={'registration_enabled': [was_registration, st.registration_enabled],
                                'before': before,
                                'after': {'expiry': expiry, 'share': share, 'timeout': timeout, 'stages': stages}})
        except services.AuditWriteError:
            messages.error(request, AUDIT_ERROR)
            return redirect('manage_sys:settings')
        messages.success(request, 'Đã lưu cài đặt hệ thống.')
        return redirect('manage_sys:settings')

    return _render(request, 'settings', {
        'st': st,
        'can_edit': has_full_power(request.user),   # ADMIN_FULL_POWER=False -> admin thường chỉ xem
        'stages_text': ', '.join(str(x) for x in (st.login_lockout_stage_minutes or [])),
    })