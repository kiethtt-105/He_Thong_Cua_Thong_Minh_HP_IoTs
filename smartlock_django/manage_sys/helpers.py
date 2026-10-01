# manage_sys/helpers.py
"""Hàm dùng chung của trang quản trị. Không import gì từ smartlock.views.

Ghi log / thông báo / khóa đăng nhập / lấy IP dùng CHUNG bản ở smartlock.services (một nguồn duy nhất,
trước đây hai nơi tự cài đặt và đã lệch nhau). Ở đây chỉ re-export để views/decorators import gọn.
"""
import logging
import math
import secrets
from datetime import timedelta

from cryptography.fernet import InvalidToken
from django.contrib.auth.hashers import check_password, make_password
from django.core.paginator import Paginator
from django.utils import timezone

from smartlock.models import AuditLog, User, fernet
from smartlock.services import (  # noqa: F401  (re-export)
    MAX_FAILED_ATTEMPTS, audit, client_ip, notify, register_failure, reset_lockout,
    system_settings, user_agent,
)

logger = logging.getLogger('smartlock.manage_sys')

PAGE_SIZE = 20
# Các hành động hỗ trợ nhạy cảm (khớp CheckConstraint chk_support_requires_recovery)
RECOVERY_ACTIONS = {'RESET_REMOTE', 'RECOVERY', 'TRANSFER_OWNER'}

# Lượt đăng nhập nay lấy từ AuditLog (bảng LoginAttemptLog cũ đã gộp vào AuditLog).
LOGIN_ACTIONS = ('LOGIN', 'LOGIN_FAILED', 'LOGIN_ADMIN_REJECTED',
                 'MANAGE_LOGIN', 'MANAGE_LOGIN_DENIED', 'MANAGE_LOGIN_FAILED',
                 'MANAGE_LOGIN_LOCKED', 'MANAGE_LOGIN_THROTTLED')
LOGIN_FAIL_ACTIONS = ('LOGIN_FAILED', 'LOGIN_ADMIN_REJECTED', 'MANAGE_LOGIN_DENIED', 'MANAGE_LOGIN_FAILED',
                      'MANAGE_LOGIN_LOCKED', 'MANAGE_LOGIN_THROTTLED')

# Giới hạn theo IP ở cổng đăng nhập quản trị (khóa theo tài khoản không đủ: kẻ tấn công đổi email liên tục).
# Đếm các lần thất bại gần đây từ AuditLog (có index idx_auditlog_act_ip_time). MANAGE_LOGIN_THROTTLED KHÔNG
# được đếm để tránh vòng lặp tự kéo dài thời gian chặn.
IP_FAIL_LIMIT = 10
IP_FAIL_WINDOW_MINUTES = 15
_IP_FAIL_COUNTED = ('MANAGE_LOGIN_FAILED', 'MANAGE_LOGIN_DENIED', 'MANAGE_LOGIN_LOCKED')

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
    return bool(user and (user.is_admin or user.is_staff or user.is_superuser))


def is_manager(user):
    return bool(user and user.is_authenticated and user.is_active and has_manage_role(user))


def modify_denied_reason(actor, target):
    """Trả về lý do KHÔNG được sửa target, hoặc None nếu được phép."""
    if actor.pk == target.pk:
        return 'Không thể tự thao tác lên chính tài khoản của bạn.'
    if has_manage_role(target) and not actor.is_superuser:
        return 'Chỉ Superuser mới được thao tác lên tài khoản quản trị khác.'
    return None


# ---------- Đăng nhập / xác nhận lại ----------
def lock_remaining_minutes(user):
    locked_until = User.objects.filter(pk=user.pk).values_list('login_locked_until', flat=True).first()
    now = timezone.now()
    if locked_until and locked_until > now:
        return math.ceil((locked_until - now).total_seconds() / 60)
    return 0


def ip_throttled(ip):
    """True nếu IP này đã thất bại >= IP_FAIL_LIMIT lần ở cổng quản trị trong IP_FAIL_WINDOW_MINUTES."""
    since = timezone.now() - timedelta(minutes=IP_FAIL_WINDOW_MINUTES)
    return AuditLog.objects.filter(
        action__in=_IP_FAIL_COUNTED, ip_address=ip, created_at__gte=since,
    ).count() >= IP_FAIL_LIMIT


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
    register_failure(user, ip, admin_portal=True)
    audit(request, 'MANAGE_REAUTH_FAILED', success=False, severity='warning')
    return False


# ---------- Phiên app di động ----------
def revoke_mobile_sessions(user):
    """Thu hồi mọi MobileSession còn hiệu lực của user (và xoá fcm_token để ngừng push). Trả về số phiên.

    TODO(smartlock/api): hiện CHƯA có API di động nào (sẽ làm sau). Khi xây API phải đảm bảo:
      1. mọi endpoint + endpoint refresh token từ chối nếu `not user.is_active`;
      2. refresh/auth luôn kiểm tra MobileSession.is_active (revoked_at is None và chưa hết hạn);
      3. access token (JWT) nếu có phải ngắn hạn, vì token đã cấp vẫn dùng được tới khi hết hạn.
    Hàm này chỉ vô hiệu hóa phía DB; không thể thu hồi access token đã phát hành.
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
