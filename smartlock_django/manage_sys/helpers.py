# manage_sys/helpers.py
"""Hàm dùng chung của trang quản trị. Không import gì từ smartlock.views.

Ghi log / thông báo / khóa đăng nhập / lấy IP dùng CHUNG bản ở smartlock.services (một nguồn duy nhất,
trước đây hai nơi tự cài đặt và đã lệch nhau). Ở đây chỉ re-export để views/decorators import gọn.
"""
import logging
import math
import secrets

from cryptography.fernet import InvalidToken
from django.contrib.auth.hashers import check_password, make_password
from django.core.paginator import Paginator
from django.utils import timezone

from smartlock.models import AuditLog, User, fernet
from smartlock.services import (  # noqa: F401  (re-export)
    MAX_FAILED_ATTEMPTS, audit, client_ip, is_admin as _services_is_admin, notify, register_failure,
    reset_lockout, system_settings, user_agent,
)

logger = logging.getLogger('smartlock.manage_sys')

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


# Thao tác NHẠY CẢM: chỉ Superuser được làm. Admin thường có quyền xem + vận hành gần như Superuser
# nhưng KHÔNG chạm được các thao tác này (cấp/thu hồi quyền quản trị, đổi secret thiết bị, gỡ chủ khoá
# -> huỷ luôn thẻ NFC / PIN / khuôn mặt của chủ). Muốn nới/siết quyền admin chỉ cần sửa tập này.
SUPERUSER_ONLY_ACTIONS = frozenset({'grant_admin', 'revoke_admin', 'rotate_secret', 'remove_owner',
                                     'update_settings'})


def is_superuser_role(user):
    return bool(user and user.is_authenticated and user.is_active and user.is_superuser)


def action_denied_reason(actor, action):
    """Lý do KHÔNG được làm `action` (thao tác nhạy cảm), hoặc None nếu được phép."""
    if action in SUPERUSER_ONLY_ACTIONS and not actor.is_superuser:
        return 'Thao tác nhạy cảm: chỉ Superuser mới được thực hiện.'
    return None


def modify_denied_reason(actor, target):
    """Trả về lý do KHÔNG được sửa target, hoặc None nếu được phép.
    Admin quản lý được mọi tài khoản (kể cả admin khác); riêng tài khoản Superuser chỉ Superuser mới đụng được."""
    if actor.pk == target.pk:
        return 'Không thể tự thao tác lên chính tài khoản của bạn.'
    if target.is_superuser and not actor.is_superuser:
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