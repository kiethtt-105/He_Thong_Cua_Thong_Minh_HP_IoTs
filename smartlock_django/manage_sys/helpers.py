# manage_sys/helpers.py
"""Hàm dùng chung của trang quản trị. Không import gì từ smartlock.views."""
import ipaddress
import logging
import math
from datetime import timedelta

from django.conf import settings as dj_settings
from django.core.paginator import Paginator
from django.db import transaction
from django.utils import timezone

from smartlock.models import (
    AuditLog, Notification, SystemSettings, User,
)

logger = logging.getLogger('smartlock.manage_sys')

PAGE_SIZE = 20
MAX_FAILED_ATTEMPTS = 5
DEFAULT_LOCKOUT_STAGES = [5, 10, 30]
# Các hành động hỗ trợ nhạy cảm (khớp CheckConstraint chk_support_requires_recovery)
RECOVERY_ACTIONS = {'RESET_REMOTE', 'RECOVERY', 'TRANSFER_OWNER'}

# Lượt đăng nhập nay lấy từ AuditLog (bảng LoginAttemptLog cũ đã gộp vào AuditLog).
LOGIN_ACTIONS = ('LOGIN', 'LOGIN_FAILED', 'LOGIN_ADMIN_REJECTED',
                 'MANAGE_LOGIN', 'MANAGE_LOGIN_DENIED', 'MANAGE_LOGIN_FAILED')
LOGIN_FAIL_ACTIONS = ('LOGIN_FAILED', 'LOGIN_ADMIN_REJECTED', 'MANAGE_LOGIN_DENIED', 'MANAGE_LOGIN_FAILED')


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


# ---------- Request ----------
def client_ip(request):
    def _valid(v):
        try:
            return str(ipaddress.ip_address((v or '').strip()))
        except ValueError:
            return None
    ip = None
    if getattr(dj_settings, 'TRUST_PROXY_HEADERS', False):
        ip = _valid((request.META.get('HTTP_X_FORWARDED_FOR') or '').split(',')[0])
    return ip or _valid(request.META.get('REMOTE_ADDR')) or '0.0.0.0'


def user_agent(request):
    return (request.META.get('HTTP_USER_AGENT') or '')[:500]


def get_settings():
    return SystemSettings.objects.get_or_create(pk=1)[0]


def ip_blacklisted(st, ip):
    lines = [l.strip() for l in (st.ip_blacklist or '').splitlines()]
    return ip in [l for l in lines if l]


def parse_ip_lines(text):
    """Trả về (danh sách IP hợp lệ, danh sách dòng lỗi)."""
    good, bad = [], []
    for line in (text or '').splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            good.append(str(ipaddress.ip_address(line)))
        except ValueError:
            bad.append(line)
    return good, bad


# ---------- Ghi log / thông báo ----------
def audit(request, action, *, device=None, target_user=None, success=True,
          severity='info', metadata=None, actor='auto', username_attempt=None):
    if actor == 'auto':
        actor = request.user if request.user.is_authenticated else None
    try:
        AuditLog.objects.create(
            actor_user=actor, target_user=target_user, device=device, action=action[:50],
            username_attempt=username_attempt, severity=severity, success=success,
            ip_address=client_ip(request), user_agent=user_agent(request), metadata=metadata,
        )
    except Exception:
        logger.exception('manage_sys audit: không ghi được log %s', action)


def notify(user, title, message, severity='info', device=None, type_='SYSTEM'):
    try:
        Notification.objects.create(
            user=user, device=device, type=type_, title=title[:150],
            message=message, severity=severity,
        )
    except Exception:
        logger.exception('manage_sys notify: không tạo được thông báo cho %s', user)


# ---------- Khóa đăng nhập ----------
def register_failure(user, ip):
    st = get_settings()
    stages = st.login_lockout_stage_minutes or DEFAULT_LOCKOUT_STAGES
    now = timezone.now()
    locked_minutes = None
    with transaction.atomic():
        lock = User.objects.select_for_update().get(pk=user.pk)
        lock.login_failed_attempts += 1
        lock.login_last_failed_at = now
        lock.login_last_failed_ip = ip
        if lock.login_failed_attempts >= MAX_FAILED_ATTEMPTS:
            locked_minutes = stages[min(lock.login_lock_stage, len(stages) - 1)]
            lock.login_locked_until = now + timedelta(minutes=locked_minutes)
            lock.login_lock_stage += 1
            lock.login_failed_attempts = 0
        lock.save(update_fields=['login_failed_attempts', 'login_last_failed_at', 'login_last_failed_ip',
                                 'login_locked_until', 'login_lock_stage', 'updated_at'])
    if locked_minutes:
        notify(user, 'Tài khoản quản trị bị khóa tạm thời',
               f'Đăng nhập trang quản trị sai nhiều lần từ IP {ip}. Khóa {locked_minutes} phút.',
               severity='critical', type_='LOGIN_LOCKOUT')


def reset_lockout(user):
    User.objects.filter(pk=user.pk).update(
        login_failed_attempts=0, login_lock_stage=0, login_locked_until=None,
    )


def lock_remaining_minutes(user):
    locked_until = User.objects.filter(pk=user.pk).values_list('login_locked_until', flat=True).first()
    now = timezone.now()
    if locked_until and locked_until > now:
        return math.ceil((locked_until - now).total_seconds() / 60)
    return 0


# ---------- Phân trang ----------
def paginate(request, queryset, per_page=PAGE_SIZE):
    """Trả về (page_obj, qs) - qs là query string giữ lại bộ lọc, dạng '&a=b'."""
    page_obj = Paginator(queryset, per_page).get_page(request.GET.get('page'))
    params = request.GET.copy()
    params.pop('page', None)
    encoded = params.urlencode()
    return page_obj, ('&' + encoded if encoded else '')