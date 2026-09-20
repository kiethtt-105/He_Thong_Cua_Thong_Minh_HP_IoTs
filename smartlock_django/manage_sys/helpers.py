# manage_sys/helpers.py
"""Hàm dùng chung của trang quản trị. Không import gì từ smartlock.views."""
import ipaddress
import logging
import math
from datetime import timedelta

from django.core.paginator import Paginator
from django.utils import timezone

from smartlock.models import (
    AuditLog, LoginLockout, Notification, SystemSettings,
)

logger = logging.getLogger('smartlock.manage_sys')

PAGE_SIZE = 20
MAX_FAILED_ATTEMPTS = 5
DEFAULT_LOCKOUT_STAGES = [5, 10, 30]
# Các hành động hỗ trợ nhạy cảm (khớp CheckConstraint chk_support_requires_recovery)
RECOVERY_ACTIONS = {'RESET_REMOTE', 'RECOVERY', 'TRANSFER_OWNER'}


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
    xff = request.META.get('HTTP_X_FORWARDED_FOR')
    ip = xff.split(',')[0].strip() if xff else request.META.get('REMOTE_ADDR')
    return ip or '0.0.0.0'


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
    lock, _ = LoginLockout.objects.get_or_create(user=user)
    lock.failed_attempts += 1
    lock.last_failed_at = now
    lock.last_failed_ip = ip
    if lock.failed_attempts >= MAX_FAILED_ATTEMPTS:
        minutes = stages[min(lock.stage, len(stages) - 1)]
        lock.locked_until = now + timedelta(minutes=minutes)
        lock.stage += 1
        lock.failed_attempts = 0
        notify(user, 'Tài khoản quản trị bị khóa tạm thời',
               f'Đăng nhập trang quản trị sai nhiều lần từ IP {ip}. Khóa {minutes} phút.',
               severity='critical', type_='LOGIN_LOCKOUT')
    lock.save()


def reset_lockout(user):
    LoginLockout.objects.filter(user=user).update(
        failed_attempts=0, stage=0, locked_until=None,
    )


def lock_remaining_minutes(user):
    lock = LoginLockout.objects.filter(user=user).first()
    now = timezone.now()
    if lock and lock.locked_until and lock.locked_until > now:
        return math.ceil((lock.locked_until - now).total_seconds() / 60)
    return 0


# ---------- Phân trang ----------
def paginate(request, queryset, per_page=PAGE_SIZE):
    """Trả về (page_obj, qs) - qs là query string giữ lại bộ lọc, dạng '&a=b'."""
    page_obj = Paginator(queryset, per_page).get_page(request.GET.get('page'))
    params = request.GET.copy()
    params.pop('page', None)
    encoded = params.urlencode()
    return page_obj, ('&' + encoded if encoded else '')
