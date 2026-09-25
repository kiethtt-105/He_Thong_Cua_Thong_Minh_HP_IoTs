# manage_sys/views.py
"""
Trang quản trị (Manage Sys) - tách hoàn toàn khỏi views của user thường.
Chỉ dùng chung MODELS với app smartlock.
"""
import logging
import re
import uuid
from datetime import timedelta

from django.conf import settings as dj_settings
from django.contrib import messages
from django.contrib.auth import authenticate, login, logout
from django.db import transaction
from django.db.models import Count, Q
from django.db.models.functions import TruncDate
from django.shortcuts import get_object_or_404, redirect, render
from django.utils import timezone
from django.utils.http import url_has_allowed_host_and_scheme
from django.views.decorators.cache import never_cache
from django.views.decorators.http import require_http_methods, require_POST

from smartlock.models import (
    Announcement, AuditLog, Device, DeviceAccess, DeviceCommand, DeviceStatusLog,
    LoginAttemptLog, LoginLockout, NfcReader, SupportRequest, User,
)

from .decorators import manage_required
from .helpers import (
    RECOVERY_ACTIONS, audit, client_ip, get_settings, has_manage_role, ip_blacklisted,
    is_manager, lock_remaining_minutes, modify_denied_reason, notify, paginate,
    parse_ip_lines, register_failure, reset_lockout, user_agent,
)

logger = logging.getLogger('smartlock.manage_sys')

LOGIN_ERROR = 'Thông tin đăng nhập không đúng hoặc không có quyền truy cập.'
SESSION_SECONDS = getattr(dj_settings, 'MANAGE_SYS_SESSION_SECONDS', 2 * 3600)
URL_PREFIX = getattr(dj_settings, 'MANAGE_SYS_URL_PREFIX', '/manage-sys/')


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
        return render(request, 'manage_sys/login/login.html', ctx)

    identifier = (request.POST.get('identifier') or '').strip()
    password = request.POST.get('password') or ''
    if not identifier or not password:
        messages.error(request, 'Vui lòng điền đầy đủ thông tin.')
        return render(request, 'manage_sys/login/login.html', ctx)

    ip = client_ip(request)
    if ip_blacklisted(get_settings(), ip):
        audit(request, 'MANAGE_LOGIN_BLOCKED_IP', actor=None, success=False,
              severity='warning', username_attempt=identifier[:150])
        messages.error(request, 'Địa chỉ IP của bạn đã bị chặn.')
        return render(request, 'manage_sys/login/login.html', ctx)

    user = _find_user(identifier)
    is_manager_account = bool(user and has_manage_role(user))

    if is_manager_account:
        remaining = lock_remaining_minutes(user)
        if remaining:
            messages.error(request, f'Tài khoản đang bị khóa tạm thời. Thử lại sau {remaining} phút.')
            audit(request, 'MANAGE_LOGIN_LOCKED', actor=None, target_user=user, success=False,
                  severity='warning', username_attempt=identifier[:150])
            return render(request, 'manage_sys/login/login.html', ctx)

    auth_user = authenticate(request, username=user.email, password=password) if user else None
    ok = bool(auth_user and has_manage_role(auth_user))

    LoginAttemptLog.objects.create(
        identifier=f'[manage] {identifier}'[:255], user=user, ip_address=ip,
        user_agent=user_agent(request), success=ok,
    )

    if ok:
        reset_lockout(auth_user)
        login(request, auth_user)
        request.session.set_expiry(SESSION_SECONDS)
        audit(request, 'MANAGE_LOGIN', actor=auth_user)
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
    return render(request, 'manage_sys/login/login.html', ctx)


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

    stats = {
        'total_users': User.objects.count(),
        'active_users': User.objects.filter(is_active=True).count(),
        'unverified_users': User.objects.filter(is_active=False, email_verified=False).count(),
        'total_devices': Device.objects.count(),
        'online_devices': Device.objects.filter(status='online').count(),
        'maintenance_devices': Device.objects.filter(status='maintenance').count(),
        'support_pending': SupportRequest.objects.filter(status='pending', expires_at__gt=now).count(),
        'failed_logins_24h': LoginAttemptLog.objects.filter(success=False, created_at__gte=day_ago).count(),
        'locked_accounts': LoginLockout.objects.filter(locked_until__gt=now).count(),
        'critical_24h': AuditLog.objects.filter(severity='critical', created_at__gte=day_ago).count(),
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
        'pending_requests': (SupportRequest.objects.filter(status='pending', expires_at__gt=now)
                             .select_related('device', 'requested_by').order_by('expires_at')[:6]),
        'alert_logs': (AuditLog.objects.filter(severity__in=['warning', 'critical'])
                       .select_related('actor_user', 'device').order_by('-created_at')[:8]),
    }
    return render(request, 'manage_sys/dashboard/dashboard.html', context)


# ====================== USERS ======================
@manage_required
def users_list(request):
    qs = User.objects.annotate(device_count=Count('device', distinct=True)).order_by('-created_at')

    q = (request.GET.get('q') or '').strip()
    if q:
        qs = qs.filter(Q(email__icontains=q) | Q(username__icontains=q)
                       | Q(full_name__icontains=q) | Q(phone__icontains=q))

    status = request.GET.get('status') or ''
    now = timezone.now()
    if status == 'active':
        qs = qs.filter(is_active=True)
    elif status == 'inactive':
        qs = qs.filter(is_active=False)
    elif status == 'locked':
        qs = qs.filter(login_lockout__locked_until__gt=now)
    elif status == 'admin':
        qs = qs.filter(Q(is_admin=True) | Q(is_staff=True) | Q(is_superuser=True))

    page_obj, qs_str = paginate(request, qs)
    locked_ids = set(LoginLockout.objects.filter(
        user__in=[u.pk for u in page_obj], locked_until__gt=now).values_list('user_id', flat=True))
    for u in page_obj:
        u.is_locked = u.pk in locked_ids
        u.is_manager_role = has_manage_role(u)

    return render(request, 'manage_sys/users/list.html', {
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

        if action == 'toggle_active':
            target.is_active = not target.is_active
            target.save(update_fields=['is_active', 'updated_at'])
            audit(request, 'MANAGE_USER_ACTIVATED' if target.is_active else 'MANAGE_USER_DEACTIVATED',
                  target_user=target, severity='info' if target.is_active else 'warning')
            messages.success(request, 'Đã kích hoạt tài khoản.' if target.is_active
                             else 'Đã vô hiệu hóa tài khoản.')

        elif action == 'unlock':
            reset_lockout(target)
            audit(request, 'MANAGE_USER_UNLOCKED', target_user=target)
            notify(target, 'Tài khoản đã được mở khóa',
                   'Quản trị viên đã mở khóa đăng nhập cho tài khoản của bạn.', type_='SECURITY')
            messages.success(request, 'Đã mở khóa đăng nhập.')

        elif action in ('grant_admin', 'revoke_admin'):
            if not request.user.is_superuser:
                messages.error(request, 'Chỉ Superuser mới được thay đổi quyền quản trị.')
                return back
            if action == 'grant_admin':
                if not target.is_active:
                    messages.error(request, 'Hãy kích hoạt tài khoản trước khi cấp quyền quản trị.')
                    return back
                target.is_admin = True
                target.save(update_fields=['is_admin', 'updated_at'])
                audit(request, 'MANAGE_ROLE_GRANTED', target_user=target, severity='critical')
                messages.success(request, 'Đã cấp quyền quản trị.')
            else:
                target.is_admin = target.is_staff = target.is_superuser = False
                target.save(update_fields=['is_admin', 'is_staff', 'is_superuser', 'updated_at'])
                audit(request, 'MANAGE_ROLE_REVOKED', target_user=target, severity='critical')
                messages.success(request, 'Đã thu hồi quyền quản trị.')
        else:
            messages.error(request, 'Hành động không hợp lệ.')
        return back

    now = timezone.now()
    lock = LoginLockout.objects.filter(user=target).first()
    context = {
        'target': target,
        'lock': lock,
        'is_locked': bool(lock and lock.locked_until and lock.locked_until > now),
        'target_is_manager': has_manage_role(target),
        'deny_reason': modify_denied_reason(request.user, target),
        'devices': Device.objects.filter(owner=target).order_by('name'),
        'accesses': (DeviceAccess.objects.filter(user=target, is_active=True)
                     .select_related('device').order_by('-created_at')[:10]),
        'login_attempts': LoginAttemptLog.objects.filter(user=target).order_by('-created_at')[:10],
        'logs': (AuditLog.objects.filter(Q(actor_user=target) | Q(target_user=target))
                 .select_related('device').order_by('-created_at')[:10]),
    }
    return render(request, 'manage_sys/users/detail.html', context)


# ====================== DEVICES ======================
@manage_required
def devices_list(request):
    qs = Device.objects.select_related('owner').order_by('name')

    q = (request.GET.get('q') or '').strip()
    if q:
        qs = qs.filter(Q(name__icontains=q) | Q(device_code__icontains=q)
                       | Q(mac_address__icontains=q) | Q(owner__email__icontains=q)
                       | Q(owner__username__icontains=q))
    status = request.GET.get('status') or ''
    if status in dict(Device._meta.get_field('status').choices):
        qs = qs.filter(status=status)
    mode = request.GET.get('mode') or ''
    if mode in ('physical', 'simulated'):
        qs = qs.filter(device_mode=mode)

    page_obj, qs_str = paginate(request, qs)
    return render(request, 'manage_sys/devices/list.html', {
        'page_obj': page_obj, 'qs': qs_str, 'q': q, 'status': status, 'mode': mode,
        'status_choices': Device._meta.get_field('status').choices,
    })


@manage_required
@require_http_methods(['GET', 'POST'])
def device_detail(request, device_id):
    device = get_object_or_404(Device.objects.select_related('owner'), id=device_id)
    back = redirect('manage_sys:device-detail', device_id=device.id)

    if request.method == 'POST':
        action = request.POST.get('action')
        if action not in ('maintenance_on', 'maintenance_off'):
            messages.error(request, 'Hành động không hợp lệ.')
            return back
        if not device.owner_id:
            # Ràng buộc DB: chưa có chủ thì phải ở trạng thái 'provisioning'
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

    context = {
        'device': device,
        'last_log': DeviceStatusLog.objects.filter(device=device).order_by('-recorded_at').first(),
        'commands': (DeviceCommand.objects.filter(device=device)
                     .select_related('issued_by').order_by('-created_at')[:10]),
        'accesses': (DeviceAccess.objects.filter(device=device, is_active=True)
                     .select_related('user').prefetch_related('permissions').order_by('-created_at')),
        'readers': NfcReader.objects.filter(device=device).order_by('-created_at'),
        'support_reqs': (SupportRequest.objects.filter(device=device)
                         .select_related('requested_by').order_by('-created_at')[:5]),
        'logs': (AuditLog.objects.filter(device=device)
                 .select_related('actor_user').order_by('-created_at')[:10]),
    }
    return render(request, 'manage_sys/devices/detail.html', context)


# ====================== SUPPORT ======================
_SUPPORT_TRANSITIONS = {
    # action: (trạng thái hiện tại được phép, trạng thái mới, nhãn, mức độ)
    'approve': ('pending', 'approved', 'duyệt', 'info'),
    'reject': ('pending', 'rejected', 'từ chối', 'warning'),
    'execute': ('approved', 'executed', 'đánh dấu đã thực hiện', 'warning'),
}


@manage_required
def support_list(request):
    qs = SupportRequest.objects.select_related('device', 'requested_by').order_by('-created_at')

    q = (request.GET.get('q') or '').strip()
    if q:
        qs = qs.filter(Q(device__name__icontains=q) | Q(device__device_code__icontains=q)
                       | Q(requested_by__email__icontains=q) | Q(requested_by__username__icontains=q))
    status = request.GET.get('status') or ''
    if status in dict(SupportRequest._meta.get_field('status').choices):
        qs = qs.filter(status=status)
    action = request.GET.get('action') or ''
    if action in dict(SupportRequest._meta.get_field('action').choices):
        qs = qs.filter(action=action)

    page_obj, qs_str = paginate(request, qs)
    now = timezone.now()
    for sr in page_obj:
        sr.is_overdue = sr.status in ('pending', 'approved') and sr.expires_at <= now
        sr.is_sensitive = sr.action in RECOVERY_ACTIONS

    return render(request, 'manage_sys/support/list.html', {
        'page_obj': page_obj, 'qs': qs_str, 'q': q, 'status': status, 'action': action,
        'status_choices': SupportRequest._meta.get_field('status').choices,
        'action_choices': SupportRequest._meta.get_field('action').choices,
    })


@manage_required
@require_http_methods(['GET', 'POST'])
def support_detail(request, request_id):
    if request.method == 'POST':
        action = request.POST.get('action')
        rule = _SUPPORT_TRANSITIONS.get(action)
        if not rule:
            messages.error(request, 'Hành động không hợp lệ.')
            return redirect('manage_sys:support-detail', request_id=request_id)

        required, new_status, label, severity = rule
        reason = (request.POST.get('reason') or '').strip()[:300]
        now = timezone.now()

        with transaction.atomic():
            # khóa dòng để tránh 2 admin xử lý cùng lúc
            sr = get_object_or_404(SupportRequest.objects.select_for_update(), id=request_id)
            if sr.status != required:
                messages.error(request, 'Trạng thái yêu cầu đã thay đổi, không thể thực hiện thao tác này.')
            elif sr.expires_at <= now:
                sr.status = 'expired'
                sr.completed_at = now
                sr.save(update_fields=['status', 'completed_at'])
                audit(request, 'MANAGE_SUPPORT_EXPIRED', device=sr.device, target_user=sr.requested_by,
                      metadata={'request_id': str(sr.id)})
                messages.error(request, 'Yêu cầu đã hết hạn nên được chuyển sang "Hết hạn".')
            else:
                sr.status = new_status
                sr.processed_by = request.user
                if new_status in ('rejected', 'executed'):
                    sr.completed_at = now
                sr.save(update_fields=['status', 'processed_by', 'completed_at'])
                audit(request, f'MANAGE_SUPPORT_{action.upper()}', device=sr.device,
                      target_user=sr.requested_by, severity=severity,
                      metadata={'request_id': str(sr.id), 'reason': reason})
                text = f'Yêu cầu hỗ trợ "{sr.get_action_display()}" cho "{sr.device.name}" đã được {label}.'
                if reason:
                    text += f' Ghi chú: {reason}'
                notify(sr.requested_by, 'Cập nhật yêu cầu hỗ trợ', text,
                       severity='warning' if new_status == 'rejected' else 'info',
                       device=sr.device, type_='SUPPORT')
                messages.success(request, f'Đã {label} yêu cầu.')
        return redirect('manage_sys:support-detail', request_id=request_id)

    sr = get_object_or_404(
        SupportRequest.objects.select_related('device', 'device__owner', 'requested_by', 'processed_by'),
        id=request_id)
    now = timezone.now()
    context = {
        'sr': sr,
        'is_overdue': sr.status in ('pending', 'approved') and sr.expires_at <= now,
        'is_sensitive': sr.action in RECOVERY_ACTIONS,
        'logs': (AuditLog.objects.filter(device=sr.device, action__startswith='SUPPORT_')
                 .order_by('-created_at')[:5]),
    }
    return render(request, 'manage_sys/support/detail.html', context)


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

    page_obj, qs_str = paginate(request, qs)
    return render(request, 'manage_sys/audit/logs.html', {
        'page_obj': page_obj, 'qs': qs_str, 'q': q, 'status': status,
        'severity': severity, 'scope': scope,
    })


@manage_required
def login_attempts(request):
    qs = LoginAttemptLog.objects.select_related('user').order_by('-created_at')
    q = (request.GET.get('q') or '').strip()
    if q:
        qs = qs.filter(Q(identifier__icontains=q) | Q(ip_address__icontains=q))
    status = request.GET.get('status') or ''
    if status == 'ok':
        qs = qs.filter(success=True)
    elif status == 'fail':
        qs = qs.filter(success=False)
    page_obj, qs_str = paginate(request, qs)
    return render(request, 'manage_sys/audit/logins.html', {
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
    return render(request, 'manage_sys/announcements/announcements.html', {'page_obj': page_obj, 'qs': qs_str})


# ====================== SETTINGS ======================
@manage_required
@require_http_methods(['GET', 'POST'])
def settings_system(request):
    st = get_settings()

    if request.method == 'POST':
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

        whitelist, bad_w = parse_ip_lines(request.POST.get('ip_whitelist'))
        blacklist, bad_b = parse_ip_lines(request.POST.get('ip_blacklist'))
        if bad_w or bad_b:
            errors.append('IP không hợp lệ: ' + ', '.join((bad_w + bad_b)[:5]))
        if client_ip(request) in blacklist:
            errors.append('Không thể chặn IP hiện tại của chính bạn.')

        if errors:
            for e in errors:
                messages.error(request, e)
            return redirect('manage_sys:settings')

        was_registration = st.registration_enabled
        st.registration_enabled = 'registration_enabled' in request.POST
        st.verification_token_expiry_minutes = expiry
        st.share_code_expiry_minutes = share
        st.session_timeout_hours = timeout
        st.login_lockout_stage_minutes = stages
        st.ip_whitelist = '\n'.join(whitelist)
        st.ip_blacklist = '\n'.join(blacklist)
        st.updated_by = request.user
        st.save()
        audit(request, 'MANAGE_SETTINGS_UPDATED', severity='warning',
              metadata={'registration_enabled': [was_registration, st.registration_enabled],
                        'blacklist_count': len(blacklist)})
        messages.success(request, 'Đã lưu cài đặt hệ thống.')
        return redirect('manage_sys:settings')

    return render(request, 'manage_sys/settings/settings.html', {
        'st': st,
        'stages_text': ', '.join(str(x) for x in (st.login_lockout_stage_minutes or [])),
    })