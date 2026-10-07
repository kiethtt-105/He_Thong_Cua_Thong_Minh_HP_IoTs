"""Views của giao diện web (smartlock).

Từ bản này, các view CHỈ render "khung trang" (layout + form). Mọi dữ liệu của người dùng được trình duyệt lấy qua
API dùng chung web/app (smartlock/api/app/...): đọc bằng GET /api/app/snapshot/ (cache sessionStorage, làm mới 3 giây),
ghi bằng các endpoint /api/app/... (đăng nhập, đăng xuất, 2FA, thiết bị, thẻ, PIN, chia sẻ...).
Còn lại ở đây: trang khung, webhook MQTT (server-to-server) và trang demo log công khai.
"""
import hmac
import logging
from datetime import timedelta
from functools import wraps

from django.conf import settings as dj_settings
from django.contrib import messages
from django.contrib.auth import logout
from django.contrib.auth.decorators import login_required
from django.db.models import Avg, Count, OuterRef, Q, Subquery
from django.db.models.functions import TruncMinute
from django.http import Http404, JsonResponse
from django.shortcuts import redirect, render
from django.utils import timezone
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_POST

from . import services
from .models import (
    AuditLog, Device, DeviceCommand, DeviceStatusLog, NfcLog, Notification, User,
)
from .services import (
    audit as _audit, is_admin as _is_admin, system_settings as _settings,
)

logger = logging.getLogger('smartlock.views')

# ====================== AUTH REQUIRED DECORATOR (đưa lên đầu) ======================
_login_required = login_required(login_url='smartlock:login')


def auth_required(view_func):
    """Đăng nhập + KHÔNG phải tài khoản quản trị. Admin chỉ dùng cổng manage_sys; nếu một phiên user
    được nâng quyền admin sau khi đăng nhập thì phiên đó bị huỷ ở request kế tiếp."""
    @_login_required
    @wraps(view_func)
    def wrapper(request, *args, **kwargs):
        if _is_admin(request.user):
            _audit(request, 'USER_SITE_ADMIN_REJECTED', success=False, severity='warning',
                   target_user=request.user)
            logout(request)
            messages.error(request, 'Tài khoản quản trị chỉ đăng nhập ở cổng quản trị.')
            return redirect('smartlock:login')
        return view_func(request, *args, **kwargs)
    return wrapper



# ====================== RENDER: mỗi nhóm trang gộp 1 template, chọn trang bằng biến `page` ======================
PAGE_TEMPLATE = {
    "login": "auth",
    "register": "auth",
    "reset_password": "auth",
    "verify_email": "auth",
    "devices_list": "devices",
    "device_detail": "devices",
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


# ====================== TRANG XÁC THỰC (khung; việc xử lý do JS gọi API /api/app/auth/...) ======================
def login_view(request):
    if request.user.is_authenticated:
        return redirect('smartlock:dashboard')
    return _render(request, 'login', {'next': request.GET.get('next') or ''})


def register(request):
    if request.user.is_authenticated:
        return redirect('smartlock:dashboard')
    if not _settings().registration_enabled:
        return _render(request, 'register', {'disabled': True})
    return _render(request, 'register')


def verify_email(request, token):
    """Link trong email: chỉ hiển thị trang; JS gọi POST /api/app/auth/verify-email/ kèm token."""
    return _render(request, 'verify_email', {'token': str(token)})


def password_reset_request(request):
    return _render(request, 'reset_password', {'mode': 'request'})


def reset_password(request, uidb64, token):
    """Link trong email: chỉ hiển thị khung; JS gọi POST /api/app/auth/password-reset/check/ rồi /confirm/."""
    return _render(request, 'reset_password', {'mode': 'confirm', 'uid': uidb64, 'token': token})


def logout_view(request):
    """Dự phòng khi gặp link /logout/ cũ: đăng xuất session rồi về trang đăng nhập.
    Nút Đăng xuất trên giao diện gọi thẳng API POST /api/app/auth/logout/."""
    if request.user.is_authenticated:
        _audit(request, 'LOGOUT')
    logout(request)
    return redirect('smartlock:login')


# ====================== TRANG DỮ LIỆU (khung; dữ liệu vẽ từ SmartlockCache = API snapshot) ======================
@auth_required
def dashboard(request):
    return _render(request, 'dashboard')


@auth_required
def devices_list(request):
    return _render(request, 'devices_list')


@auth_required
def device_claim(request):
    return _render(request, 'device_claim')


@auth_required
def device_detail(request, device_id):
    return _render(request, 'device_detail', {'device_id': str(device_id)})


@auth_required
def nfc_tags(request):
    return _render(request, 'nfc_tags')


@auth_required
def nfc_reader(request):
    return _render(request, 'nfc_reader')


@auth_required
def shares_manage(request):
    return _render(request, 'shares')


@auth_required
def door_pins(request):
    return _render(request, 'door_pins')


@auth_required
def face_profiles(request):
    return _render(request, 'face_profiles')


@auth_required
def access_events_history(request):
    return _render(request, 'access_history')


@auth_required
def notifications_list(request):
    return _render(request, 'notifications')


@auth_required
def profile(request):
    return _render(request, 'profile')


@auth_required
def audit_logs(request):
    return _render(request, 'audit_logs')


@auth_required
def live_page(request, device_id):
    """Trang xem trực tiếp: chỉ render khung; JS poll API device-live (tên, mã, trạng thái, quyền truy cập do API kiểm tra)."""
    return render(request, 'account/live.html', {'device_id': str(device_id)})


# ====================== MQTT (server-to-server, không phải route cho người dùng) ======================
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
    return services.safe_eq(request.META.get('HTTP_X_WEBHOOK_SECRET', ''), secret)


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
        if services.safe_eq(password, expected):
            return JsonResponse({'ok': True})
        _audit(request, 'MQTT_AUTH_DENIED', success=False, severity='warning',
               username_attempt=username[:150])
        return JsonResponse({'ok': False}, status=401)

    device = Device.objects.filter(device_code=username).first()
    if not device or not services.safe_eq(device.provisioning_secret_hash, services.hash_token(password)):
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