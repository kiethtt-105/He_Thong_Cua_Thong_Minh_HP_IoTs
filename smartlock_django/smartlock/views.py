"""Views của giao diện web (smartlock) - 100% dữ liệu và thao tác đi qua API dùng chung web/app (smartlock/api/).

Ở đây CHỈ còn:
  * render "khung trang" account/app.html (JS tự gọi /api/app/... để đăng nhập, đọc snapshot, thao tác);
  * decorator chặn tài khoản quản trị vào cổng người dùng;
  * trang demo log công khai (khung) + hàm kiểm tra quyền dùng cho sysview.py.
Không còn form POST, không truy vấn dữ liệu người dùng trong view.
"""
from functools import wraps

from django.conf import settings as dj_settings
from django.contrib import messages
from django.contrib.auth import logout
from django.contrib.auth.decorators import login_required
from django.http import Http404
from django.shortcuts import redirect, render

from .services import audit as _audit, is_admin as _is_admin
import os
import re
import time
from datetime import timedelta

from django.apps import apps
from django.db import connection
from django.db.models import Avg, Count, F, OuterRef, Q, Subquery
from django.db.models.functions import TruncHour, TruncMinute
from django.http import JsonResponse
from django.urls import URLPattern, URLResolver, get_resolver
from django.utils import timezone
from django.views.decorators.http import require_GET

from . import services
from .models import (AccessEvent, Announcement, AuditLog, CardDeviceAccess, ActivityLog, Device, DeviceAccess,
                     DeviceCommand, DeviceStatusLog, DoorPinCode, FaceProfile, MobileSession, NfcLog, NfcReader, User)

_login_required = login_required(login_url='smartlock:login')


def auth_required(view_func):
    """Phải đăng nhập và KHÔNG phải tài khoản quản trị (admin chỉ dùng cổng manage_sys)."""
    @_login_required
    @wraps(view_func)
    def wrapper(request, *args, **kwargs):
        if _is_admin(request.user):
            _audit(request, 'USER_SITE_ADMIN_REJECTED', success=False, severity='warning', target_user=request.user)
            logout(request)
            messages.error(request, 'Tài khoản quản trị chỉ đăng nhập ở cổng quản trị.')
            return redirect('smartlock:login')
        return view_func(request, *args, **kwargs)
    return wrapper


def _render(request, page, context=None):
    """Mọi trang dùng chung account/app.html; `page` chỉ để chọn lane JS cần nạp (auth hay app)."""
    return render(request, 'account/app.html', {**(context or {}), 'page': page})


# ---------- trang công khai (chưa đăng nhập): khung; JS gọi /api/app/auth/... ----------
def login_view(request):
    if request.user.is_authenticated:
        return redirect('smartlock:dashboard')
    return _render(request, 'login', {'next': request.GET.get('next') or ''})


def register(request):
    # đóng/mở đăng ký do API quyết định (auth/register/ trả REGISTRATION_DISABLED -> hiện trong form)
    if request.user.is_authenticated:
        return redirect('smartlock:dashboard')
    return _render(request, 'register')


def verify_email(request, token):
    return _render(request, 'verify_email', {'token': str(token)})


def password_reset_request(request):
    return _render(request, 'reset_password')


def reset_password(request, uidb64, token):
    return _render(request, 'reset_password', {'uid': uidb64, 'token': token})


def logout_view(request):
    """Link /logout/ cũ: hiện khung, JS gọi POST /api/app/auth/logout/ rồi về trang đăng nhập."""
    return _render(request, 'logout')


# ---------- trang sau đăng nhập: khung; dữ liệu = GET /api/app/snapshot/ ----------
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
def live_page(request, device_id):
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


# ---------- DEMO log hệ thống (công khai khi DEBUG): khung + guard; dữ liệu ở sysview.py ----------
def _require_demo_logs(request):
    """Chỉ bật khi settings.DEMO_LOGS_ENABLED; khi DEBUG=False chỉ admin đã đăng nhập xem được."""
    if not getattr(dj_settings, 'DEMO_LOGS_ENABLED', False):
        raise Http404()
    if not dj_settings.DEBUG:
        user = getattr(request, 'user', None)
        if not (user and user.is_authenticated and _is_admin(user)):
            raise Http404()


def public_system_logs(request):
    _require_demo_logs(request)
    return render(request, 'public/system_logs.html', {})


# ====================== API xem hệ thống (demo, chỉ GET) - gộp từ sysview.py ======================
SECRET_RE = re.compile(r'(hash|secret|password|token|embedding|public_key|fcm|pepper|key_enc|encrypted)', re.I)
ENV_KEYS = ['DJANGO_SECRET_KEY', 'FERNET_KEY', 'SHARE_CODE_PEPPER', 'MQTT_HOST', 'MQTT_WEBHOOK_SECRET',
            'EMAIL_HOST_USER', 'WEBAUTHN_RP_ID', 'SUPABASE_URI']   # chỉ báo "đã cấu hình hay chưa", không lộ giá trị


def _iso(v):
    return v.isoformat() if v else None


def _int(v, d, lo=1, hi=500):
    try:
        return max(lo, min(hi, int(v)))
    except (TypeError, ValueError):
        return d


def _guard(view):
    def wrapper(request, *a, **kw):
        _require_demo_logs(request)
        return view(request, *a, **kw)
    wrapper.__name__ = view.__name__
    return require_GET(wrapper)


def _channel(a):
    ua = (a.user_agent or '').lower()
    if a.kind in ('STATUS', 'NFC') or a.reader_id:
        return 'thiết bị'
    if any(x in ua for x in ('okhttp', 'dart', 'android', 'cfnetwork')):
        return 'app'
    return 'web' if ua else 'hệ thống'


@_guard
def overview_api(request):
    now = timezone.now()
    t0 = time.perf_counter()
    with connection.cursor() as c:
        c.execute('SELECT 1')
    latency = round((time.perf_counter() - t0) * 1000, 1)
    d24 = now - timedelta(hours=24)

    latest = {}
    for s in (ActivityLog.objects.filter(kind='STATUS').order_by('device_id', '-recorded_at')
              .distinct('device_id') if connection.vendor == 'postgresql' else []):
        latest[s.device_id] = s
    devices = []
    for d in Device.objects.select_related('owner').order_by('name'):
        s = latest.get(d.id)
        if s is None and connection.vendor != 'postgresql':
            s = (ActivityLog.objects.filter(kind='STATUS', device=d).order_by('-recorded_at').first())
        age = (now - d.last_seen_at).total_seconds() if d.last_seen_at else None
        devices.append({
            'id': str(d.id), 'name': d.name, 'code': d.device_code, 'mode': d.device_mode, 'status': d.status,
            'owner': d.owner.username if d.owner else None, 'battery': d.battery_level,
            'fw': d.firmware_version, 'mac': d.mac_address, 'location': d.location,
            'lock': s.lock_state if s else None, 'tamper': bool(s and s.tamper_detected),
            'temp': str(s.temperature) if s and s.temperature is not None else None,
            'signal': s.signal_strength if s else None, 'last_seen': _iso(d.last_seen_at),
            'stale': age is None or age > services.OFFLINE_AFTER_SECONDS,
            'radio': [n for n, f in (('BLE', d.bluetooth_enabled), ('WiFi', d.wifi_enabled),
                                      ('NFC', d.nfc_enabled)) if f],
        })

    kinds = dict(ActivityLog.objects.values_list('kind').annotate(n=Count('id')))
    kinds24 = dict(ActivityLog.objects.filter(created_at__gte=d24).values_list('kind').annotate(n=Count('id')))
    fail24 = dict(ActivityLog.objects.filter(created_at__gte=d24, success=False)
                  .values_list('kind').annotate(n=Count('id')))
    hourly = {}
    for r in (ActivityLog.objects.filter(created_at__gte=d24).annotate(h=TruncHour('created_at'))
              .values('h', 'kind').annotate(n=Count('id'))):
        hourly.setdefault(r['kind'], {})[r['h']] = r['n']
    hour0 = now.replace(minute=0, second=0, microsecond=0)
    hours = [hour0 - timedelta(hours=i) for i in range(23, -1, -1)]
    series = {k: [v.get(h, 0) for h in hours] for k, v in hourly.items()}

    users = {
        'total': User.objects.count(), 'active': User.objects.filter(is_active=True).count(),
        'admin': User.objects.filter(is_admin=True).count(),
        'two_fa': User.objects.filter(two_fa_enabled=True).count(),
        'unverified': User.objects.filter(email_verified=False).count(),
        'locked': User.objects.filter(login_locked_until__gt=now).count(),
        'sessions_active': MobileSession.objects.filter(revoked_at__isnull=True, expires_at__gt=now).count(),
    }
    return JsonResponse({
        'server_time': now.isoformat(),
        'db': {'vendor': connection.vendor, 'name': connection.settings_dict.get('NAME') and
               os.path.basename(str(connection.settings_dict['NAME'])), 'latency_ms': latency,
               'tables': len([m for m in apps.get_models() if not m._meta.proxy])},
        'config': {k: bool(os.environ.get(k)) for k in ENV_KEYS},
        'devices': devices, 'users': users,
        'commands': dict(DeviceCommand.objects.values_list('status').annotate(n=Count('id'))),
        'commands24': DeviceCommand.objects.filter(created_at__gte=d24).count(),
        'kinds': kinds, 'kinds24': kinds24, 'fail24': fail24,
        'hours': [h.strftime('%H:00') for h in hours], 'series': series,
    })


@_guard
def events_api(request):
    g = request.GET
    qs = ActivityLog.objects.select_related('device', 'actor_user', 'target_user', 'user')
    if g.get('kind') in ('AUDIT', 'NFC', 'ACCESS', 'STATUS'):
        qs = qs.filter(kind=g['kind'])
    if g.get('severity'):
        qs = qs.filter(severity=g['severity'])
    if g.get('ok') in ('0', '1'):
        qs = qs.filter(success=g['ok'] == '1')
    if g.get('device'):
        qs = qs.filter(device_id=g['device'])
    if g.get('method'):
        qs = qs.filter(method=g['method'])
    if g.get('hours'):
        qs = qs.filter(created_at__gte=timezone.now() - timedelta(hours=_int(g['hours'], 24, 1, 24 * 365)))
    if g.get('q'):
        q = g['q'].strip()[:80]
        qs = qs.filter(Q(action__icontains=q) | Q(username_attempt__icontains=q) | Q(reason__icontains=q)
                       | Q(event_type__icontains=q) | Q(ip_address__startswith=q) | Q(device__name__icontains=q)
                       | Q(actor_user__username__icontains=q) | Q(target_user__username__icontains=q)
                       | Q(user__username__icontains=q))
    total = qs.count()
    size, page = _int(g.get('size'), 50, 10, 200), _int(g.get('page'), 1, 1, 100000)
    rows = []
    for a in qs.order_by('-created_at')[(page - 1) * size: page * size]:
        who = a.actor_user or a.user or a.target_user
        detail = a.metadata or a.raw_payload
        rows.append({
            'id': str(a.id), 'time': _iso(a.created_at), 'kind': a.kind, 'ok': a.success, 'sev': a.severity,
            'who': who.username if who else (a.username_attempt or None),
            'device': a.device.name if a.device else None, 'ip': a.ip_address, 'channel': _channel(a),
            'what': a.action or a.event_type or a.method or a.lock_state or '',
            'reason': a.reason, 'ua': (a.user_agent or '')[:160], 'detail': detail,
        })
    return JsonResponse({'total': total, 'page': page, 'size': size, 'rows': rows})


# ------------------------------------------------------------------------------------ trình duyệt database
def _models():
    return {m._meta.db_table: m for m in apps.get_models() if not m._meta.proxy}


def _cell(name, v):
    if v is None:
        return None
    if SECRET_RE.search(name):
        return '‹đã che›'
    if isinstance(v, (bytes, memoryview)):
        return '‹binary›'
    if hasattr(v, 'isoformat'):
        return v.isoformat()
    return v if isinstance(v, (int, float, bool, dict, list)) else str(v)[:500]


@_guard
def db_tables_api(request):
    out = []
    for t, m in sorted(_models().items()):
        out.append({'table': t, 'model': m._meta.label, 'rows': m._base_manager.count(),
                    'cols': len(m._meta.concrete_fields)})
    return JsonResponse({'tables': out})


OPS = {'eq': 'exact', 'contains': 'icontains', 'gt': 'gt', 'lt': 'lt', 'starts': 'istartswith'}


@_guard
def db_rows_api(request):
    g = request.GET
    m = _models().get(g.get('table'))
    if not m:
        return JsonResponse({'error': 'Bảng không tồn tại'}, status=404)
    fields = {f.attname: f for f in m._meta.concrete_fields}
    cols = list(fields)
    qs = m._base_manager.all()
    errors = []
    for spec in g.getlist('f')[:8]:                       # f=cột:phép:giá trị
        col, _, rest = spec.partition(':')
        op, _, val = rest.partition(':')
        f = fields.get(col)
        if not f or SECRET_RE.search(col):
            errors.append(f'Bỏ qua bộ lọc {col}')
            continue
        try:
            if op == 'null':
                qs = qs.filter(**{f.name + '__isnull': True})
            elif op == 'notnull':
                qs = qs.filter(**{f.name + '__isnull': False})
            elif op in OPS:
                qs = qs.filter(**{f'{f.name}__{OPS[op]}': val})
        except Exception:
            errors.append(f'Giá trị không hợp lệ cho {col}')
    q = (g.get('q') or '').strip()[:80]
    if q:
        text = [f.name for f in m._meta.concrete_fields if f.get_internal_type() in ('CharField', 'TextField', 'EmailField')
                and not SECRET_RE.search(f.name)]
        cond = Q()
        for n in text:
            cond |= Q(**{n + '__icontains': q})
        qs = qs.filter(cond) if text else qs.none()
    order = g.get('order') or ''
    desc = order.startswith('-')
    if order.lstrip('-') in fields:
        qs = qs.order_by(('-' if desc else '') + fields[order.lstrip('-')].name)
    else:
        qs = qs.order_by(m._meta.pk.name)
    total = qs.count()
    size, page = _int(g.get('size'), 50, 10, 200), _int(g.get('page'), 1, 1, 1000000)
    try:
        data = list(qs.values_list(*cols)[(page - 1) * size: page * size])
    except Exception as e:
        return JsonResponse({'error': str(e)[:200]}, status=400)
    return JsonResponse({
        'table': g['table'], 'columns': [{'name': c, 'type': fields[c].get_internal_type(),
                                          'secret': bool(SECRET_RE.search(c))} for c in cols],
        'rows': [[_cell(c, v) for c, v in zip(cols, r)] for r in data],
        'total': total, 'page': page, 'size': size, 'warnings': errors})


# ------------------------------------------------------------------------------------ API / MQTT / phiên
def _walk(patterns, prefix=''):
    for p in patterns:
        if isinstance(p, URLResolver):
            yield from _walk(p.url_patterns, prefix + str(p.pattern))
        elif isinstance(p, URLPattern):
            cb = p.callback
            wrapped = getattr(cb, '__wrapped__', cb)
            doc = (wrapped.__doc__ or '').strip().split('\n')[0][:140]
            yield '/' + prefix + str(p.pattern), p.name or '', getattr(wrapped, '__module__', ''), doc


@_guard
def api_api(request):
    """Danh mục endpoint /api/** lấy từ URL resolver (luôn khớp code thật) + health."""
    groups = {}
    for path, name, mod, doc in _walk(get_resolver().url_patterns):
        if not path.startswith('/api/'):
            continue
        seg = path.split('/')[2] if path.count('/') > 2 else 'khác'
        groups.setdefault(seg, []).append({'path': path.replace('^', '').replace('$', ''), 'name': name,
                                           'module': mod.replace('smartlock.api.', ''), 'doc': doc})
    kinds = {'app': 'App + Web (Bearer / cookie + CSRF)', 'device': 'Thiết bị (X-Device-Code + Secret)',
             'webhooks': 'Broker MQTT gọi vào', 'system': 'Công khai (health, config)'}
    since = timezone.now() - timedelta(hours=24)
    health = None
    try:
        t0 = time.perf_counter()
        with connection.cursor() as c:
            c.execute('SELECT 1')
        health = {'status': 'up', 'ms': round((time.perf_counter() - t0) * 1000, 1)}
    except Exception as e:
        health = {'status': 'down', 'error': str(e)[:120]}
    top = (ActivityLog.objects.filter(kind='AUDIT', created_at__gte=since).values('action')
           .annotate(n=Count('id'), bad=Count('id', filter=Q(success=False))).order_by('-n')[:15])
    return JsonResponse({'groups': [{'key': k, 'label': kinds.get(k, k), 'routes': sorted(v, key=lambda r: r['path'])}
                                    for k, v in sorted(groups.items())],
                         'health': health, 'top_actions_24h': list(top)})


@_guard
def channels_api(request):
    """Lệnh MQTT/điều khiển, vòng ping hai chiều và phiên đăng nhập app."""
    now = timezone.now()
    since = now - timedelta(hours=24)
    cmds = DeviceCommand.objects.filter(created_at__gte=since)
    by = [{'type': r['command_type'], 'status': r['status'], 'n': r['n']}
          for r in cmds.values('command_type', 'status').annotate(n=Count('id'))]
    lat = (DeviceCommand.objects.filter(acknowledged_at__isnull=False, created_at__gte=since)
           .annotate(d=F('acknowledged_at') - F('created_at')).aggregate(a=Avg('d'))['a'])
    recent = [{'time': _iso(c.created_at), 'device': c.device.name, 'type': c.command_type, 'status': c.status,
               'by': c.issued_by.username, 'ack': _iso(c.acknowledged_at), 'expires': _iso(c.expires_at),
               'payload': c.payload}
              for c in DeviceCommand.objects.select_related('device', 'issued_by').order_by('-created_at')[:60]]
    sessions = [{'user': s.user.username, 'platform': s.platform, 'app': s.app_version, 'device_name': s.device_name,
                 'ip': s.ip_address, 'push': bool(s.fcm_token) and s.push_enabled, 'last_used': _iso(s.last_used_at),
                 'expires': _iso(s.expires_at), 'revoked': bool(s.revoked_at)}
                for s in MobileSession.objects.select_related('user').order_by('-last_used_at')[:60]]
    return JsonResponse({
        'mqtt': {'host_set': bool(os.environ.get('MQTT_HOST')), 'webhook_secret_set': bool(os.environ.get('MQTT_WEBHOOK_SECRET')),
                 'topic_prefix': os.environ.get('MQTT_TOPIC_PREFIX') or None},
        'fcm_set': bool(os.environ.get('FIREBASE_CREDENTIALS_JSON') or os.environ.get('GOOGLE_APPLICATION_CREDENTIALS')),
        'offline_after_s': services.OFFLINE_AFTER_SECONDS,
        'ack_latency_s': round(lat.total_seconds(), 2) if lat else None,
        'by': by, 'recent': recent, 'sessions': sessions})


# ------------------------------------------------------------------------------------ chức năng quản trị (chỉ đọc)
# Dùng lại serializer của manage_sys nên không bao giờ lộ mật khẩu / hash PIN / UID thẻ / embedding / secret.


# ====================== API log demo (chuyển từ views.py sang đây: view không còn xử lý dữ liệu) ======================
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