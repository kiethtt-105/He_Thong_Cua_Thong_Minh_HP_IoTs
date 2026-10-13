# smartlock/views.py

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
from django.core.cache import cache
from django.db import connection
from django.db.models import Avg, Count, F, Max, OuterRef, Q, Subquery
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
    ctx = {**(context or {}), 'page': page}
    u = getattr(request, 'user', None)
    if u is not None and u.is_authenticated:
        ctx.update(me_avatar=u.avatar, me_initials=u.initials, me_name=u.full_name or u.username)
    return render(request, 'account/app.html', ctx)


def login_view(request):
    if request.user.is_authenticated:
        return redirect('smartlock:dashboard')
    return _render(request, 'login', {'next': request.GET.get('next') or ''})


def register(request):
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
    return _render(request, 'logout')


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


def _require_demo_logs(request):
    if not getattr(dj_settings, 'DEMO_LOGS_ENABLED', False):
        raise Http404()
    if dj_settings.DEBUG and getattr(dj_settings, 'DEMO_LOGS_PUBLIC', False):
        return
    user = getattr(request, 'user', None)
    if not (user and user.is_authenticated and _is_admin(user)):
        raise Http404()


def public_system_logs(request):
    _require_demo_logs(request)
    return render(request, 'public/system_logs.html', {})


SECRET_RE = re.compile(r'(hash|secret|password|token|embedding|public_key|fcm|pepper|key_enc|encrypted)', re.I)
ENV_KEYS = ['DJANGO_SECRET_KEY', 'FERNET_KEY', 'SHARE_CODE_PEPPER', 'MQTT_HOST', 'MQTT_WEBHOOK_SECRET',
            'EMAIL_HOST_USER', 'WEBAUTHN_RP_ID', 'SUPABASE_URI']


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
    for spec in g.getlist('f')[:8]:
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


def _bucketed_counts(queryset, dt_field, minutes=20):
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
    return AuditLog.objects.filter(action__in=_LOGIN_OK_ACTIONS + _LOGIN_FAIL_ACTIONS)


# ======================================================================
#  API còn thiếu cho trang system_logs.html (chỉ đọc)
# ======================================================================
def _brief(u):
    """Thông tin rút gọn của người dùng cho cột avatar/email trên giao diện."""
    if not u:
        return None
    return {'id': str(u.pk), 'email': u.email, 'username': u.username, 'full_name': u.full_name,
            'initials': u.initials, 'avatar': u.avatar}


def _role(u):
    return 'superuser' if u.is_superuser else 'admin' if u.is_admin else 'user'


def _page(g, default=25):
    return _int(g.get('size'), default, 10, 200), _int(g.get('page'), 1, 1, 1000000)


@_guard
def users_api(request):
    g = request.GET
    now = timezone.now()
    qs = User.objects.annotate(device_count=Count('device', distinct=True))
    st = g.get('status')
    if st == 'active':
        qs = qs.filter(is_active=True)
    elif st == 'inactive':
        qs = qs.filter(is_active=False)
    elif st == 'unverified':
        qs = qs.filter(email_verified=False)
    elif st == 'locked':
        qs = qs.filter(login_locked_until__gt=now)
    elif st == 'admin':
        qs = qs.filter(Q(is_admin=True) | Q(is_superuser=True))
    elif st == '2fa':
        qs = qs.filter(two_fa_enabled=True)
    q = (g.get('q') or '').strip()[:80]
    if q:
        qs = qs.filter(Q(email__icontains=q) | Q(username__icontains=q) | Q(full_name__icontains=q)
                       | Q(phone__icontains=q))
    total = qs.count()
    size, page = _page(g)
    rows = []
    for u in qs.order_by('-created_at')[(page - 1) * size: page * size]:
        rows.append({
            **_brief(u), 'phone': u.phone, 'role': _role(u), 'is_active': u.is_active,
            'email_verified': u.email_verified, 'two_fa_enabled': u.two_fa_enabled,
            'is_locked': bool(u.login_locked_until and u.login_locked_until > now),
            'login_locked_until': _iso(u.login_locked_until),
            'login_failed_attempts': u.login_failed_attempts,
            'login_last_failed_ip': u.login_last_failed_ip,
            'device_count': u.device_count, 'last_login': _iso(u.last_login),
            'created_at': _iso(u.created_at), 'updated_at': _iso(u.updated_at),
        })
    return JsonResponse({'total': total, 'page': page, 'size': size, 'rows': rows})


@_guard
def logins_api(request):
    g = request.GET
    qs = _login_attempts().select_related('actor_user', 'target_user')
    if g.get('status') == 'ok':
        qs = qs.filter(action__in=_LOGIN_OK_ACTIONS)
    elif g.get('status') == 'fail':
        qs = qs.filter(action__in=_LOGIN_FAIL_ACTIONS)
    q = (g.get('q') or '').strip()[:80]
    if q:
        qs = qs.filter(Q(username_attempt__icontains=q) | Q(ip_address__startswith=q)
                       | Q(actor_user__email__icontains=q) | Q(target_user__email__icontains=q)
                       | Q(action__icontains=q))
    total = qs.count()
    size, page = _page(g)
    rows = []
    for a in qs.order_by('-created_at')[(page - 1) * size: page * size]:
        who = a.target_user or a.actor_user
        rows.append({
            'id': str(a.id), 'created_at': _iso(a.created_at),
            'identifier': a.username_attempt or (who.email if who else None),
            'user': _brief(who), 'ip_address': a.ip_address,
            'is_manage_portal': bool(who and who.is_admin and a.action in _LOGIN_OK_ACTIONS),
            'success': a.action in _LOGIN_OK_ACTIONS, 'action': a.action,
            'user_agent': (a.user_agent or '')[:200], 'reason': a.reason,
        })
    return JsonResponse({'total': total, 'page': page, 'size': size, 'rows': rows})


@_guard
def announcements_api(request):
    g = request.GET
    qs = Announcement.objects.select_related('created_by')
    if g.get('status') == 'active':
        qs = qs.filter(is_active=True)
    elif g.get('status') == 'inactive':
        qs = qs.filter(is_active=False)
    q = (g.get('q') or '').strip()[:80]
    if q:
        qs = qs.filter(Q(title__icontains=q) | Q(body__icontains=q))
    total = qs.count()
    size, page = _page(g)
    rows = [{'id': str(a.id), 'title': a.title, 'body': a.body, 'level': a.level, 'is_active': a.is_active,
             'created_by': _brief(a.created_by), 'created_at': _iso(a.created_at)}
            for a in qs.order_by('-created_at')[(page - 1) * size: page * size]]
    return JsonResponse({'total': total, 'page': page, 'size': size, 'rows': rows})


@_guard
def admin_settings_api(request):
    from .models import SystemSettings, default_lockout_stage_minutes
    s = SystemSettings.objects.select_related('updated_by').filter(pk=1).first()
    cfg = {
        'registration_enabled': s.registration_enabled if s else True,
        'verification_token_expiry_minutes': s.verification_token_expiry_minutes if s else 30,
        'share_code_expiry_minutes': s.share_code_expiry_minutes if s else 15,
        'login_lockout_stage_minutes': (s.login_lockout_stage_minutes if s else default_lockout_stage_minutes()),
        'session_timeout_hours': s.session_timeout_hours if s else 24,
        'updated_at': _iso(s.updated_at) if s else None,
        'updated_by': _brief(s.updated_by) if s else None,
    }
    sup = User.objects.filter(is_superuser=True).count()
    adm = User.objects.filter(is_admin=True, is_superuser=False).count()
    admins = [{'email': u.email, 'username': u.username, 'role': _role(u), 'last_login': _iso(u.last_login)}
              for u in User.objects.filter(Q(is_admin=True) | Q(is_superuser=True)).order_by('email')]
    full = getattr(dj_settings, 'ADMIN_FULL_POWER', None)
    if full is None:
        full = os.environ.get('ADMIN_FULL_POWER', '').lower() in ('1', 'true', 'yes')
    return JsonResponse({
        'settings': cfg,
        'roles': {'superuser': sup, 'admin': adm, 'user': User.objects.count() - sup - adm},
        'admin_full_power': bool(full),
        'session_seconds': getattr(dj_settings, 'SESSION_COOKIE_AGE', 1209600),
        'admins': admins,
    })


@_guard
def device_detail_api(request, device_id):
    d = Device.objects.select_related('owner').filter(pk=device_id).first()
    if not d:
        return JsonResponse({'error': 'Thiết bị không tồn tại'}, status=404)
    device = {f.attname: _cell(f.name, getattr(d, f.attname)) for f in Device._meta.concrete_fields}
    device['owner'] = _brief(d.owner)
    status = [{'time': _iso(s.recorded_at), 'battery': s.battery_level, 'lock': s.lock_state,
               'tamper': s.tamper_detected, 'temp': str(s.temperature) if s.temperature is not None else None,
               'signal': s.signal_strength}
              for s in DeviceStatusLog.objects.filter(device=d).order_by('-recorded_at')[:20]]
    commands = [{'time': _iso(c.created_at), 'type': c.command_type, 'status': c.status,
                 'by': c.issued_by.username, 'ack': _iso(c.acknowledged_at)}
                for c in DeviceCommand.objects.filter(device=d).select_related('issued_by').order_by('-created_at')[:10]]
    events = [{'time': _iso(a.created_at), 'kind': a.kind, 'what': a.action or a.event_type or a.method,
               'ok': a.success, 'sev': a.severity, 'ip': a.ip_address}
              for a in ActivityLog.objects.filter(device=d).exclude(kind='STATUS').order_by('-created_at')[:20]]
    return JsonResponse({'device': device, 'status_logs': status, 'commands': commands, 'events': events})


def _ago(dt, now):
    if not dt:
        return 'chưa từng'
    n = int((now - dt).total_seconds())
    return (f'{n} giây' if n < 60 else f'{n // 60} phút' if n < 3600
            else f'{n // 3600} giờ' if n < 86400 else f'{n // 86400} ngày')


@_guard
def alerts_api(request):
    """Cảnh báo chi tiết: danh sách hợp nhất theo mức độ + xu hướng 24 giờ + bảng phân tích nguyên nhân."""
    now = timezone.now()
    d24 = now - timedelta(hours=24)
    A = []

    def add(sev, cat, title, detail, time=None, ref=None):
        A.append({'sev': sev, 'cat': cat, 'title': title, 'detail': detail, 'time': _iso(time), 'ref': ref or {}})

    # ---- thiết bị ----
    devices = []
    for d in Device.objects.select_related('owner').exclude(status__in=('provisioning', 'revoked')).order_by('name')[:300]:
        st = DeviceStatusLog.objects.filter(device=d).order_by('-recorded_at').first()
        tam = (DeviceStatusLog.objects.filter(device=d, tamper_detected=True).order_by('-recorded_at').first()
               if st and st.tamper_detected else None)
        age = (now - d.last_seen_at).total_seconds() if d.last_seen_at else None
        issues = []
        owner = d.owner.username if d.owner else 'chưa có chủ'
        if st and st.tamper_detected:
            issues.append('tamper')
            add('critical', 'device', f'Thiết bị bị tháo: {d.name}',
                f'Cảm biến chống tháo đang kích hoạt (ghi nhận lúc {fmt_time(tam.recorded_at) if tam else "?"}). '
                f'Chủ khóa: {owner}. Pin {d.battery_level}%.', tam.recorded_at if tam else None,
                {'device': str(d.id), 'code': d.device_code})
        if age is None or age > services.OFFLINE_AFTER_SECONDS:
            issues.append('stale')
            long_ = age is None or age > 86400
            add('warning' if long_ else 'info', 'device', f'Mất tín hiệu: {d.name}',
                f'Lần cuối thấy thiết bị: {_ago(d.last_seen_at, now)} trước (ngưỡng offline {services.OFFLINE_AFTER_SECONDS}s). '
                f'Trạng thái: {d.status}; pin {d.battery_level}%; chủ khóa: {owner}.', d.last_seen_at,
                {'device': str(d.id), 'code': d.device_code})
        if d.battery_level < 20:
            issues.append('low_battery')
            add('critical' if d.battery_level < 10 else 'warning', 'device', f'Pin yếu: {d.name}',
                f'Pin còn {d.battery_level}%. Cần thay pin/sạc trước khi thiết bị tắt.', None,
                {'device': str(d.id), 'code': d.device_code})
        if issues:
            devices.append({'id': str(d.id), 'name': d.name, 'code': d.device_code, 'issues': issues,
                            'battery': d.battery_level, 'fw': d.firmware_version, 'mode': d.device_mode,
                            'status': d.status, 'lock': st.lock_state if st else None,
                            'temp': str(st.temperature) if st and st.temperature is not None else None,
                            'signal': st.signal_strength if st else None, 'owner': d.owner.username if d.owner else None,
                            'last_seen': _iso(d.last_seen_at), 'offline_for': _ago(d.last_seen_at, now)})

    # ---- đăng nhập ----
    fails = _login_attempts().filter(action__in=_LOGIN_FAIL_ACTIONS, created_at__gte=d24)
    suspect_ips = [{'ip': r['ip_address'], 'n': r['n'], 'accounts': r['accounts'], 'last': _iso(r['last'])}
                   for r in fails.exclude(ip_address__isnull=True).values('ip_address')
                   .annotate(n=Count('id'), accounts=Count('username_attempt', distinct=True), last=Max('created_at'))
                   .filter(n__gte=3).order_by('-n')[:15]]
    for r in suspect_ips:
        add('critical' if r['n'] >= 10 or r['accounts'] >= 3 else 'warning', 'login',
            f'IP đăng nhập sai nhiều lần: {r["ip"]}',
            f'{r["n"]} lần sai trong 24 giờ, thử {r["accounts"]} tài khoản khác nhau'
            + (' (dấu hiệu dò tài khoản).' if r['accounts'] >= 3 else '.'), None, {'ip': r['ip']})
    top_accounts = [{'account': r['username_attempt'], 'n': r['n'], 'ips': r['ips'], 'last': _iso(r['last'])}
                    for r in fails.exclude(username_attempt__isnull=True).exclude(username_attempt='')
                    .values('username_attempt').annotate(n=Count('id'), ips=Count('ip_address', distinct=True),
                                                         last=Max('created_at'))
                    .filter(n__gte=2).order_by('-n')[:10]]
    locked = [{**_brief(u), 'until': _iso(u.login_locked_until), 'attempts': u.login_failed_attempts,
               'stage': u.login_lock_stage, 'ip': u.login_last_failed_ip, 'last_failed': _iso(u.login_last_failed_at)}
              for u in User.objects.filter(login_locked_until__gt=now).order_by('-login_locked_until')[:30]]
    for u in locked:
        add('warning', 'account', f'Tài khoản bị khóa đăng nhập: {u["email"]}',
            f'Sai {u["attempts"]} lần (mức khóa {u["stage"]}), IP gần nhất {u["ip"] or "—"}; khóa đến {u["until"]}.',
            None, {'user': u['id']})
    for u in User.objects.filter(Q(is_admin=True) | Q(is_superuser=True), two_fa_enabled=False, is_active=True)[:20]:
        add('warning', 'account', f'Quản trị viên chưa bật 2FA: {u.email}',
            'Tài khoản có quyền quản trị nhưng chưa bật xác thực hai lớp.', None, {'user': str(u.pk)})

    # ---- sự kiện nghiêm trọng, ra vào, NFC ----
    crit_qs = ActivityLog.objects.filter(severity='critical', created_at__gte=d24)
    critical = []
    for a in crit_qs.select_related('device', 'actor_user', 'user', 'target_user').order_by('-created_at')[:25]:
        who = a.actor_user or a.user or a.target_user
        row = {'time': _iso(a.created_at), 'kind': a.kind, 'what': a.action or a.event_type or a.method or '',
               'who': who.username if who else a.username_attempt, 'device': a.device.name if a.device else None,
               'ip': a.ip_address, 'reason': a.reason}
        critical.append(row)
        add('critical', 'event', f'Sự kiện nghiêm trọng: {row["what"] or a.kind}',
            f'Loại {a.kind}; người: {row["who"] or "—"}; thiết bị: {row["device"] or "—"}; IP: {row["ip"] or "—"}'
            + (f'; lý do: {a.reason}' if a.reason else '.'), a.created_at, {'id': str(a.id)})
    access_fail = [{'device': r['device__name'], 'method': r['method'], 'reason': r['reason'], 'n': r['n']}
                   for r in ActivityLog.objects.filter(kind='ACCESS', success=False, created_at__gte=d24)
                   .values('device__name', 'method', 'reason').annotate(n=Count('id')).order_by('-n')[:15]]
    for r in access_fail:
        if r['n'] >= 3:
            add('warning', 'access', f'Mở khóa thất bại nhiều lần: {r["device"] or "?"}',
                f'{r["n"]} lần qua kênh {r["method"] or "?"} trong 24 giờ; lý do: {r["reason"] or "không rõ"}.', None,
                {'device_name': r['device']})
    nfc_fail = [{'device': r['device__name'], 'event': r['event_type'], 'n': r['n']}
                for r in NfcLog.objects.filter(success=False, created_at__gte=d24)
                .values('device__name', 'event_type').annotate(n=Count('id')).order_by('-n')[:15]]
    for r in nfc_fail:
        if r['n'] >= 5:
            add('warning', 'nfc', f'NFC thất bại nhiều: {r["device"] or "?"}',
                f'{r["n"]} lần "{r["event"] or "không rõ"}" trong 24 giờ (có thể thẻ lạ hoặc đầu đọc lỗi).', None,
                {'device_name': r['device']})

    # ---- lệnh điều khiển ----
    cmds = [{'time': _iso(c.created_at), 'device': c.device.name, 'type': c.command_type, 'status': c.status,
             'by': c.issued_by.username, 'expires': _iso(c.expires_at)}
            for c in DeviceCommand.objects.filter(created_at__gte=d24, status__in=('failed', 'expired'))
            .select_related('device', 'issued_by').order_by('-created_at')[:25]]
    for c in cmds[:10]:
        add('warning', 'command', f'Lệnh {c["type"]} {c["status"]}: {c["device"]}',
            f'Người gửi {c["by"]}; hết hạn {c["expires"]}.', None, {})

    # ---- cấu hình thiếu ----
    for k in ENV_KEYS:
        if not os.environ.get(k):
            add('warning', 'config', f'Thiếu biến cấu hình: {k}', 'Biến môi trường chưa được đặt.', None, {})

    # ---- xu hướng 24 giờ ----
    hour0 = now.replace(minute=0, second=0, microsecond=0)
    hours = [hour0 - timedelta(hours=i) for i in range(23, -1, -1)]

    def series(qs):
        m = {r['h']: r['n'] for r in qs.annotate(h=TruncHour('created_at')).values('h').annotate(n=Count('id'))}
        return [m.get(h, 0) for h in hours]

    trend = {'hours': [h.strftime('%H:00') for h in hours],
             'login_fail': series(fails),
             'access_fail': series(ActivityLog.objects.filter(kind='ACCESS', success=False, created_at__gte=d24)),
             'nfc_fail': series(NfcLog.objects.filter(success=False, created_at__gte=d24)),
             'critical': series(crit_qs)}

    order = {'critical': 0, 'warning': 1, 'info': 2}
    A.sort(key=lambda x: (order[x['sev']], x['time'] is None, '' if not x['time'] else
                          ''.join(chr(255 - ord(ch)) for ch in x['time'])))
    for i, x in enumerate(A):
        x['id'] = i
    by_sev = {k: sum(1 for x in A if x['sev'] == k) for k in order}
    by_cat = {}
    for x in A:
        by_cat[x['cat']] = by_cat.get(x['cat'], 0) + 1
    return JsonResponse({
        'server_time': now.isoformat(), 'by_sev': by_sev, 'by_cat': by_cat, 'alerts': A, 'trend': trend,
        'devices': devices, 'suspect_ips': suspect_ips, 'top_accounts': top_accounts, 'locked_users': locked,
        'access_fail': access_fail, 'nfc_fail': nfc_fail, 'critical': critical, 'commands': cmds})


def fmt_time(dt):
    return timezone.localtime(dt).strftime('%d/%m/%Y %H:%M:%S') if dt else '?'