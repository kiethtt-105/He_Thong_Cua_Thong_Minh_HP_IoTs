"""Trang quản trị TOÀN HỆ THỐNG (chỉ xem). Mọi endpoint là GET, không ghi dữ liệu.
Quyền: dùng lại _require_demo_logs (DEMO_LOGS_ENABLED; khi DEBUG=False chỉ admin đăng nhập mới xem được).
Trình duyệt DB đọc được MỌI bảng nhưng che các cột bí mật (hash, secret, token, embedding...)."""
import os
import re
import time
from datetime import timedelta

from django.apps import apps
from django.db import connection
from django.db.models import Avg, Count, F, Q
from django.db.models.functions import TruncHour
from django.http import JsonResponse
from django.urls import URLPattern, URLResolver, get_resolver
from django.utils import timezone
from django.views.decorators.http import require_GET

from django.http import Http404
from django.shortcuts import get_object_or_404

from manage_sys import views as mlegacy

from .models import (AccessEvent, Announcement, AuditLog, CardDeviceAccess, ActivityLog, Device, DeviceAccess,
                     DeviceCommand, DeviceStatusLog, DoorPinCode, FaceProfile, MobileSession, NfcReader, User)
from . import services
from .views import _require_demo_logs

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
def _page(request, qs, ser, default=25):
    size, page = _int(request.GET.get('size'), default, 5, 200), _int(request.GET.get('page'), 1, 1, 100000)
    return JsonResponse({'total': qs.count(), 'page': page, 'size': size,
                         'rows': [ser(o) for o in qs[(page - 1) * size: page * size]]})


@_guard
def users_api(request):
    g, now = request.GET, timezone.now()
    qs = User.objects.annotate(device_count=Count('device', distinct=True)).order_by('-created_at')
    q = (g.get('q') or '').strip()[:80]
    if q:
        qs = qs.filter(Q(email__icontains=q) | Q(username__icontains=q) | Q(full_name__icontains=q) | Q(phone__icontains=q))
    flt = {'active': Q(is_active=True), 'inactive': Q(is_active=False), 'unverified': Q(is_active=False, email_verified=False),
           'locked': Q(login_locked_until__gt=now), 'admin': Q(is_admin=True) | Q(is_staff=True) | Q(is_superuser=True),
           '2fa': Q(two_fa_enabled=True)}
    if g.get('status') in flt:
        qs = qs.filter(flt[g['status']])
    return _page(request, qs, lambda u: S.user_item(u, locked=bool(u.login_locked_until and u.login_locked_until > now)))


@_guard
def logins_api(request):
    g = request.GET
    qs = mlegacy.login_attempts_qs().select_related('actor_user', 'target_user').order_by('-created_at')
    q = (g.get('q') or '').strip()[:80]
    if q:
        qs = qs.filter(Q(username_attempt__icontains=q) | Q(ip_address__icontains=q) | Q(target_user__email__icontains=q)
                       | Q(actor_user__email__icontains=q))
    if g.get('status') in ('ok', 'fail'):
        qs = qs.filter(success=g['status'] == 'ok')
    return _page(request, qs, S.login_attempt_item)


@_guard
def announcements_api(request):
    qs = Announcement.objects.select_related('created_by').order_by('-created_at')
    if request.GET.get('status') in ('active', 'inactive'):
        qs = qs.filter(is_active=request.GET['status'] == 'active')
    return _page(request, qs, S.announcement_item)


@_guard
def admin_settings_api(request):
    st = services.SystemSettings.objects.select_related('updated_by').get_or_create(pk=1)[0]
    return JsonResponse({
        'settings': S.settings_item(st), 'session_seconds': mlegacy.SESSION_SECONDS,
        'admin_full_power': bool(getattr(__import__('django.conf', fromlist=['settings']).settings, 'ADMIN_FULL_POWER', True)),
        'roles': {'superuser': User.objects.filter(is_superuser=True).count(),
                  'admin': User.objects.filter(Q(is_admin=True) | Q(is_staff=True)).count(),
                  'user': User.objects.filter(is_admin=False, is_staff=False, is_superuser=False).count()},
        'admins': [S.user_brief(u) | {'role': S.role_of(u), 'last_login': _iso(u.last_login)}
                   for u in User.objects.filter(Q(is_admin=True) | Q(is_staff=True) | Q(is_superuser=True))[:50]]})


@_guard
def device_api(request, device_id):
    d = get_object_or_404(Device.objects.select_related('owner'), id=device_id)
    last = DeviceStatusLog.objects.filter(device=d).order_by('-recorded_at').first()
    return JsonResponse({
        **S.device_item(d), 'link': {k: (_iso(v) if hasattr(v, 'isoformat') else v)
                                     for k, v in services.link_status(d).items()},
        'last_status': last and {'battery': last.battery_level, 'signal': last.signal_strength, 'lock': last.lock_state,
                                 'tamper': last.tamper_detected, 'at': _iso(last.recorded_at)},
        'commands': [S.command_item(c) for c in DeviceCommand.objects.filter(device=d).select_related('issued_by').order_by('-created_at')[:10]],
        'accesses': [S.access_item(a) for a in DeviceAccess.objects.filter(device=d, is_active=True).select_related('user').prefetch_related('permissions')[:30]],
        'readers': [S.reader_item(r) for r in NfcReader.objects.filter(device=d)],
        'cards': [{'name': c.access_card.name, 'owner': c.access_card.user.email, 'active': c.is_active and c.access_card.is_active}
                  for c in CardDeviceAccess.objects.filter(device=d).select_related('access_card', 'access_card__user')[:50]],
        'pins': [{'label': x.label, 'expires_at': _iso(x.expires_at), 'uses': f'{x.use_count}/{x.max_uses or "∞"}', 'revoked': x.is_revoked}
                 for x in DoorPinCode.objects.filter(device=d).order_by('-created_at')[:30]],
        'faces': [{'name': x.name, 'user': x.user.email, 'active': x.is_active, 'consent': x.consent_confirmed}
                  for x in FaceProfile.objects.filter(device=d).select_related('user')[:30]],
        'access_events': [{'at': _iso(e.created_at), 'method': e.method, 'ok': e.success, 'reason': e.reason,
                           'user': e.user.email if e.user_id else None}
                          for e in AccessEvent.objects.filter(device=d).select_related('user').order_by('-created_at')[:20]],
        'audit': [S.audit_item(a) for a in AuditLog.objects.filter(device=d).select_related('actor_user', 'target_user', 'device').order_by('-created_at')[:10]]})