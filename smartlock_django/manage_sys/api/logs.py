# manage_sys/api/logs.py
from django.db.models import Q
from django.utils.dateparse import parse_datetime, parse_date
from datetime import datetime, time

from django.utils import timezone

from smartlock.models import AuditLog

from .. import views as legacy
from . import serializers as S
from .common import ok, paginate, route


def _dt(value, *, end=False):
    """?from= / ?to= nhận ISO datetime hoặc YYYY-MM-DD (to: hết ngày đó)."""
    if not value:
        return None
    dt = parse_datetime(value)
    if dt is None:
        d = parse_date(value)
        if d is None:
            return None
        dt = datetime.combine(d, time.max if end else time.min)
    return timezone.make_aware(dt) if timezone.is_naive(dt) else dt


def _range(request, qs):
    start, end = _dt(request.GET.get('from')), _dt(request.GET.get('to'), end=True)
    if start:
        qs = qs.filter(created_at__gte=start)
    if end:
        qs = qs.filter(created_at__lte=end)
    return qs


def audit_logs(request):
    qs = AuditLog.objects.select_related('actor_user', 'target_user', 'device').order_by('-created_at')
    q = (request.GET.get('q') or '').strip()
    if q:
        qs = qs.filter(Q(action__icontains=q) | Q(actor_user__email__icontains=q) | Q(target_user__email__icontains=q)
                       | Q(username_attempt__icontains=q) | Q(ip_address__icontains=q))
    status = request.GET.get('status') or ''
    if status in ('ok', 'fail'):
        qs = qs.filter(success=(status == 'ok'))
    severity = request.GET.get('severity') or ''
    if severity in ('info', 'warning', 'critical'):
        qs = qs.filter(severity=severity)
    scope = request.GET.get('scope') or ''
    if scope == 'manage':
        qs = qs.filter(action__startswith='MANAGE_')
    elif scope == 'mail':
        qs = qs.filter(action__startswith='MAIL_')
    if request.GET.get('device'):
        qs = qs.filter(device_id=legacy._parse_uuid(request.GET['device']))
    if request.GET.get('user'):
        uid = legacy._parse_uuid(request.GET['user'])
        qs = qs.filter(Q(actor_user_id=uid) | Q(target_user_id=uid))
    qs = _range(request, qs)
    if not request.GET.get('page'):
        legacy.audit(request, 'MANAGE_VIEW_AUDIT_LOGS', metadata={'q': q[:80], 'status': status, 'severity': severity})
    items, meta = paginate(request, qs, S.audit_item)
    return ok(items, meta=meta)


def login_attempts(request):
    qs = legacy.login_attempts_qs().select_related('actor_user', 'target_user').order_by('-created_at')
    q = (request.GET.get('q') or '').strip()
    if q:
        qs = qs.filter(Q(username_attempt__icontains=q) | Q(ip_address__icontains=q)
                       | Q(target_user__email__icontains=q) | Q(actor_user__email__icontains=q))
    status = request.GET.get('status') or ''
    if status in ('ok', 'fail'):
        qs = qs.filter(success=(status == 'ok'))
    items, meta = paginate(request, _range(request, qs), S.login_attempt_item)
    return ok(items, meta=meta)


audit_logs_view = route({'GET': audit_logs})
login_attempts_view = route({'GET': login_attempts})
