# manage_sys/api/dashboard.py
from datetime import timedelta

from django.db.models import Count, Q
from django.db.models.functions import TruncDate
from django.utils import timezone

from smartlock.models import AuditLog, Device, User

from .. import views as legacy
from . import serializers as S
from .common import ok, route


def dashboard(request):
    now = timezone.now()
    day_ago = now - timedelta(hours=24)
    u = User.objects.aggregate(
        total=Count('id'), active=Count('id', filter=Q(is_active=True)),
        unverified=Count('id', filter=Q(is_active=False, email_verified=False)),
        locked=Count('id', filter=Q(login_locked_until__gt=now)))
    d = Device.objects.aggregate(
        total=Count('id'), online=Count('id', filter=Q(status='online')),
        maintenance=Count('id', filter=Q(status='maintenance')))
    a24 = AuditLog.objects.filter(created_at__gte=day_ago).aggregate(
        failed=Count('id', filter=Q(action__in=legacy.LOGIN_FAIL_ACTIONS)),
        critical=Count('id', filter=Q(severity='critical')))
    today = timezone.localdate()
    days = [today - timedelta(days=i) for i in range(6, -1, -1)]
    counts = {r['d']: r['c'] for r in AuditLog.objects.filter(created_at__date__gte=days[0])
              .annotate(d=TruncDate('created_at')).values('d').annotate(c=Count('id'))}
    alerts = (AuditLog.objects.filter(severity__in=['warning', 'critical'])
              .select_related('actor_user', 'target_user', 'device').order_by('-created_at')[:8])
    return ok({
        'stats': {'total_users': u['total'], 'active_users': u['active'], 'unverified_users': u['unverified'],
                  'locked_accounts': u['locked'], 'total_devices': d['total'], 'online_devices': d['online'],
                  'maintenance_devices': d['maintenance'], 'failed_logins_24h': a24['failed'],
                  'critical_24h': a24['critical']},
        'activity_7d': [{'date': x.isoformat(), 'count': counts.get(x, 0)} for x in days],
        'recent_alerts': [S.audit_item(a) for a in alerts],
    })


dashboard_view = route({'GET': dashboard})
