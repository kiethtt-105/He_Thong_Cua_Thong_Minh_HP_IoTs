"""Lịch sử ra vào + nhật ký hệ thống (audit)."""
from smartlock import services
from smartlock.api.common import api, iso, ok, paginate, uuid_or_404
from smartlock.models import AccessEvent

from ..serializers import event_json


@api('GET', auth='any')
def access_history(request):
    user = request.user
    devices = services.devices_with_permission(user, 'view_history')
    qs = AccessEvent.objects.filter(device__in=devices).select_related('device', 'user').order_by('-created_at')
    dev = request.GET.get('device')
    if dev:
        qs = qs.filter(device_id=uuid_or_404(dev))
    method = request.GET.get('method')
    if method in dict(AccessEvent.METHOD_CHOICES):
        qs = qs.filter(method=method)
    if request.GET.get('success') in ('0', '1'):
        qs = qs.filter(success=request.GET['success'] == '1')
    return ok(paginate(request, qs, event_json))


@api('GET', auth='any')
def audit_logs(request):
    qs = services.visible_logs(request.user).select_related('device').order_by('-created_at')
    dev = request.GET.get('device')
    if dev:
        qs = qs.filter(device_id=uuid_or_404(dev))
    return ok(paginate(request, qs, lambda l: {
        'id': str(l.id), 'action': l.action, 'success': l.success, 'severity': l.severity,
        'device_id': str(l.device_id) if l.device_id else None, 'device': l.device.name if l.device_id else None,
        'ip_address': l.ip_address, 'created_at': iso(l.created_at)}))
