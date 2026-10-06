"""Lịch sử / nhật ký / thông báo - /api/app/history/, /audit/, /notifications/, /events/, /announcements/"""
from datetime import timedelta

from django.utils import timezone

from .serializers import announcement_json, event_json, notification_json
from smartlock import services
from smartlock.api.common import api, ApiError, iso, ok, paginate, parse_iso, read_json, uuid_or_404
from smartlock.constants import EVENTS_BATCH, EVENTS_MAX_BACKLOG_SECONDS
from smartlock.models import AccessEvent, Announcement, Notification


# ======================================================================
# history.py - Lịch sử ra vào + nhật ký hệ thống (audit).
# ======================================================================

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


# ======================================================================
# notifications.py - Thông báo + poll sự kiện khi app đang mở.
# ======================================================================

@api('GET', 'DELETE', auth='any')
def notifications(request):
    user = request.user
    if request.method == 'DELETE':
        deleted, _ = Notification.objects.filter(user=user, is_read=True).delete()
        return ok({'deleted': deleted})
    qs = Notification.objects.filter(user=user).select_related('device').order_by('-created_at')
    if request.GET.get('unread') == '1':
        qs = qs.filter(is_read=False)
    data = paginate(request, qs, notification_json)
    data['unread_count'] = Notification.objects.filter(user=user, is_read=False).count()
    return ok(data)


@api('POST', auth='any')
def notifications_read(request):
    data = read_json(request)
    qs = Notification.objects.filter(user=request.user, is_read=False)
    if data.get('all') is True:
        pass
    else:
        ids = [services.parse_uuid(i) for i in (data.get('ids') or []) if services.parse_uuid(i)]
        if not ids:
            raise ApiError('MISSING_FIELD', 'Cần "ids" (mảng UUID) hoặc "all": true.', 400)
        qs = qs.filter(id__in=ids[:200])
    n = qs.update(is_read=True, read_at=timezone.now())
    return ok({'updated': n, 'unread_count': Notification.objects.filter(user=request.user, is_read=False).count()})


@api('DELETE', auth='any')
def notification_delete(request, notification_id):
    n, _ = Notification.objects.filter(user=request.user, pk=uuid_or_404(notification_id)).delete()
    if not n:
        raise ApiError('NOT_FOUND', 'Không tìm thấy thông báo.', 404)
    return ok()


@api('GET', auth='any')
def events_poll(request):
    """Poll nhẹ khi app đang mở (khi nền thì dùng push FCM). ?cursor=<iso> (lần đầu bỏ trống)."""
    user, now = request.user, timezone.now()
    since = parse_iso(request.GET.get('cursor'), 'cursor')
    unread = Notification.objects.filter(user=user, is_read=False).count()
    if since is None:
        return ok({'events': [], 'cursor': iso(now), 'unread_count': unread})
    since = max(since, now - timedelta(seconds=EVENTS_MAX_BACKLOG_SECONDS))
    rows = list(Notification.objects.filter(user=user, created_at__gt=since).order_by('created_at')[:EVENTS_BATCH])
    cursor = rows[-1].created_at if rows else since
    return ok({'events': [notification_json(n) for n in rows], 'cursor': iso(cursor), 'unread_count': unread})


# ======================================================================
# announcements.py - GET /announcements/ - thông báo hệ thống đang bật (quản trị đăng ở manage_sys).
# ======================================================================

@api('GET', auth='any')
def announcements(request):
    qs = Announcement.objects.filter(is_active=True).order_by('-created_at')
    return ok(paginate(request, qs, announcement_json))
