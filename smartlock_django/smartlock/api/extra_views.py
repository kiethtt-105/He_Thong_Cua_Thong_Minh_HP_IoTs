# smartlock/api/extra_views.py
"""Endpoint bổ sung cho app: cấu hình công khai và gói dữ liệu đồng bộ 1 lần."""
from django.conf import settings
from django.db.models import Q
from django.utils import timezone
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework.views import APIView

from ..models import Announcement, DeviceAccess, Notification
from ..utils import SmartlockUtils as U
from . import serializers as S
from .common import secret_response, visible_logs, with_lock_state
from .mobile_auth import ACCESS_TTL


class AppConfigView(APIView):
    """Công khai (không cần đăng nhập): app gọi khi khởi động để biết có được đăng ký không,
    phiên bản tối thiểu (ép cập nhật) và lệch giờ máy so với server (quan trọng cho mã TOTP)."""
    authentication_classes = []
    permission_classes = [AllowAny]

    def get(self, request):
        return Response({
            'api_version': 'v1',
            'registration_enabled': U.settings().registration_enabled,
            'min_app_version': getattr(settings, 'MOBILE_MIN_APP_VERSION', '1.0.0'),
            'latest_app_version': getattr(settings, 'MOBILE_LATEST_APP_VERSION', '1.0.0'),
            'access_token_ttl': ACCESS_TTL,
            'server_time': timezone.now().isoformat(),
        })


class SyncView(APIView):
    """GET /sync/ - mọi thứ màn hình chính cần trong 1 request (thiết bị + trạng thái khoá, thông báo mới,
    log gần đây, quyền đã cấp, quyền được cấp, thông báo hệ thống). Không cấp thêm quyền xem dữ liệu nào
    ngoài các endpoint khác."""

    def get(self, request):
        user = request.user
        ctx = {'request': request}
        devices = list(with_lock_state(U.accessible_devices(user)).order_by('name'))
        owned_ids = [d.id for d in devices if d.owner_id == user.id]
        now = timezone.now()

        granted = (DeviceAccess.objects.filter(device_id__in=owned_ids, is_active=True)
                   .select_related('user').prefetch_related('permissions')) if owned_ids else []
        mine = (DeviceAccess.objects.filter(user=user, is_active=True)
                .filter(Q(expires_at__isnull=True) | Q(expires_at__gt=now))
                .select_related('device').prefetch_related('permissions'))

        return secret_response({
            'generated_at': now.isoformat(),
            'unread_count': Notification.objects.filter(user=user, is_read=False).count(),
            'devices': S.DeviceSerializer(devices, many=True, context=ctx).data,
            'notifications': S.NotificationSerializer(
                Notification.objects.filter(user=user).select_related('device').order_by('-created_at')[:20],
                many=True).data,
            'recent_logs': S.AuditLogSerializer(
                visible_logs(user).select_related('device', 'actor_user', 'target_user')
                .order_by('-created_at')[:20], many=True).data,
            'accesses_granted': S.DeviceAccessSerializer(granted, many=True).data,
            'my_accesses': S.MyAccessSerializer(mine, many=True).data,
            'announcements': S.AnnouncementSerializer(
                Announcement.objects.filter(is_active=True).order_by('-created_at')[:5], many=True).data,
        })