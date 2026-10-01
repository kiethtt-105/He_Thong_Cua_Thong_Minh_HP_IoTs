# smartlock/api/permissions.py
"""Phân quyền theo thiết bị cho API (dùng lại services.accessible_devices / has_permission của web)."""
from rest_framework.exceptions import NotFound, PermissionDenied
from rest_framework.permissions import IsAuthenticated

from smartlock import services
from smartlock.models import Device, DeviceAccess, Permission


class IsMobileUser(IsAuthenticated):
    """Đã đăng nhập bằng Bearer, tài khoản còn hoạt động và KHÔNG phải tài khoản quản trị
    (quản trị chỉ dùng cổng /manage-sys/, giống luật ở login_view của web)."""
    def has_permission(self, request, view):
        user = request.user
        return bool(super().has_permission(request, view) and user.is_active and not services.is_admin(user))


def get_device(user, device_id, *, owner_only=False, permission=None) -> Device:
    """Lấy thiết bị user được phép thấy. Không thấy -> 404 (không tiết lộ thiết bị có tồn tại hay không).
    owner_only: chỉ chủ; permission: mã quyền cần có (chủ luôn có đủ)."""
    dev_id = services.parse_uuid(device_id)
    qs = Device.objects.filter(owner=user) if owner_only else services.accessible_devices(user)
    device = qs.filter(id=dev_id).first() if dev_id else None
    if not device:
        raise NotFound()
    if permission and not services.has_permission(user, device, permission):
        raise PermissionDenied('Bạn không có quyền thực hiện thao tác này trên thiết bị.')
    return device


def my_permission_codes(user, device) -> list:
    """Danh sách mã quyền của user trên thiết bị (chủ: toàn bộ quyền)."""
    if device.owner_id == user.id:
        return sorted(Permission.objects.values_list('code', flat=True))
    from django.db.models import Q
    from django.utils import timezone
    now = timezone.now()
    codes = set()
    for access in (DeviceAccess.objects.filter(device=device, user=user, is_active=True, accepted=True,
                                               valid_from__lte=now)
                   .filter(Q(expires_at__isnull=True) | Q(expires_at__gt=now))
                   .prefetch_related('permissions')):
        codes.update(p.code for p in access.permissions.all())
    return sorted(codes)
