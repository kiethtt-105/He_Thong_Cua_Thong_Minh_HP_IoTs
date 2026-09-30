# smartlock/api/common.py
"""Tiện ích dùng chung cho API v1: định dạng lỗi, phân trang, tra cứu thiết bị theo quyền."""
from django.utils import timezone
from rest_framework import status
from rest_framework.exceptions import NotFound, PermissionDenied
from rest_framework.pagination import PageNumberPagination
from rest_framework.response import Response
from rest_framework.views import exception_handler

from ..utils import SmartlockUtils as U


# ------------------------------------------------------------------ lỗi thống nhất
# Mọi lỗi trả về dạng: {"error": {"code": "...", "message": "...", "details": {...}|null}}
def api_exception_handler(exc, context):
    response = exception_handler(exc, context)
    if response is None:
        return None
    data = response.data
    detail = getattr(exc, 'detail', None)
    code = getattr(detail, 'code', None) or getattr(exc, 'default_code', 'error')
    if isinstance(data, dict) and set(data.keys()) == {'detail'}:
        message, details = str(data['detail']), None
    else:
        message, details = 'Dữ liệu không hợp lệ.', data
        code = 'validation_error'
    response.data = {'error': {'code': str(code).upper(), 'message': message, 'details': details}}
    return response


def fail(code: str, message: str, http_status=status.HTTP_400_BAD_REQUEST, **details) -> Response:
    return Response({'error': {'code': code, 'message': message, 'details': details or None}},
                    status=http_status)


# ------------------------------------------------------------------ phân trang
class StandardPagination(PageNumberPagination):
    page_size = 20
    page_size_query_param = 'page_size'
    max_page_size = 100


# ------------------------------------------------------------------ thiết bị & quyền
def get_device(request, device_id, permission: str = None, owner_only: bool = False):
    """Lấy thiết bị user được truy cập. 404 nếu không thấy (không lộ sự tồn tại của
    thiết bị người khác), 403 nếu thiếu quyền `permission` hoặc không phải chủ (owner_only)."""
    device = U.accessible_devices(request.user).filter(id=device_id).first()
    if device is None:
        raise NotFound('Không tìm thấy thiết bị.')
    if owner_only and device.owner_id != request.user.id:
        raise PermissionDenied('Chỉ chủ thiết bị mới được thực hiện thao tác này.')
    if permission and not U.has_permission(request.user, device, permission):
        raise PermissionDenied('Bạn không có quyền thực hiện thao tác này.')
    return device


def device_context(user, devices):
    """Gom dữ liệu phụ (trạng thái khoá mới nhất, quyền của user) cho DeviceSerializer - tránh N+1."""
    from ..models import DeviceAccess, DeviceStatusLog
    from django.db.models import Q
    devices = list(devices)
    ids = [d.id for d in devices]
    last_logs = {}
    if ids:
        qs = DeviceStatusLog.objects.filter(device_id__in=ids).order_by('-recorded_at')[:max(200, 50 * len(ids))]
        for log in qs:
            last_logs.setdefault(log.device_id, log)

    now = timezone.now()
    perm_map = {}
    shared = (DeviceAccess.objects.filter(user=user, device_id__in=ids, is_active=True, accepted=True,
                                          valid_from__lte=now)
              .filter(Q(expires_at__isnull=True) | Q(expires_at__gt=now))
              .prefetch_related('permissions'))
    for a in shared:
        perm_map.setdefault(a.device_id, set()).update(p.code for p in a.permissions.all())
    return {'user': user, 'last_logs': last_logs, 'perm_map': perm_map}
