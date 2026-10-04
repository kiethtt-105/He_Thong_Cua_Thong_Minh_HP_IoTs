"""Hàm dùng chung: lấy khoá theo quyền (chủ / quyền được chia sẻ)."""
from smartlock import services
from smartlock.api.common import ApiError, uuid_or_404


def get_device(request, device_id):
    d = (services.accessible_devices(request.user).select_related('owner')
         .filter(pk=uuid_or_404(device_id)).first())
    if not d:
        raise ApiError('DEVICE_NOT_FOUND', 'Không tìm thấy khoá.', 404)
    return d


def need_owner(request, device, action='DEVICE_ACTION'):
    if device.owner_id != request.user.id:
        services.audit(request, f'{action}_DENIED', device=device, success=False, severity='warning')
        raise ApiError('OWNER_ONLY', 'Chỉ chủ khoá mới được thực hiện thao tác này.', 403)


def _need_perm(request, device, code, action='DEVICE_ACTION'):
    if not services.has_permission(request.user, device, code):
        services.audit(request, f'{action}_DENIED', device=device, success=False, severity='warning')
        raise ApiError('FORBIDDEN', 'Bạn không có quyền thực hiện thao tác này.', 403, permission=code)


def managed_device(request, device_id, code):
    """Khoá mà user có quyền `code` (chủ luôn có). 404 nếu không thấy, 403 nếu thiếu quyền."""
    device = get_device(request, device_id)
    _need_perm(request, device, code)
    return device
