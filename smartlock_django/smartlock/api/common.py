# smartlock/api/common.py
"""Helper dùng chung cho API user: phân trang, tra cứu thiết bị + kiểm tra quyền, response chứa bí mật."""
from django.db.models import CharField, OuterRef, Q, Subquery, Value
from django.db.models.functions import Coalesce
from rest_framework.exceptions import NotFound, PermissionDenied
from rest_framework.pagination import PageNumberPagination
from rest_framework.response import Response

from ..models import AuditLog, DeviceStatusLog, Permission, ShareAccessCode
import secrets

from ..utils import DEFAULT_PERMISSIONS, SmartlockUtils as U


class StandardPagination(PageNumberPagination):
    page_size = 20
    page_size_query_param = 'page_size'
    max_page_size = 100


def paginate(request, queryset, serializer_cls, **context):
    """Trả Response dạng {count, next, previous, results}."""
    paginator = StandardPagination()
    page = paginator.paginate_queryset(queryset, request)
    data = serializer_cls(page, many=True, context={'request': request, **context}).data
    return paginator.get_paginated_response(data)


def secret_response(data, status=200):
    """Response chứa bí mật hiển thị 1 lần (PIN, share code, provisioning secret...): cấm cache."""
    resp = Response(data, status=status)
    resp['Cache-Control'] = 'no-store'
    return resp


# ------------------------------------------------------------------ thiết bị
def with_lock_state(queryset):
    """Gắn lock_state (trạng thái khoá mới nhất từ DeviceStatusLog) bằng subquery - không N+1."""
    latest = (DeviceStatusLog.objects.filter(device=OuterRef('pk'))
              .order_by('-recorded_at').values('lock_state')[:1])
    return queryset.annotate(
        lock_state=Coalesce(Subquery(latest, output_field=CharField()), Value('unknown'),
                            output_field=CharField()))


def get_accessible_device(user, device_id):
    """Thiết bị user là chủ hoặc đang được chia sẻ còn hiệu lực. Không thấy -> 404."""
    device = with_lock_state(U.accessible_devices(user)).filter(pk=device_id).first()
    if not device:
        raise NotFound('Không tìm thấy thiết bị.')
    return device


def get_owned_device(user, device_id):
    device = get_accessible_device(user, device_id)
    if device.owner_id != user.id:
        raise PermissionDenied('Chỉ chủ thiết bị mới được thực hiện thao tác này.')
    return device


def require_permission(request, device, code, audit_action=None):
    if not U.has_permission(request.user, device, code):
        if audit_action:
            U.audit(request, audit_action, device=device, success=False, severity='warning')
        raise PermissionDenied('Bạn không có quyền thực hiện thao tác này trên thiết bị.')


# ------------------------------------------------------------------ quyền / mã
def ensure_default_permissions():
    """Tạo các quyền mặc định còn thiếu (khác SmartlockUtils.ensure_default_permissions:
    hàm đó chỉ chạy khi bảng Permission rỗng, nên nếu sau này thêm quyền mới sẽ không được tạo)."""
    existing = set(Permission.objects.values_list('code', flat=True))
    for code, name, desc, sensitive in DEFAULT_PERMISSIONS:
        if code not in existing:
            Permission.objects.get_or_create(
                code=code, defaults={'name': name, 'description': desc, 'is_sensitive': sensitive})


def resolve_permissions(codes):
    """Danh sách mã quyền -> list Permission. Mã không tồn tại -> ValidationError (không âm thầm bỏ qua)."""
    from rest_framework.exceptions import ValidationError
    ensure_default_permissions()
    codes = set(codes or [])
    perms = list(Permission.objects.filter(code__in=codes))
    unknown = codes - {p.code for p in perms}
    if unknown:
        raise ValidationError({'permissions': f'Quyền không hợp lệ: {", ".join(sorted(unknown))}'})
    return perms


def unique_share_plain():
    """Mã 6 số không trùng mã nào đang còn hạn."""
    for _ in range(20):
        plain = f'{secrets.randbelow(10 ** 6):06d}'
        if not ShareAccessCode.is_code_taken(plain):
            return plain
    return None


def visible_logs(user):
    """Log user được xem: mình làm, mình là đối tượng, hoặc xảy ra trên thiết bị của mình."""
    return AuditLog.objects.filter(Q(actor_user=user) | Q(target_user=user) | Q(device__owner=user))