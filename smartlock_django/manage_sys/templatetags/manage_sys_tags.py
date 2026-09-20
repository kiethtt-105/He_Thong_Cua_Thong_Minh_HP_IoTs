from django import template

register = template.Library()

_BADGE = {
    # thiết bị
    'online': 'success', 'offline': 'secondary', 'maintenance': 'warning', 'provisioning': 'info',
    # hỗ trợ
    'pending': 'warning', 'approved': 'primary', 'executed': 'success',
    'expired': 'secondary', 'rejected': 'danger', 'cancelled': 'dark',
    # mức độ / cấp độ
    'info': 'info', 'warning': 'warning', 'critical': 'danger', 'danger': 'danger',
}

_VI = {
    'online': 'Trực tuyến', 'offline': 'Ngoại tuyến', 'maintenance': 'Bảo trì', 'provisioning': 'Chờ cấu hình',
    'pending': 'Chờ xử lý', 'approved': 'Đã duyệt', 'executed': 'Đã thực hiện',
    'expired': 'Hết hạn', 'rejected': 'Từ chối', 'cancelled': 'Đã hủy',
    'info': 'Thông tin', 'warning': 'Cảnh báo', 'critical': 'Nghiêm trọng', 'danger': 'Nguy hiểm',
    'physical': 'Thật', 'simulated': 'Mô phỏng',
}


@register.filter
def badge(value):
    """status -> lớp màu Bootstrap (dùng: bg-{{ x|badge }})."""
    return _BADGE.get(str(value), 'secondary')


@register.filter
def vi(value):
    """status -> nhãn tiếng Việt."""
    return _VI.get(str(value), value)
