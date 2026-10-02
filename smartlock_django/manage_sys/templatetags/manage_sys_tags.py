# manage_sys/templatetags/manage_sys_tags.py
"""Filter dùng trong template quản trị: {{ value|vi }} (nhãn tiếng Việt) và {{ value|badge }} (màu Bootstrap).
Giá trị lạ -> vi trả lại nguyên văn, badge trả 'secondary' (không bao giờ lỗi template)."""
from django import template

register = template.Library()

_VI = {
    # Device.status
    'online': 'Trực tuyến', 'offline': 'Ngoại tuyến', 'maintenance': 'Bảo trì',
    'provisioning': 'Chờ cấu hình', 'revoked': 'Đã gỡ chủ',
    # device_mode / reader_mode
    'physical': 'Thiết bị thật', 'simulated': 'Giả lập',
    # AuditLog.severity
    'info': 'Thông tin', 'warning': 'Cảnh báo', 'critical': 'Nghiêm trọng',
    # Announcement.level
    'danger': 'Nguy hiểm',
    # AccessEvent.method
    'RFID': 'Thẻ RFID', 'PIN': 'Mã PIN', 'FACE': 'Khuôn mặt', 'BLE': 'Bluetooth', 'NFC_PHONE': 'NFC điện thoại',
}

_BADGE = {
    'online': 'success', 'offline': 'secondary', 'maintenance': 'warning',
    'provisioning': 'info', 'revoked': 'dark',
    'info': 'info', 'warning': 'warning', 'critical': 'danger', 'danger': 'danger',
}


@register.filter
def vi(value):
    return _VI.get(value, value)


@register.filter
def badge(value):
    return _BADGE.get(value, 'secondary')