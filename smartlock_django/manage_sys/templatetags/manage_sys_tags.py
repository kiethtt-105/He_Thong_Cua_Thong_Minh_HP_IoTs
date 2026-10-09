# manage_sys/templatetags/manage_sys_tags.py

from django import template

register = template.Library()

_VI = {
    'online': 'Trực tuyến', 'offline': 'Ngoại tuyến', 'maintenance': 'Bảo trì',
    'provisioning': 'Chờ cấu hình', 'revoked': 'Đã gỡ chủ',
    'physical': 'Thiết bị thật', 'simulated': 'Giả lập',
    'info': 'Thông tin', 'warning': 'Cảnh báo', 'critical': 'Nghiêm trọng',
    'danger': 'Nguy hiểm',
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
