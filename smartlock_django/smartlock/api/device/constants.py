"""Hằng số của API khoá: chu kỳ, giới hạn thử sai, trạng thái khoá, loại sự kiện cảnh báo."""
import re


HEARTBEAT_SECONDS = 60


COMMAND_POLL_SECONDS = 3


AUTH_FAIL_LIMIT = 10


AUTH_FAIL_WINDOW = 600


LOG_MIN_INTERVAL = 300             # chỉ ghi DeviceStatusLog khi trạng thái đổi hoặc >= 5 phút (đỡ phình DB)


LOW_BATTERY = 15


MAC_RE = re.compile(r'^([0-9A-F]{2}:){5}[0-9A-F]{2}$')


LOCK_STATES = ('locked', 'unlocked', 'jammed', 'unknown')


# sự kiện không phải mở cửa -> (mức độ, tiêu đề, báo cho ai: 'watchers' | 'owner' | None, giãn cách thông báo giây)
DEVICE_EVENTS = {
    'BOOT':           ('info',     'Khoá vừa khởi động lại',          None,       0),
    'TAMPER':         ('critical', 'Cảnh báo: khoá bị tác động mạnh', 'watchers', 300),
    'FORCED_OPEN':    ('critical', 'Cảnh báo: cửa bị mở cưỡng bức',   'watchers', 300),
    'DOOR_LEFT_OPEN': ('warning',  'Cửa đang mở quá lâu',             'watchers', 600),
    'LOW_BATTERY':    ('warning',  'Pin khoá sắp hết',                'owner',    3600),
}
