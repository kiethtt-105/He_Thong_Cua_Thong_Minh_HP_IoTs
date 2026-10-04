"""Hằng số dùng chung cho web + app + API."""
COMMAND_TTL_SECONDS = 120
# lệnh -> quyền cần có (None = chỉ chủ khoá)
ALLOWED_COMMANDS = {'LOCK': 'LOCK', 'UNLOCK': 'UNLOCK', 'REBOOT': None}
COMMAND_LABELS = {'LOCK': 'Khóa', 'UNLOCK': 'Mở khóa', 'REBOOT': 'Khởi động lại'}

EVENTS_MAX_BACKLOG_SECONDS = 300     # tab mở lại sau lâu: không dội cả đống popup cũ
EVENTS_BATCH = 10

RESET_NEUTRAL_MSG = ('Nếu email này đã đăng ký, chúng tôi đã gửi link đặt lại mật khẩu. '
                     'Vui lòng kiểm tra hộp thư (kể cả mục Spam).')
