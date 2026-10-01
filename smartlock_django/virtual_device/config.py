# virtual_device/config.py
"""
Cấu hình chung cho thiết bị ảo. Tất cả đều đọc từ biến môi trường (.env ở thư mục gốc dự án
hoặc virtual_device/.env) và có giá trị mặc định hợp lý.

!!! QUY ƯỚC PAYLOAD MQTT (cần khớp với smartlock/management/commands/mqtt_subscriber.py) !!!
File mqtt_subscriber.py không nằm trong bộ file được gửi nên các tên trường dưới đây được SUY RA từ
services.py (touch_device / dispatch_command / verify_* / record_*_unlock). Nếu subscriber của bạn
đặt tên khác, chỉ cần sửa ở ĐÚNG file này (EVENT_TYPE, ACK_*), không phải đụng vào device.py.
"""
import os
from pathlib import Path

PACKAGE_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = PACKAGE_DIR.parent            # thư mục chứa manage.py
DATA_DIR = PACKAGE_DIR / 'data'              # mỗi profile 1 thư mục: identity.json + state.json


def _load_dotenv():
    try:
        from dotenv import load_dotenv
    except ImportError:
        return
    for p in (PROJECT_ROOT / '.env', PACKAGE_DIR / '.env'):
        if p.exists():
            load_dotenv(p, override=False)


_load_dotenv()


def _env(*names, default=''):
    for n in names:
        v = os.environ.get(n)
        if v not in (None, ''):
            return v
    return default


def _num(cast, *names, default):
    try:
        return cast(_env(*names, default=str(default)))
    except ValueError:
        return default


def _flag(*names, default=False):
    v = _env(*names, default='')
    return default if v == '' else v.strip().lower() in ('1', 'true', 'yes', 'on')


# ---------------------------------------------------------------- MQTT
MQTT_HOST = _env('VDEVICE_MQTT_HOST', 'MQTT_BROKER_HOST', 'MQTT_HOST', default='localhost')
MQTT_PORT = _num(int, 'VDEVICE_MQTT_PORT', 'MQTT_BROKER_PORT', 'MQTT_PORT', default=1883)
MQTT_TLS = _flag('VDEVICE_MQTT_TLS', 'MQTT_BROKER_USE_TLS', default=False)
MQTT_KEEPALIVE = _num(int, 'VDEVICE_MQTT_KEEPALIVE', default=30)
# Mặc định clean_session=True: lệnh UNLOCK "cũ" xếp hàng lúc mất mạng sẽ bị BỎ khi nối lại
# (khoá thật không nên mở cửa theo lệnh đã hết hạn từ lâu). Đặt 0 nếu muốn thử persistent session.
MQTT_CLEAN_SESSION = _flag('VDEVICE_CLEAN_SESSION', default=True)

# ---------------------------------------------------------------- Hành vi thiết bị
STATUS_INTERVAL = _num(int, 'VDEVICE_STATUS_INTERVAL', default=30)       # giây; server coi offline sau 180s
AUTO_LOCK_SECONDS = _num(int, 'VDEVICE_AUTO_LOCK', default=10)           # 0 = không tự khoá lại
BATTERY_DRAIN_EVERY = _num(int, 'VDEVICE_BATTERY_DRAIN_EVERY', default=600)  # giây / 1% pin, 0 = tắt
REBOOT_SECONDS = _num(int, 'VDEVICE_REBOOT_SECONDS', default=3)
OTA_SECONDS = _num(int, 'VDEVICE_OTA_SECONDS', default=6)
DEFAULT_FIRMWARE = _env('VDEVICE_FIRMWARE', default='1.0.0-virtual')
OUTBOX_MAX = 500                                                         # tối đa sự kiện xếp hàng khi offline

# ---------------------------------------------------------------- Topic (khớp services.py + mqtt_acl_webhook)
def topic_cmd(code: str) -> str:
    return f'smartlock/{code}/cmd'


def topic_status(code: str) -> str:
    return f'smartlock/{code}/status'


def topic_ack(code: str) -> str:
    return f'smartlock/{code}/ack'


def topic_event(code: str) -> str:
    return f'smartlock/{code}/event'


# ---------------------------------------------------------------- Tên loại sự kiện gửi lên topic /event
EVENT_TYPE = {
    'rfid': 'rfid',            # {"type": "rfid", "uid": "04A1B2C3"}                  -> services.verify_rfid_tap
    'pin': 'pin',              # {"type": "pin", "pin": "123456"}                      -> services.verify_door_pin
    'face': 'face',            # {"type": "face", "embedding": [...], "snapshot_url"}  -> services.verify_face
    'ble': 'ble',              # {"type": "ble", "ticket", "ok", "reason", "at"}       -> services.record_ble_unlock
    'nfc_phone': 'nfc_phone',  # {"type": "nfc_phone", "ticket", "ok", "reason","at"}  -> services.record_nfc_phone_unlock
}
# Ack gửi lên topic /ack: command_id + token (hash server gửi kèm lệnh) + kết quả.
ACK_OK = 'acknowledged'
ACK_FAIL = 'failed'
