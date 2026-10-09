"""Lưu cấu hình + hàng đợi sự kiện ra file (giống NVS/flash của ESP32). Ghi nguyên tử để mất điện không hỏng file."""
import json
import os
import threading

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
STATE_DIR = os.path.join(BASE, 'state')
CONFIG_PATH = os.path.join(STATE_DIR, 'config.json')
QUEUE_PATH = os.path.join(STATE_DIR, 'queue.json')
FACE_PATH = os.path.join(STATE_DIR, 'face.json')
_mtx = threading.Lock()

DEFAULT_HW = {
    'firmware': '1.0.0',
    'mac': '',
    'auto_lock_seconds': 5,        # tự khoá lại sau khi mở (khi cửa đã đóng)
    'door_left_open_seconds': 60,  # cửa mở quá lâu -> DOOR_LEFT_OPEN
    'battery_drain_minutes': 5,    # cứ N phút tụt 1% pin (0 = không tụt)
    'servo_seconds': 0.6,          # thời gian chốt chạy
    'jam_chance': 0.0,             # 0..1 xác suất kẹt chốt (để thử trạng thái jammed)
    'auto_ota': False,
}


def load(path, default):
    try:
        with open(path, 'r', encoding='utf-8') as f:
            return json.load(f)
    except (OSError, ValueError):
        return default


def save(path, data):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = path + '.tmp'
    with _mtx:
        with open(tmp, 'w', encoding='utf-8') as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
        os.replace(tmp, path)


def load_config():
    cfg = load(CONFIG_PATH, {})
    hw = dict(DEFAULT_HW)
    hw.update(cfg.get('hardware') or {})
    cfg['hardware'] = hw
    return cfg


def save_config(cfg):
    save(CONFIG_PATH, cfg)


def clear_config():
    for p in (CONFIG_PATH, QUEUE_PATH):
        try:
            os.remove(p)
        except OSError:
            pass
