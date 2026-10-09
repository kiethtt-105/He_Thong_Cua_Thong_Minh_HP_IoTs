"""Cấu hình + bộ nhớ của khoá.

  config.json        (thư mục gốc, BẠN sửa tay)  -> toàn bộ thông số khoá + kết nối. Không bao giờ bị khoá tự xoá.
  state/config.json  (khoá tự ghi khi SETUP trên UI) -> chỉ wifi / server / mã / secret; đè lên config.json. Factory reset xoá file này.
  state/runtime.json, queue.json, face.json           -> "flash/NVS" của ESP32 (cache cấu hình server, command_id đã xử lý, hàng đợi offline)

Thứ tự ưu tiên: tham số dòng lệnh  >  biến môi trường (DEVICE_SECRET, DEVICE_CODE, SERVER_URL)  >  state/config.json  >  config.json  >  mặc định.
Ghi nguyên tử để mất điện không hỏng file.
"""
import copy
import json
import os
import threading

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
STATE_DIR = os.path.join(BASE, 'state')
USER_CONFIG_PATH = os.path.join(BASE, 'config.json')           # đổi bằng run.py --config
CONFIG_PATH = os.path.join(STATE_DIR, 'config.json')           # phần ghi đè do SETUP tạo
QUEUE_PATH = os.path.join(STATE_DIR, 'queue.json')
RUNTIME_PATH = os.path.join(STATE_DIR, 'runtime.json')
FACE_PATH = os.path.join(STATE_DIR, 'face.json')
_mtx = threading.Lock()

DEFAULTS = {
    'device_code': '',
    'secret': '',
    'server': {'active': 'tunnel', 'urls': {}},
    'wifi': {'ssid': '', 'password': '', 'source': 'host'},      # host = dùng Wi-Fi THẬT của máy chạy giả lập | simulated = mạng ảo
    'network': {
        'http_timeout_seconds': 10,
        'heartbeat_seconds': None,        # None = theo server (thường 60)
        'poll_seconds': None,             # None = theo server (thường 3)
        'offline_queue_max': 200,
    },
    'mqtt': {
        'enabled': False,
        'url': '',                        # vd wss://<id>-9001.asse.devtunnels.ms  (đè transport/host/port/path/tls)
        'transport': 'websockets',        # websockets (qua dev tunnel) | tcp
        'host': 'localhost', 'port': None, 'path': '/', 'tls': True,
        'tls_insecure': False, 'ca_file': '', 'keepalive': 30,
        'publish_telemetry': False,       # true -> đẩy status/ack/event lên smartlock/<code>/...
        'headers': {},
    },
    'hardware': {
        'firmware': '1.0.0',
        'mac': '',
        'battery': 100,                   # % pin lúc bật nguồn
        'signal': -55,                    # RSSI dBm
        'temperature': 27.0,              # °C
        'auto_lock_seconds': 5,           # tự khoá lại sau khi mở (khi cửa đã đóng)
        'door_left_open_seconds': 60,     # cửa mở quá lâu -> DOOR_LEFT_OPEN
        'battery_drain_minutes': 5,       # cứ N phút tụt 1% pin (0 = không tụt)
        'servo_seconds': 0.6,             # thời gian chốt chạy
        'jam_chance': 0.0,                # 0..1 xác suất kẹt chốt
        'auto_ota': False,
    },
}
DEFAULT_HW = DEFAULTS['hardware']          # tương thích code cũ


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


def _merge(base, over):
    """Gộp đệ quy; khoá bắt đầu bằng '_' (ghi chú) bị bỏ qua."""
    for k, v in (over or {}).items():
        if k.startswith('_'):
            continue
        if isinstance(v, dict) and isinstance(base.get(k), dict):
            _merge(base[k], v)
        else:
            base[k] = copy.deepcopy(v)
    return base


def load_config():
    cfg = copy.deepcopy(DEFAULTS)
    _merge(cfg, load(USER_CONFIG_PATH, {}))
    _merge(cfg, load(CONFIG_PATH, {}))
    for key, env in (('device_code', 'DEVICE_CODE'), ('secret', 'DEVICE_SECRET')):
        if os.environ.get(env):
            cfg[key] = os.environ[env].strip()
    if os.environ.get('SERVER_URL'):
        cfg['server'] = {'active': 'env', 'urls': {'env': os.environ['SERVER_URL'].strip().rstrip('/')}}
    cfg['device_code'] = (cfg.get('device_code') or '').strip().upper()
    cfg['secret'] = (cfg.get('secret') or '').strip()
    s = cfg['server']
    s['urls'] = {k: v.rstrip('/') for k, v in (s.get('urls') or {}).items() if v}
    if s.get('active') not in s['urls'] and s['urls']:
        s['active'] = next(iter(s['urls']))
    return cfg


def save_overrides(patch):
    """Ghi phần SETUP/đổi server vào state/config.json (gộp với phần cũ)."""
    cur = load(CONFIG_PATH, {})
    _merge(cur, patch)
    save(CONFIG_PATH, cur)


def clear_config():
    for p in (CONFIG_PATH, QUEUE_PATH, RUNTIME_PATH):
        try:
            os.remove(p)
        except OSError:
            pass
