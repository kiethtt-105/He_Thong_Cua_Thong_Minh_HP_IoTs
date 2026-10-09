# smartlock_django/links.py
"""LINKS SERVER - NGUỒN DUY NHẤT cho mọi địa chỉ của hệ thống. Mọi nơi trong project PHẢI lấy link từ đây.

Có HAI loại link:

1) SERVER_URL  - nơi server đang chạy (CSRF, ALLOWED_HOSTS, passkey, MQTT host mặc định).
       SERVER_URL=http://localhost:8000                 # chạy local
       SERVER_URL=https://xxxx-8000.asse.devtunnels.ms  # chạy qua devtunnel
       SERVER_URL=https://ten-mien.vercel.app           # production

2) PUBLIC_URL  - link GỬI RA NGOÀI cho người dùng (email xác thực, đặt lại mật khẩu, chia sẻ khoá, thông báo...).
       LUÔN là link Vercel, kể cả khi đang chạy local/devtunnel. Mặc định: DEFAULT_PUBLIC_URL bên dưới.
       Ghi đè (nếu đổi tên miền): PUBLIC_URL=https://ten-mien.vercel.app
       Bị CHẶN nếu trỏ về localhost / IP nội bộ / devtunnel / ngrok... (báo lỗi cấu hình ngay khi khởi động).

   => Mọi code tạo link trong email PHẢI dùng links.public_absolute('/verify-email/<token>/'),
      KHÔNG dùng request.build_absolute_uri(), links.absolute() hay SERVER_URL.

LƯU Ý khi chạy local nhưng link mail trỏ Vercel: local và Vercel phải CÙNG DJANGO_SECRET_KEY + FERNET_KEY
(và cùng database Supabase), nếu không token reset/xác thực tạo ở local sẽ không hợp lệ trên Vercel.

MQTT_BROKER_HOST=...   MQTT_BROKER_PORT=1883   MQTT_BROKER_USE_TLS=false   # (cổng 8883 tự bật TLS)

Thứ tự tìm SERVER_URL: SERVER_URL -> Vercel (VERCEL_PROJECT_PRODUCTION_URL / VERCEL_URL) -> DEBUG=True thì http://localhost:8000
-> còn lại báo lỗi cấu hình (không đoán link từ request nữa: tránh link sai trong email, passkey, CSRF...).

Module này chỉ dùng os.environ (không import django.conf.settings) nên settings.py import được ngay.
Phải import SAU khi đã load_dotenv() (settings.py làm sẵn).
"""
import ipaddress
import os
from urllib.parse import urlsplit

from django.core.exceptions import ImproperlyConfigured

_LOCAL_HOSTS = ('localhost', '127.0.0.1', '0.0.0.0', '10.0.2.2')
# Tunnel / dịch vụ dev: không bao giờ được xuất hiện trong link gửi cho người dùng.
_DEV_HOST_SUFFIXES = ('.devtunnels.ms', '.ngrok-free.app', '.ngrok.app', '.ngrok.io', '.ngrok.dev',
                      '.trycloudflare.com', '.loca.lt', '.localtunnel.me', '.local', '.localhost', '.internal')
_TRUE = ('1', 'true', 'yes', 'on')

# Link mặc định cho mọi email / thông báo gửi ra ngoài.
DEFAULT_PUBLIC_URL = 'https://he-thong-cua-thong-minh-hp-iots.vercel.app'


def _env(name, default=''):
    return (os.environ.get(name) or default).strip()


def _flag(name, default=False):
    value = os.environ.get(name)
    return default if value is None else value.strip().lower() in _TRUE


def _is_dev_host(host):
    """localhost / IP nội bộ / devtunnel / ngrok... -> True."""
    host = (host or '').lower()
    if host in _LOCAL_HOSTS or any(host.endswith(sfx) for sfx in _DEV_HOST_SUFFIXES):
        return True
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return False
    return ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_unspecified


def _normalize(raw):
    """'host:8000' / 'http://host:8000/abc/' -> 'http(s)://host:8000' (bỏ path, bỏ dấu / cuối)."""
    raw = raw.strip().rstrip('/')
    if '://' not in raw:
        host = raw.split('/')[0].split(':')[0].lower()
        raw = ('http://' if _is_dev_host(host) else 'https://') + raw
    parts = urlsplit(raw)
    if parts.scheme not in ('http', 'https') or not parts.hostname:
        raise ImproperlyConfigured(f'SERVER_URL không hợp lệ: {raw!r} (ví dụ http://localhost:8000)')
    return f'{parts.scheme}://{parts.netloc}'


def _resolve_server_url():
    raw = _env('SERVER_URL')
    if not raw:
        vercel = _env('VERCEL_PROJECT_PRODUCTION_URL') or _env('VERCEL_URL')
        raw = vercel
    if not raw:
        if _flag('DEBUG'):
            raw = 'http://localhost:8000'
        else:
            raise ImproperlyConfigured('Thiếu SERVER_URL trong .env (link gốc của server, vd https://ten-mien.vercel.app).')
    return _normalize(raw)


def _resolve_public_url():
    """Link gửi ra ngoài: mặc định Vercel; từ chối localhost/devtunnel/ngrok và bắt buộc https."""
    url = _normalize(_env('PUBLIC_URL') or DEFAULT_PUBLIC_URL)
    parts = urlsplit(url)
    if _is_dev_host(parts.hostname):
        raise ImproperlyConfigured(
            f'PUBLIC_URL={url!r} là địa chỉ local/devtunnel. Link trong email phải là link Vercel '
            f'(vd {DEFAULT_PUBLIC_URL}).')
    if parts.scheme != 'https':
        raise ImproperlyConfigured(f'PUBLIC_URL={url!r} phải dùng https.')
    return url


# ============================== SERVER (web + API + email + passkey) ==============================
SERVER_URL = _resolve_server_url()
_parts = urlsplit(SERVER_URL)
SERVER_SCHEME = _parts.scheme
SERVER_HOST = _parts.hostname                 # chỉ tên miền/IP, không port
SERVER_NETLOC = _parts.netloc                 # có port nếu có
SERVER_IS_SECURE = SERVER_SCHEME == 'https'

API_URL = f'{SERVER_URL}/api'
API_APP_URL = f'{API_URL}/app'                # người dùng (app + web)
API_DEVICE_URL = f'{API_URL}/device'          # firmware khoá
API_WEBHOOK_URL = f'{API_URL}/webhooks'       # broker MQTT gọi vào (auth/acl)
API_SYSTEM_URL = f'{API_URL}/system'          # health, config công khai

# ============================== PUBLIC (link trong email / thông báo) ==============================
PUBLIC_URL = _resolve_public_url()

# ============================== MQTT BROKER ==============================
# Chấp nhận cả MQTT_BROKER_* lẫn MQTT_HOST/MQTT_PORT. Không đặt host -> dùng cùng host với SERVER_URL.
MQTT_HOST = _env('MQTT_BROKER_HOST') or _env('MQTT_HOST') or SERVER_HOST
try:
    MQTT_PORT = int(_env('MQTT_BROKER_PORT') or _env('MQTT_PORT') or '1883')
except ValueError:
    MQTT_PORT = 1883
MQTT_USE_TLS = _flag('MQTT_BROKER_USE_TLS') or MQTT_PORT == 8883

# ============================== PASSKEY (WebAuthn) ==============================
# Origin phải TRÙNG địa chỉ đang mở trên trình duyệt: mở bằng link khác SERVER_URL thì passkey sẽ không dùng được.
WEBAUTHN_RP_ID = _env('WEBAUTHN_RP_ID') or SERVER_HOST
WEBAUTHN_ORIGIN = SERVER_URL


# ============================== HÀM TIỆN ÍCH ==============================
def absolute(path='/'):
    """Link tuyệt đối trên server ĐANG CHẠY: absolute('/x/') -> 'https://.../x/'. KHÔNG dùng cho email."""
    path = path or '/'
    return SERVER_URL + (path if path.startswith('/') else '/' + path)


def public_absolute(path='/'):
    """Link tuyệt đối để GỬI RA NGOÀI (email, thông báo): luôn là link Vercel.
    public_absolute('/verify-email/abc/') -> 'https://he-thong-cua-thong-minh-hp-iots.vercel.app/verify-email/abc/'"""
    path = path or '/'
    return PUBLIC_URL + (path if path.startswith('/') else '/' + path)


def _loopback_aliases():
    """Chạy local: localhost và 127.0.0.1 là CÙNG một máy -> chấp nhận cả hai khi SERVER_URL trỏ về máy này."""
    return ['localhost', '127.0.0.1'] if SERVER_HOST in ('localhost', '127.0.0.1') else []


def allowed_hosts():
    hosts = [SERVER_HOST] + _loopback_aliases()
    if _flag('DEBUG'):
        hosts += ['localhost', '127.0.0.1']
    hosts += [h.strip() for h in _env('ALLOWED_HOSTS').split(',') if h.strip()]   # bổ sung thêm nếu thật sự cần
    return list(dict.fromkeys(hosts))


def csrf_trusted_origins():
    origins = [SERVER_URL]
    if _loopback_aliases():
        port = f':{_parts.port}' if _parts.port else ''
        origins += [f'{SERVER_SCHEME}://{h}{port}' for h in _loopback_aliases()]
    origins += [o.strip() for o in _env('CSRF_TRUSTED_ORIGINS').split(',') if o.strip()]
    return list(dict.fromkeys(origins))
