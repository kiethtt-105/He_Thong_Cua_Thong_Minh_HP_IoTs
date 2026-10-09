# smartlock_django/smartlock_django/links.py

import ipaddress
import os
from urllib.parse import urlsplit

from django.core.exceptions import ImproperlyConfigured

_LOCAL_HOSTS = ('localhost', '127.0.0.1', '0.0.0.0', '10.0.2.2')
_DEV_HOST_SUFFIXES = ('.devtunnels.ms', '.ngrok-free.app', '.ngrok.app', '.ngrok.io', '.ngrok.dev',
                      '.trycloudflare.com', '.loca.lt', '.localtunnel.me', '.local', '.localhost', '.internal')
_TRUE = ('1', 'true', 'yes', 'on')

DEFAULT_PUBLIC_URL = 'https://he-thong-cua-thong-minh-hp-iots.vercel.app'


def _env(name, default=''):
    return (os.environ.get(name) or default).strip()


def _flag(name, default=False):
    value = os.environ.get(name)
    return default if value is None else value.strip().lower() in _TRUE


def _is_dev_host(host):
    host = (host or '').lower()
    if host in _LOCAL_HOSTS or any(host.endswith(sfx) for sfx in _DEV_HOST_SUFFIXES):
        return True
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return False
    return ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_unspecified


def _normalize(raw):
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
    url = _normalize(_env('PUBLIC_URL') or DEFAULT_PUBLIC_URL)
    parts = urlsplit(url)
    if _is_dev_host(parts.hostname):
        raise ImproperlyConfigured(
            f'PUBLIC_URL={url!r} là địa chỉ local/devtunnel. Link trong email phải là link Vercel '
            f'(vd {DEFAULT_PUBLIC_URL}).')
    if parts.scheme != 'https':
        raise ImproperlyConfigured(f'PUBLIC_URL={url!r} phải dùng https.')
    return url


SERVER_URL = _resolve_server_url()
_parts = urlsplit(SERVER_URL)
SERVER_SCHEME = _parts.scheme
SERVER_HOST = _parts.hostname
SERVER_NETLOC = _parts.netloc
SERVER_IS_SECURE = SERVER_SCHEME == 'https'

API_URL = f'{SERVER_URL}/api'
API_APP_URL = f'{API_URL}/app'
API_DEVICE_URL = f'{API_URL}/device'
API_WEBHOOK_URL = f'{API_URL}/webhooks'
API_SYSTEM_URL = f'{API_URL}/system'

PUBLIC_URL = _resolve_public_url()

MQTT_HOST = _env('MQTT_BROKER_HOST') or _env('MQTT_HOST') or SERVER_HOST
try:
    MQTT_PORT = int(_env('MQTT_BROKER_PORT') or _env('MQTT_PORT') or '1883')
except ValueError:
    MQTT_PORT = 1883
MQTT_USE_TLS = _flag('MQTT_BROKER_USE_TLS') or MQTT_PORT == 8883

WEBAUTHN_RP_ID = _env('WEBAUTHN_RP_ID') or SERVER_HOST
WEBAUTHN_ORIGIN = SERVER_URL


def absolute(path='/'):
    path = path or '/'
    return SERVER_URL + (path if path.startswith('/') else '/' + path)


def public_absolute(path='/'):
    path = path or '/'
    return PUBLIC_URL + (path if path.startswith('/') else '/' + path)


def _loopback_aliases():
    return ['localhost', '127.0.0.1'] if SERVER_HOST in ('localhost', '127.0.0.1') else []


def allowed_hosts():
    hosts = [SERVER_HOST] + _loopback_aliases()
    if _flag('DEBUG'):
        hosts += ['localhost', '127.0.0.1']
    hosts += [h.strip() for h in _env('ALLOWED_HOSTS').split(',') if h.strip()]
    return list(dict.fromkeys(hosts))


def csrf_trusted_origins():
    origins = [SERVER_URL]
    if _loopback_aliases():
        port = f':{_parts.port}' if _parts.port else ''
        origins += [f'{SERVER_SCHEME}://{h}{port}' for h in _loopback_aliases()]
    origins += [o.strip() for o in _env('CSRF_TRUSTED_ORIGINS').split(',') if o.strip()]
    return list(dict.fromkeys(origins))
