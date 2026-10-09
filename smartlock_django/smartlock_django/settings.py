# smartlock_django/smartlock_django/settings.py

import os
from pathlib import Path

from django.core.exceptions import ImproperlyConfigured

BASE_DIR = Path(__file__).resolve().parent.parent

from dotenv import load_dotenv
load_dotenv(BASE_DIR.parent / ".env")
load_dotenv()


from smartlock_django import links


def env_bool(name, default=False):
    value = os.environ.get(name)
    if value is None:
        return default
    return value.strip().lower() in ("1", "true", "yes", "on")


def env_int(name, default):
    try:
        return int(str(os.environ.get(name, default)).strip())
    except (TypeError, ValueError):
        return default


def env_list(name, default=""):
    raw = os.environ.get(name, default)
    return [item.strip() for item in raw.split(",") if item.strip()]


SECRET_KEY = os.environ.get("DJANGO_SECRET_KEY")
if not SECRET_KEY:
    raise ImproperlyConfigured("Thiếu biến môi trường DJANGO_SECRET_KEY")

DEBUG = env_bool("DEBUG", False)

FERNET_KEY = os.environ.get("FERNET_KEY")
OTP_EXPIRY_MINUTES = env_int("OTP_EXPIRY_MINUTES", 5)
OTP_MAX_ATTEMPTS = env_int("OTP_MAX_ATTEMPTS", 5)

WEBAUTHN_RP_ID = links.WEBAUTHN_RP_ID
WEBAUTHN_ORIGIN = links.WEBAUTHN_ORIGIN
WEBAUTHN_RP_NAME = os.environ.get("WEBAUTHN_RP_NAME", "Smart Lock")

MQTT_HOST = links.MQTT_HOST
MQTT_PORT = links.MQTT_PORT
MQTT_TOPIC_PREFIX = os.environ.get("MQTT_TOPIC_PREFIX", "")
MQTT_WEBHOOK_SECRET = os.environ.get("MQTT_WEBHOOK_SECRET") or None
MQTT_TRUSTED_USERNAMES = env_list("MQTT_TRUSTED_USERNAMES", os.environ.get("MQTT_PUBLISHER_USERNAME", ""))

DEMO_LOGS_ENABLED = env_bool("DEMO_LOGS_ENABLED", False)
DEMO_LOGS_PUBLIC = env_bool("DEMO_LOGS_PUBLIC", False)

FACE_MAX_THRESHOLD = float(os.environ.get("FACE_MAX_THRESHOLD", "0.5"))
FACE_MIN_MARGIN = float(os.environ.get("FACE_MIN_MARGIN", "0.04"))
HTTP_ACCESS_PUSH_UNLOCK = env_bool("HTTP_ACCESS_PUSH_UNLOCK", False)

MESSAGE_STORAGE = "django.contrib.messages.storage.session.SessionStorage"


ALLOW_ALL_HOSTS = env_bool("ALLOW_ALL_HOSTS", False)
ALLOWED_HOSTS = links.allowed_hosts()
if ALLOW_ALL_HOSTS:
    ALLOWED_HOSTS = ["*"]


CSRF_TRUSTED_ORIGINS = links.csrf_trusted_origins()


TRUST_PROXY_HEADERS = env_bool("TRUST_PROXY_HEADERS", True)
if TRUST_PROXY_HEADERS:
    SECURE_PROXY_SSL_HEADER = ("HTTP_X_FORWARDED_PROTO", "https")

SECURE_COOKIES = env_bool("SECURE_COOKIES", not DEBUG)
if SECURE_COOKIES:
    SESSION_COOKIE_SECURE = True
    CSRF_COOKIE_SECURE = True


INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'django_otp',
    'django_otp.plugins.otp_totp',
    'django_otp.plugins.otp_static',
    'smartlock',
    'allauth',
    'allauth.account',
    'manage_sys',
    'corsheaders',
]
if DEBUG:
    INSTALLED_APPS.append('django_extensions')


MIDDLEWARE = [
    'corsheaders.middleware.CorsMiddleware',
    'django.middleware.security.SecurityMiddleware',
    'whitenoise.middleware.WhiteNoiseMiddleware',
    'manage_sys.middleware.ManageSysSessionCookieMiddleware',   
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
    'allauth.account.middleware.AccountMiddleware',
    'django_otp.middleware.OTPMiddleware',
]
if env_bool("PERF_TIMING", False):
    MIDDLEWARE.insert(0, 'manage_sys.middleware.ServerTimingMiddleware')


ROOT_URLCONF = 'smartlock_django.urls'


TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [BASE_DIR / 'templates'],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]


WSGI_APPLICATION = 'smartlock_django.wsgi.application'
ASGI_APPLICATION = 'smartlock_django.asgi.application'


DATABASES = {
    'default': {
        'ENGINE': os.environ.get("ENGINE", "django.db.backends.postgresql"),
        'NAME': os.environ.get("DB_NAME"),
        'USER': os.environ.get("DB_USER"),
        'PASSWORD': os.environ.get("DB_PASSWORD"),
        'HOST': os.environ.get("DB_HOST"),
        'PORT': os.environ.get("DB_PORT", "6543"),
        'CONN_MAX_AGE': env_int("DB_CONN_MAX_AGE", 0 if os.environ.get("VERCEL") else 60),
        'CONN_HEALTH_CHECKS': True,
        'DISABLE_SERVER_SIDE_CURSORS': True,
        'OPTIONS': {
            'sslmode': os.environ.get("DB_SSLMODE", "require"),
            'connect_timeout': env_int("DB_CONNECT_TIMEOUT", 5),
        },
    }
}
if not DATABASES['default']['ENGINE'].endswith('postgresql'):
    DATABASES['default']['OPTIONS'] = {}
    DATABASES['default'].pop('CONN_HEALTH_CHECKS', None)


LOCAL_REPLICA = env_bool("LOCAL_REPLICA", False)
REPLICA_SYNC_SECONDS = max(1, env_int("REPLICA_SYNC_SECONDS", 2))
REPLICA_FULL_SYNC_SECONDS = max(10, env_int("REPLICA_FULL_SYNC_SECONDS", 300))
REPLICA_STICKY_SECONDS = env_int("REPLICA_STICKY_SECONDS", 5)
REPLICA_FRESH_MODELS = set(env_list("REPLICA_FRESH_MODELS", ",".join([
    "sessions.Session", "smartlock.User", "smartlock.OneTimeCode", "smartlock.TwoFactorConfig",
    "smartlock.Fido2Credential", "smartlock.MobileSession", "smartlock.DeviceCommand",
    "smartlock.SystemSettings", "otp_totp.TOTPDevice", "otp_static.StaticDevice", "otp_static.StaticToken",
    "smartlock.SecurityRecord",
    "smartlock.Device", "smartlock.DeviceAccess", "smartlock.AccessCredential", "smartlock.CardDeviceAccess",
    "smartlock.NfcReader",
])))
if LOCAL_REPLICA:
    _replica_engine = os.environ.get("REPLICA_ENGINE", "django.db.backends.sqlite3")
    if _replica_engine.endswith("sqlite3"):
        DATABASES['replica'] = {
            'ENGINE': _replica_engine,
            'NAME': BASE_DIR / 'replica.sqlite3',
            'OPTIONS': {'timeout': 20, 'init_command': 'PRAGMA journal_mode=WAL;'},
        }
    else:
        DATABASES['replica'] = {
            'ENGINE': _replica_engine,
            'NAME': os.environ.get("REPLICA_DB_NAME", "smartlock_replica"),
            'USER': os.environ.get("REPLICA_DB_USER", "postgres"),
            'PASSWORD': os.environ.get("REPLICA_DB_PASSWORD", ""),
            'HOST': os.environ.get("REPLICA_DB_HOST", "localhost"),
            'PORT': os.environ.get("REPLICA_DB_PORT", "5432"),
        }
    DATABASE_ROUTERS = ['smartlock_django.settings.ReplicaRouter']


if os.environ.get("VERCEL"):
    CACHES = {
        'default': {
            'BACKEND': 'django.core.cache.backends.db.DatabaseCache',
            'LOCATION': 'email_cache',
            'TIMEOUT': 60 * 60 * 24,
            'OPTIONS': {'MAX_ENTRIES': 10000},
        }
    }
else:
    CACHES = {
        'default': {
            'BACKEND': 'django.core.cache.backends.locmem.LocMemCache',
            'LOCATION': 'smartlock-local',
            'TIMEOUT': 60 * 60 * 24,
            'OPTIONS': {'MAX_ENTRIES': 10000},
        }
    }
    SESSION_ENGINE = 'django.contrib.sessions.backends.cached_db'


AUTH_USER_MODEL = 'smartlock.User'


AUTH_PASSWORD_VALIDATORS = [
    {'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator'},
    {'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator', 'OPTIONS': {'min_length': 8}},
    {'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator'},
    {'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator'},
]

LOGIN_URL = 'smartlock:login'
LOGIN_REDIRECT_URL = 'smartlock:dashboard'
LOGOUT_REDIRECT_URL = 'smartlock:login'


EMAIL_BACKEND = os.environ.get("EMAIL_BACKEND", "django.core.mail.backends.smtp.EmailBackend")
EMAIL_HOST = os.environ.get("EMAIL_HOST")
EMAIL_PORT = env_int("EMAIL_PORT", 465)
EMAIL_USE_TLS = env_bool("EMAIL_USE_TLS", False)
EMAIL_USE_SSL = env_bool("EMAIL_USE_SSL", True)
EMAIL_HOST_USER = os.environ.get("EMAIL_HOST_USER")
EMAIL_HOST_PASSWORD = os.environ.get("EMAIL_HOST_PASSWORD")
DEFAULT_FROM_EMAIL = os.environ.get("DEFAULT_FROM_EMAIL")
EMAIL_TIMEOUT = env_int("EMAIL_TIMEOUT", 10)
EMAIL_BATCH_SIZE = env_int("EMAIL_BATCH_SIZE", 100)

PASSWORD_RESET_TIMEOUT = env_int("PASSWORD_RESET_TIMEOUT_MINUTES", 5) * 60

LANGUAGE_CODE = 'vi'
TIME_ZONE = 'Asia/Ho_Chi_Minh'
USE_I18N = True
USE_TZ = True


STATIC_URL = '/static/'
STATIC_ROOT = BASE_DIR / 'staticfiles'
WHITENOISE_USE_FINDERS = env_bool("WHITENOISE_USE_FINDERS", True)
STORAGES = {
    "default": {"BACKEND": "django.core.files.storage.FileSystemStorage"},
    "staticfiles": {"BACKEND": "whitenoise.storage.CompressedStaticFilesStorage"},
}


SUPABASE_URI = os.environ.get("SUPABASE_URI")


LOGGING = {
    "version": 1,
    "disable_existing_loggers": False,

    "formatters": {
        "verbose": {
            "format": "{levelname} {asctime} {name} {message}",
            "style": "{",
        },
    },

    "handlers": {
        "console": {
            "class": "logging.StreamHandler",
            "formatter": "verbose",
        },
    },

    "loggers": {
        "django": {
            "handlers": ["console"],
            "level": "INFO",
            "propagate": False,
        },

        "smartlock": {
            "handlers": ["console"],
            "level": "INFO",
            "propagate": False,
        },
    },
}

MANAGE_SYS_URL_PREFIX = '/manage-sys/'
ADMIN_REQUIRE_2FA = env_bool("ADMIN_REQUIRE_2FA", False)
MANAGE_SYS_SESSION_SECONDS = 2 * 60 * 60
ADMIN_FULL_POWER = env_bool("ADMIN_FULL_POWER", True)


TRUST_PROXY_COUNT = env_int("TRUST_PROXY_COUNT", 1)

BLE_TICKET_TTL_SECONDS = env_int("BLE_TICKET_TTL_SECONDS", 3600)

if not DEBUG and SECURE_COOKIES:
    SECURE_HSTS_SECONDS = env_int("SECURE_HSTS_SECONDS", 60 * 60 * 24 * 30)
    SECURE_HSTS_INCLUDE_SUBDOMAINS = env_bool("SECURE_HSTS_INCLUDE_SUBDOMAINS", False)
    SECURE_SSL_REDIRECT = env_bool("SECURE_SSL_REDIRECT", False)
    SECURE_REDIRECT_EXEMPT = [r"api/mqtt/", r"api/webhooks/"]
    SECURE_REFERRER_POLICY = "same-origin"


CORS_URLS_REGEX = r"^/api/app/.*$"
CORS_ALLOWED_ORIGINS = env_list("CORS_ALLOWED_ORIGINS")
if env_bool("CORS_ALLOW_LOCALHOST", DEBUG):
    CORS_ALLOWED_ORIGIN_REGEXES = [r"^http://localhost:\d+$", r"^http://127\.0\.0\.1:\d+$"]


MOBILE_ACCESS_TOKEN_SECONDS = 15 * 60


import sys as _sys
import threading as _threading
import time as _time

_REPLICA_STATE_FILE = BASE_DIR / '.replica_state.json'
_replica_tls = _threading.local()
_up_cache = {'t': 0.0, 'ok': True}
_ready_cache = {'t': 0.0, 'ok': False}


def _supabase_up():
    from django.db import connections
    now = _time.monotonic()
    if now - _up_cache['t'] < 15:
        return _up_cache['ok']
    try:
        connections['default'].ensure_connection()
        ok = True
    except Exception:
        ok = False
        try:
            connections['default'].close()
        except Exception:
            pass
    _up_cache.update(t=now, ok=ok)
    return ok


def _replica_ready():
    now = _time.monotonic()
    if now - _ready_cache['t'] > 5:
        _ready_cache.update(t=now, ok=os.path.exists(_REPLICA_STATE_FILE))
    return _ready_cache['ok']


class ReplicaRouter:
    def db_for_read(self, model, **hints):
        from django.db import connections
        if not _replica_ready() or model._meta.app_label == 'django_cache':
            return 'default'
        if connections['default'].in_atomic_block:
            return 'default'
        fresh = model._meta.label in REPLICA_FRESH_MODELS
        recent = (_time.monotonic() - getattr(_replica_tls, 'wrote', -1e9)) < REPLICA_STICKY_SECONDS
        if fresh or recent:
            return 'default' if _supabase_up() else 'replica'
        return 'replica'

    def db_for_write(self, model, **hints):
        _replica_tls.wrote = _time.monotonic()
        _replica_wake.set()
        return 'default'

    def allow_relation(self, obj1, obj2, **hints):
        return True

    def allow_migrate(self, db, app_label, model_name=None, **hints):
        return True

_REPLICA_APPEND_ONLY = {'smartlock.ActivityLog': 'created_at'}

_replica_sync_lock = _threading.Lock()
_replica_wake = _threading.Event()
_replica_state = {'snap': None, 'full_at': 0.0}


def _replica_log(msg):
    print(f'[replica] {msg}', file=_sys.stderr, flush=True)


def _replica_chunks(seq, n=400):
    seq = list(seq)
    for i in range(0, len(seq), n):
        yield seq[i:i + n]


def _replica_upsert(model, qs):
    from django.db import connections
    conn = connections['replica']
    q = conn.ops.quote_name
    fields = list(model._meta.concrete_fields)
    pk_col = model._meta.pk.column
    cols = [f.column for f in fields]
    updates = [c for c in cols if c != pk_col]
    sql = f'INSERT INTO {q(model._meta.db_table)} ({", ".join(q(c) for c in cols)}) VALUES ({", ".join(["%s"] * len(cols))}) '
    if updates:
        sql += f'ON CONFLICT ({q(pk_col)}) DO UPDATE SET ' + ', '.join(f'{q(c)} = EXCLUDED.{q(c)}' for c in updates)
    else:
        sql += f'ON CONFLICT ({q(pk_col)}) DO NOTHING'
    total, batch = 0, []

    def flush():
        with conn.cursor() as cur:
            cur.executemany(sql, batch)

    for obj in qs.iterator(chunk_size=400):
        batch.append([f.get_db_prep_save(getattr(obj, f.attname), connection=conn) for f in fields])
        if len(batch) >= 400:
            flush(); total += len(batch); batch = []
    if batch:
        flush(); total += len(batch)
    return total


def _replica_counters():
    from django.db import connections
    from django.db.utils import InterfaceError, OperationalError
    try:
        with connections['default'].cursor() as cur:
            cur.execute('SELECT relname, n_tup_ins, n_tup_upd, n_tup_del FROM pg_stat_user_tables '
                        'WHERE schemaname = current_schema()')
            return {r[0]: (r[1], r[2], r[3]) for r in cur.fetchall()}
    except (OperationalError, InterfaceError):
        raise
    except Exception:
        return None


def replica_sync_once(full=False):
    import json
    from datetime import timedelta
    from django.apps import apps
    from django.db import transaction
    from django.utils import timezone
    from django.utils.dateparse import parse_datetime

    if not _replica_sync_lock.acquire(blocking=False):
        return None
    try:
        snap = _replica_counters()
        prev = _replica_state['snap']
        now = _time.monotonic()
        full_pass = (full or snap is None or prev is None
                     or now - _replica_state['full_at'] >= REPLICA_FULL_SYNC_SECONDS)
        models_ = [m for m in apps.get_models(include_auto_created=True) if m._meta.managed and not m._meta.proxy]
        todo = [m for m in models_ if full_pass or snap.get(m._meta.db_table) != prev.get(m._meta.db_table)]
        if not todo:
            return 0, 0
        try:
            state = json.loads(_REPLICA_STATE_FILE.read_text(encoding='utf-8'))
        except Exception:
            state = {}
        started = timezone.now()
        upserted = deleted = 0
        with transaction.atomic(using='replica'):
            for m in todo:
                pk_name = m._meta.pk.name
                remote = set(m._base_manager.using('default').values_list(pk_name, flat=True))
                local = set(m._base_manager.using('replica').values_list(pk_name, flat=True))
                gone = local - remote
                for part in _replica_chunks(gone):
                    m._base_manager.using('replica').filter(pk__in=part)._raw_delete('replica')
                deleted += len(gone)
            for m in todo:
                label = m._meta.label
                qs = m._base_manager.using('default').all()
                ts = _REPLICA_APPEND_ONLY.get(label)
                if ts and state.get(label) and not full:
                    qs = qs.filter(**{f'{ts}__gte': parse_datetime(state[label]) - timedelta(minutes=2)})
                upserted += _replica_upsert(m, qs)
        for m in todo:
            state[m._meta.label] = started.isoformat()
        state['_last_ok'] = timezone.now().isoformat()
        _REPLICA_STATE_FILE.write_text(json.dumps(state), encoding='utf-8')
        _replica_state['snap'] = snap
        if full_pass:
            _replica_state['full_at'] = now
        return upserted, deleted
    finally:
        _replica_sync_lock.release()


def _replica_autosync_loop():
    from django.apps import apps
    from django.core.management import call_command
    from django.db import connections
    while not apps.ready:
        _time.sleep(0.5)
    try:
        call_command('migrate', database='replica', verbosity=0, interactive=False)
    except Exception as exc:
        _replica_log(f'Không dựng được schema bản sao: {exc}. Thử REPLICA_ENGINE=postgresql (Postgres local).')
        return
    first = True
    while True:
        try:
            r = replica_sync_once()
            if r is not None and first:
                _replica_log(f'Tải xong lần đầu ({r[0]} dòng). Kiểm tra thay đổi mỗi {REPLICA_SYNC_SECONDS}s, '
                             f'chỉ chép bảng có đổi.')
                first = False
        except Exception as exc:
            _replica_log(f'Đồng bộ lỗi, giữ bản sao cũ: {exc}')
            for alias in ('default', 'replica'):
                try:
                    connections[alias].close()
                except Exception:
                    pass
        woke = _replica_wake.wait(timeout=REPLICA_SYNC_SECONDS)
        if woke:
            _replica_wake.clear()
            _time.sleep(0.4)


def _start_replica_autosync():
    argv = _sys.argv
    is_runserver = len(argv) > 1 and argv[1] == 'runserver'
    is_child = os.environ.get('RUN_MAIN') == 'true' or '--noreload' in argv
    if not (LOCAL_REPLICA and is_runserver and is_child):
        return
    _threading.Thread(target=_replica_autosync_loop, name='replica-autosync', daemon=True).start()
    _replica_log('Tự đồng bộ Supabase -> máy local đã bật.')


_start_replica_autosync()
