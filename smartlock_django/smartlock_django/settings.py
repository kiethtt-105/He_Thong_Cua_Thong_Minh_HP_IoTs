# smartlock_django/smartlock_django/settings.py
import os
from pathlib import Path

from django.core.exceptions import ImproperlyConfigured

BASE_DIR = Path(__file__).resolve().parent.parent

# Load .env (local). Trên Vercel không có file .env, biến lấy từ Environment Variables.
from dotenv import load_dotenv
load_dotenv(BASE_DIR.parent / ".env")   # .env nằm ở thư mục gốc repo
load_dotenv()                           # fallback: .env ở thư mục hiện tại


# ==================== HELPERS ====================
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


# ==================== SECURITY CONFIGURATION ====================
SECRET_KEY = os.environ.get("DJANGO_SECRET_KEY")
if not SECRET_KEY:
    raise ImproperlyConfigured("Thiếu biến môi trường DJANGO_SECRET_KEY")

DEBUG = env_bool("DEBUG", False)

# Khóa mã hóa Fernet và cấu hình OTP (đọc từ .env)
FERNET_KEY = os.environ.get("FERNET_KEY")
OTP_EXPIRY_MINUTES = env_int("OTP_EXPIRY_MINUTES", 5)
OTP_MAX_ATTEMPTS = env_int("OTP_MAX_ATTEMPTS", 5)

# ==================== WEBAUTHN (PASSKEY) ====================
# Để trống -> tự suy ra từ Host header của request (dễ sai khi chạy qua devtunnel/ngrok
# vì tunnel có thể đổi Host header thành localhost). Đặt cứng trong .env để chắc chắn khớp
# domain đang mở trên trình duyệt, ví dụ khi test qua devtunnel:
#   WEBAUTHN_RP_ID=xxxx.asse.devtunnels.ms
#   WEBAUTHN_ORIGIN=https://xxxx.asse.devtunnels.ms
WEBAUTHN_RP_ID = os.environ.get("WEBAUTHN_RP_ID") or None
WEBAUTHN_ORIGIN = os.environ.get("WEBAUTHN_ORIGIN") or None
WEBAUTHN_RP_NAME = os.environ.get("WEBAUTHN_RP_NAME", "Smart Lock")

# ==================== MQTT ====================
MQTT_HOST = os.environ.get("MQTT_HOST")
MQTT_PORT = env_int("MQTT_PORT", 1883)
MQTT_TOPIC_PREFIX = os.environ.get("MQTT_TOPIC_PREFIX", "")
# Bí mật chung broker <-> Django cho webhook auth/ACL (broker gửi header X-Webhook-Secret).
MQTT_WEBHOOK_SECRET = os.environ.get("MQTT_WEBHOOK_SECRET") or None
# Tài khoản MQTT của server (publisher/subscriber) được bỏ qua ACL theo thiết bị.
MQTT_TRUSTED_USERNAMES = env_list("MQTT_TRUSTED_USERNAMES", os.environ.get("MQTT_PUBLISHER_USERNAME", ""))

# Trang log công khai /demo/system-logs/: chỉ bật khi DEBUG hoặc khi đặt DEMO_LOGS_ENABLED=True.
DEMO_LOGS_ENABLED = env_bool("DEMO_LOGS_ENABLED", DEBUG)

# Lưu messages trong session (không đi qua cookie) - PIN cấp cho khách hiển thị qua messages.
MESSAGE_STORAGE = "django.contrib.messages.storage.session.SessionStorage"


# ==================== HOST CONFIGURATION (100% từ .env) ====================
# Dự án học tập: ALLOW_ALL_HOSTS=True -> chạy được ở local, devtunnel, Vercel (mọi preview) mà không cần liệt kê host.
# Production thật: đặt ALLOW_ALL_HOSTS=False và liệt kê ALLOWED_HOSTS (vd. localhost,ten-mien.vercel.app).
ALLOW_ALL_HOSTS = env_bool("ALLOW_ALL_HOSTS", False)
ALLOWED_HOSTS = env_list("ALLOWED_HOSTS", "localhost,127.0.0.1")
if ALLOW_ALL_HOSTS:
    ALLOWED_HOSTS = ["*"]


# ==================== CSRF TRUSTED ORIGINS ====================
_explicit_origins = env_list("CSRF_TRUSTED_ORIGINS")
if _explicit_origins:
    CSRF_TRUSTED_ORIGINS = _explicit_origins
elif ALLOW_ALL_HOSTS:
    # "*" ở ALLOWED_HOSTS không áp dụng cho CSRF -> liệt kê wildcard cho các môi trường hay dùng.
    CSRF_TRUSTED_ORIGINS = [
        "http://localhost:8000", "http://127.0.0.1:8000", "http://10.0.2.2:8000",
        "https://*.vercel.app", "https://*.devtunnels.ms", "https://*.ngrok-free.app", "https://*.ngrok.io",
    ]
else:
    CSRF_TRUSTED_ORIGINS = []
    for _host in ALLOWED_HOSTS:
        if _host in ("localhost", "127.0.0.1", "0.0.0.0", "10.0.2.2"):
            CSRF_TRUSTED_ORIGINS += [f"http://{_host}", f"http://{_host}:8000"]
        elif _host.startswith("."):
            CSRF_TRUSTED_ORIGINS.append(f"https://*{_host}")
        else:
            CSRF_TRUSTED_ORIGINS.append(f"https://{_host}")


# ==================== PROXY / HTTPS (Vercel) ====================
# Chỉ tin X-Forwarded-Proto khi app thật sự đứng sau proxy tin cậy (nếu không, client giả header được).
TRUST_PROXY_HEADERS = env_bool("TRUST_PROXY_HEADERS", True)
if TRUST_PROXY_HEADERS:
    SECURE_PROXY_SSL_HEADER = ("HTTP_X_FORWARDED_PROTO", "https")

# Mặc định bật cookie Secure khi DEBUG=False (Vercel dùng HTTPS).
# Chạy local bằng http://localhost với DEBUG=False: đặt SECURE_COOKIES=False trong .env
SECURE_COOKIES = env_bool("SECURE_COOKIES", not DEBUG)
if SECURE_COOKIES:
    SESSION_COOKIE_SECURE = True
    CSRF_COOKIE_SECURE = True


# ==================== APPLICATION CONFIGURATION ====================
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
    'manage_sys'
]
if DEBUG:
    INSTALLED_APPS.append('django_extensions')   # chỉ dùng khi dev (shell_plus...)


# ==================== MIDDLEWARE CONFIGURATION ====================
MIDDLEWARE = [
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
if env_bool("PERF_TIMING", False):   # xem manage_sys/middleware.py: Server-Timing + log request chậm
    MIDDLEWARE.insert(0, 'manage_sys.middleware.ServerTimingMiddleware')


# ==================== URL CONFIGURATION ====================
ROOT_URLCONF = 'smartlock_django.urls'


# ==================== TEMPLATE CONFIGURATION ====================
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


# ==================== WSGI/ASGI CONFIGURATION ====================
WSGI_APPLICATION = 'smartlock_django.wsgi.application'
ASGI_APPLICATION = 'smartlock_django.asgi.application'


# ==================== DATABASE CONFIGURATION ====================
# Dùng Supabase Transaction Pooler: DB_HOST=...pooler.supabase.com, DB_PORT=6543
DATABASES = {
    'default': {
        'ENGINE': os.environ.get("ENGINE", "django.db.backends.postgresql"),
        'NAME': os.environ.get("DB_NAME"),
        'USER': os.environ.get("DB_USER"),
        'PASSWORD': os.environ.get("DB_PASSWORD"),
        'HOST': os.environ.get("DB_HOST"),
        'PORT': os.environ.get("DB_PORT", "6543"),
        # Mở kết nối TLS tới Supabase mỗi request tốn ~0.3-1s. Local/VPS: giữ kết nối 60s; Vercel (serverless): 0.
        'CONN_MAX_AGE': env_int("DB_CONN_MAX_AGE", 0 if os.environ.get("VERCEL") else 60),
        'CONN_HEALTH_CHECKS': True,               # kết nối cũ bị pooler đóng -> tự mở lại, không lỗi
        'DISABLE_SERVER_SIDE_CURSORS': True,      # bắt buộc với pooler transaction mode
        'OPTIONS': {
            'sslmode': os.environ.get("DB_SSLMODE", "require"),
            'connect_timeout': env_int("DB_CONNECT_TIMEOUT", 5),   # mất mạng -> báo lỗi sau 5s thay vì treo
        },
    }
}
if not DATABASES['default']['ENGINE'].endswith('postgresql'):
    DATABASES['default']['OPTIONS'] = {}      # sslmode/connect_timeout chỉ dành cho Postgres (vd. ENGINE=sqlite3 khi test)
    DATABASES['default'].pop('CONN_HEALTH_CHECKS', None)


# ==================== BẢN SAO LOCAL + TỰ ĐỒNG BỘ (chỉ máy cá nhân; Vercel không đặt LOCAL_REPLICA) ====================
# LOCAL_REPLICA=True: khi chạy `python manage.py runserver`, server TỰ tải Supabase về DB trên máy rồi tự làm mới
# mỗi REPLICA_SYNC_SECONDS giây (mặc định 2s, chỉ chép bảng có thay đổi; luồng nền, code ở cuối file này). Đọc từ máy local cho nhanh; GHI luôn vào
# Supabase (nguồn dữ liệu duy nhất -> không xung đột); dữ liệu Vercel ghi sẽ về máy sau tối đa vài giây.
# Mất kết nối Supabase: vẫn ĐỌC được từ bản sao, ghi sẽ báo lỗi.
LOCAL_REPLICA = env_bool("LOCAL_REPLICA", False)
REPLICA_SYNC_SECONDS = max(1, env_int("REPLICA_SYNC_SECONDS", 2))          # chu kỳ kiểm tra thay đổi (rẻ: 1 truy vấn nhỏ)
REPLICA_FULL_SYNC_SECONDS = max(10, env_int("REPLICA_FULL_SYNC_SECONDS", 300))   # định kỳ chép lại tất cả để chắc chắn khớp
REPLICA_STICKY_SECONDS = env_int("REPLICA_STICKY_SECONDS", 5)
# Bảng luôn đọc Supabase (ghi xong đọc lại ngay: phiên đăng nhập, tài khoản, OTP, 2FA, lệnh thiết bị...).
# Mọi bảng còn lại đọc từ máy. Ghi đè bằng .env: REPLICA_FRESH_MODELS=a,b,c (thay thế hoàn toàn danh sách này).
REPLICA_FRESH_MODELS = set(env_list("REPLICA_FRESH_MODELS", ",".join([
    "sessions.Session", "smartlock.User", "smartlock.OneTimeCode", "smartlock.TwoFactorConfig",
    "smartlock.Fido2Credential", "smartlock.MobileSession", "smartlock.DeviceCommand",
    "smartlock.SystemSettings", "otp_totp.TOTPDevice", "otp_static.StaticDevice", "otp_static.StaticToken",
])))
if LOCAL_REPLICA:
    # Mặc định SQLite (không cần cài gì). Postgres local: REPLICA_ENGINE=django.db.backends.postgresql + REPLICA_DB_*.
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


# ==================== CACHE CONFIGURATION ====================
# Cần chạy 1 lần: python manage.py createcachetable
if os.environ.get("VERCEL"):
    CACHES = {
        'default': {
            'BACKEND': 'django.core.cache.backends.db.DatabaseCache',
            'LOCATION': 'email_cache',
            'TIMEOUT': 60 * 60 * 24,                  # 1 ngày
            'OPTIONS': {'MAX_ENTRIES': 10000},
        }
    }
else:
    # Local/VPS 1 tiến trình: cache trong RAM (không tốn 1 vòng mạng tới Supabase cho mỗi lần get/set).
    # Lưu ý: mỗi tiến trình có cache riêng; nếu chạy nhiều worker gunicorn thì dùng Redis/Memcached.
    CACHES = {
        'default': {
            'BACKEND': 'django.core.cache.backends.locmem.LocMemCache',
            'LOCATION': 'smartlock-local',
            'TIMEOUT': 60 * 60 * 24,
            'OPTIONS': {'MAX_ENTRIES': 10000},
        }
    }
    # Session: đọc từ RAM, ghi xuống DB (đăng xuất/xoá session vẫn có hiệu lực).
    SESSION_ENGINE = 'django.contrib.sessions.backends.cached_db'


# ==================== AUTH CONFIGURATION ====================
AUTH_USER_MODEL = 'smartlock.User'


# ==================== LOGIN/LOGOUT CONFIGURATION ====================
AUTH_PASSWORD_VALIDATORS = [
    {'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator'},
    {'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator', 'OPTIONS': {'min_length': 8}},
    {'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator'},
    {'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator'},
]

LOGIN_URL = 'smartlock:login'
LOGIN_REDIRECT_URL = 'smartlock:dashboard'
LOGOUT_REDIRECT_URL = 'smartlock:login'


# ==================== EMAIL CONFIGURATION ====================
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

# ==================== INTERNATIONALIZATION CONFIGURATION ====================
LANGUAGE_CODE = 'vi'
TIME_ZONE = 'Asia/Ho_Chi_Minh'
USE_I18N = True
USE_TZ = True


# ==================== STATIC FILES CONFIGURATION ====================
STATIC_URL = '/static/'
STATIC_ROOT = BASE_DIR / 'staticfiles'
# Vercel (@vercel/python) không chạy collectstatic lúc build -> để WhiteNoise tự tìm file static qua finders
# (admin + static của các app) thay vì đọc từ STATIC_ROOT. Có thể tắt nếu đã commit thư mục staticfiles/.
WHITENOISE_USE_FINDERS = env_bool("WHITENOISE_USE_FINDERS", True)
STORAGES = {
    "default": {"BACKEND": "django.core.files.storage.FileSystemStorage"},
    "staticfiles": {"BACKEND": "whitenoise.storage.CompressedStaticFilesStorage"},
}


# ==================== MEDIA FILES CONFIGURATION ====================
SUPABASE_URI = os.environ.get("SUPABASE_URI")


# ==================== LOGGING ====================
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
# Bắt buộc 2FA (TOTP) khi vào Django admin /admin/. CHỈ bật sau khi Superuser đã có thiết bị TOTP
# (tạo bằng shell: TOTPDevice.objects.create(user=u, name='default', confirmed=True)), nếu không sẽ tự khoá mình.
ADMIN_REQUIRE_2FA = env_bool("ADMIN_REQUIRE_2FA", False)
MANAGE_SYS_SESSION_SECONDS = 2 * 60 * 60
# True (mặc định): mọi tài khoản quản trị có quyền cao nhất trong manage-sys (cấp/thu hồi admin, xoay secret, gỡ chủ khoá,
# đổi cài đặt). Vẫn bắt nhập lại mật khẩu + audit. False: các thao tác đó chỉ dành cho Superuser.
ADMIN_FULL_POWER = env_bool("ADMIN_FULL_POWER", True)


# TRUST_PROXY_HEADERS (khai báo ở phần PROXY / HTTPS phía trên): đứng sau proxy (Vercel/nginx) -> tin X-Forwarded-For/Proto
# Số proxy TIN CẬY phía trước app: IP client = phần tử thứ N tính từ cuối của X-Forwarded-For
# (phần tử đầu do client tự đặt được). Vercel = 1; nginx -> gunicorn = 1.
TRUST_PROXY_COUNT = env_int("TRUST_PROXY_COUNT", 1)

# Vé Bluetooth offline không thu hồi được -> giữ hạn ngắn (mặc định 1 giờ).
BLE_TICKET_TTL_SECONDS = env_int("BLE_TICKET_TTL_SECONDS", 3600)

# ==================== HTTPS HARDENING (production) ====================
if not DEBUG and SECURE_COOKIES:
    SECURE_HSTS_SECONDS = env_int("SECURE_HSTS_SECONDS", 60 * 60 * 24 * 30)   # 30 ngày
    SECURE_HSTS_INCLUDE_SUBDOMAINS = env_bool("SECURE_HSTS_INCLUDE_SUBDOMAINS", False)
    SECURE_SSL_REDIRECT = env_bool("SECURE_SSL_REDIRECT", False)   # Vercel đã tự redirect; bật nếu tự host
    SECURE_REDIRECT_EXEMPT = [r"api/mqtt/", r"api/webhooks/"]   # broker gọi webhook server-to-server, không bị 301
    SECURE_REFERRER_POLICY = "same-origin"


# ==================== API (api/app dùng chung APP + WEB) ====================
# API viết bằng Django thuần (smartlock/api/), KHÔNG dùng Django REST Framework.
#   * App (Android/iOS): Authorization: Bearer <access_token>
#   * Web: session cookie + header X-CSRFToken (lấy bằng GET /api/app/auth/csrf/)
# Khối REST_FRAMEWORK cũ trỏ tới smartlock.api.mobile_auth, api_exception_handler, StandardPagination
# (các module này không còn tồn tại) nên đã được gỡ.

# ==================== APP DI ĐỘNG ====================
MOBILE_ACCESS_TOKEN_SECONDS = 15 * 60


# =====================================================================================================
# ROUTER + TỰ ĐỒNG BỘ BẢN SAO LOCAL (mọi import Django đều để lười bên trong hàm: settings chưa sẵn sàng lúc import)
# =====================================================================================================
import sys as _sys
import threading as _threading
import time as _time

_REPLICA_STATE_FILE = BASE_DIR / '.replica_state.json'
_replica_tls = _threading.local()
_up_cache = {'t': 0.0, 'ok': True}
_ready_cache = {'t': 0.0, 'ok': False}


def _supabase_up():
    """Supabase còn kết nối được không (cache 15 giây)."""
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
    """Đã có ít nhất 1 lượt đồng bộ thành công chưa."""
    now = _time.monotonic()
    if now - _ready_cache['t'] > 5:
        _ready_cache.update(t=now, ok=os.path.exists(_REPLICA_STATE_FILE))
    return _ready_cache['ok']


class ReplicaRouter:
    """GHI -> Supabase. ĐỌC -> bản sao local, trừ: bảng REPLICA_FRESH_MODELS, trong transaction.atomic(),
    và REPLICA_STICKY_SECONDS giây sau khi vừa ghi (để thấy ngay dữ liệu mình vừa ghi). Mất Supabase -> đọc local."""

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
        _replica_wake.set()          # vừa ghi -> đánh thức luồng đồng bộ chạy sớm
        return 'default'

    def allow_relation(self, obj1, obj2, **hints):
        return True

    def allow_migrate(self, db, app_label, model_name=None, **hints):
        return True


# Bảng log chỉ-thêm: chỉ chép dòng mới. Bảng khác chép lại toàn bộ mỗi lượt (nhiều chỗ dùng queryset.update()
# nên không thể tin cột updated_at để lọc).
_REPLICA_APPEND_ONLY = {
    'smartlock.AuditLog': 'created_at', 'smartlock.AccessEvent': 'created_at',
    'smartlock.NfcLog': 'created_at', 'smartlock.DeviceStatusLog': 'recorded_at',
}
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
    """INSERT ... ON CONFLICT (pk) DO UPDATE bằng SQL thuần: không signal, không auto_now (giữ nguyên giờ gốc),
    không phải sửa thuộc tính field dùng chung với các luồng đang xử lý request."""
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
    """Bộ đếm insert/update/delete của mọi bảng trên Supabase (1 truy vấn nhỏ). Bảng không đổi bộ đếm = không cần chép.
    Trả None nếu không đọc được (không phải Postgres...) -> khi đó chép tất cả."""
    from django.db import connections
    from django.db.utils import InterfaceError, OperationalError
    try:
        with connections['default'].cursor() as cur:
            cur.execute('SELECT relname, n_tup_ins, n_tup_upd, n_tup_del FROM pg_stat_user_tables '
                        'WHERE schemaname = current_schema()')
            return {r[0]: (r[1], r[2], r[3]) for r in cur.fetchall()}
    except (OperationalError, InterfaceError):
        raise                                   # mất kết nối: để vòng lặp xử lý
    except Exception:
        return None


def replica_sync_once(full=False):
    """Supabase -> bản sao local, một chiều, CHỈ chép bảng có thay đổi. Cả lượt nằm trong 1 transaction:
    lỗi giữa chừng thì giữ nguyên bản cũ. Trả (số dòng ghi, số dòng xoá), hoặc None nếu đang có lượt khác chạy."""
    import json
    from datetime import timedelta
    from django.apps import apps
    from django.db import transaction
    from django.utils import timezone
    from django.utils.dateparse import parse_datetime

    if not _replica_sync_lock.acquire(blocking=False):
        return None
    try:
        snap = _replica_counters()                  # lấy TRƯỚC khi chép: thay đổi xảy ra trong lúc chép sẽ bắt ở lượt sau
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
            # Pha 1: xoá dòng local không còn trên Supabase (cả contenttype/permission tự sinh khi migrate local).
            for m in todo:
                pk_name = m._meta.pk.name
                remote = set(m._base_manager.using('default').values_list(pk_name, flat=True))
                local = set(m._base_manager.using('replica').values_list(pk_name, flat=True))
                gone = local - remote
                for part in _replica_chunks(gone):
                    m._base_manager.using('replica').filter(pk__in=part)._raw_delete('replica')
                deleted += len(gone)
            # Pha 2: ghi đè dòng mới/đã đổi. FK là DEFERRABLE nên thứ tự bảng không quan trọng.
            for m in todo:
                label = m._meta.label
                qs = m._base_manager.using('default').all()
                ts = _REPLICA_APPEND_ONLY.get(label)
                if ts and state.get(label) and not full:
                    qs = qs.filter(**{f'{ts}__gte': parse_datetime(state[label]) - timedelta(minutes=2)})
                upserted += _replica_upsert(m, qs)
        for m in todo:                              # chỉ cập nhật mốc của bảng vừa chép (log chỉ-thêm dựa vào mốc này)
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
    while not apps.ready:                      # chờ Django nạp xong app
        _time.sleep(0.5)
    try:
        call_command('migrate', database='replica', verbosity=0, interactive=False)   # dựng schema bản sao
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
        except Exception as exc:               # mất mạng...: giữ bản sao cũ, lượt sau thử lại
            _replica_log(f'Đồng bộ lỗi, giữ bản sao cũ: {exc}')
            for alias in ('default', 'replica'):
                try:
                    connections[alias].close()
                except Exception:
                    pass
        woke = _replica_wake.wait(timeout=REPLICA_SYNC_SECONDS)
        if woke:
            _replica_wake.clear()
            _time.sleep(0.4)                   # chờ request commit xong rồi mới chép


def _start_replica_autosync():
    """Chỉ chạy trong tiến trình thật của `runserver` (không chạy ở migrate/shell/Vercel/tiến trình cha của reloader)."""
    argv = _sys.argv
    is_runserver = len(argv) > 1 and argv[1] == 'runserver'
    is_child = os.environ.get('RUN_MAIN') == 'true' or '--noreload' in argv
    if not (LOCAL_REPLICA and is_runserver and is_child):
        return
    _threading.Thread(target=_replica_autosync_loop, name='replica-autosync', daemon=True).start()
    _replica_log('Tự đồng bộ Supabase -> máy local đã bật.')


_start_replica_autosync()