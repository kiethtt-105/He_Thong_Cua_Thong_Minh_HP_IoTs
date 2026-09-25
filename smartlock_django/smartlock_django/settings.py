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


# ==================== HOST CONFIGURATION (100% từ .env) ====================
# Ví dụ: ALLOWED_HOSTS=localhost,127.0.0.1,ten-mien.vercel.app
# Muốn cho phép mọi link preview của Vercel: thêm ".vercel.app"
ALLOWED_HOSTS = env_list("ALLOWED_HOSTS", "localhost,127.0.0.1")
if DEBUG:
    ALLOWED_HOSTS = list(ALLOWED_HOSTS) + ["*"]


# ==================== CSRF TRUSTED ORIGINS ====================
_explicit_origins = env_list("CSRF_TRUSTED_ORIGINS")
if _explicit_origins:
    CSRF_TRUSTED_ORIGINS = _explicit_origins
else:
    CSRF_TRUSTED_ORIGINS = []
    for _host in ALLOWED_HOSTS:
        if _host == "*":
            continue
        if _host in ("localhost", "127.0.0.1", "0.0.0.0"):
            CSRF_TRUSTED_ORIGINS += [f"http://{_host}", f"http://{_host}:8000"]
        elif _host.startswith("."):
            CSRF_TRUSTED_ORIGINS.append(f"https://*{_host}")
        else:
            CSRF_TRUSTED_ORIGINS.append(f"https://{_host}")


# ==================== PROXY / HTTPS (Vercel) ====================
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
    'rest_framework',
    'allauth',
    'allauth.account',
    'django_extensions',  
    'manage_sys'
]


# ==================== MIDDLEWARE CONFIGURATION ====================
MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'whitenoise.middleware.WhiteNoiseMiddleware',
    'manage_sys.middleware.ManageSysSessionCookieMiddleware',   
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'smartlock.admin_audit.AuditRequestMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
    'allauth.account.middleware.AccountMiddleware',
    'django_otp.middleware.OTPMiddleware',

]


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
        'CONN_MAX_AGE': 0,                        # serverless: không giữ kết nối
        'DISABLE_SERVER_SIDE_CURSORS': True,      # bắt buộc với pooler transaction mode
        'OPTIONS': {'sslmode': os.environ.get("DB_SSLMODE", "require")},
    }
}


# ==================== CACHE CONFIGURATION ====================
# Cần chạy 1 lần: python manage.py createcachetable
CACHES = {
    'default': {
        'BACKEND': 'django.core.cache.backends.db.DatabaseCache',
        'LOCATION': 'email_cache',
        'TIMEOUT': 60 * 60 * 24,                  # 1 ngày
        'OPTIONS': {
            'MAX_ENTRIES': 10000,
        },
    }
}


# ==================== AUTH CONFIGURATION ====================
AUTH_USER_MODEL = 'smartlock.User'


# ==================== LOGIN/LOGOUT CONFIGURATION ====================
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

#
PASSWORD_RESET_TIMEOUT = env_int("PASSWORD_RESET_TIMEOUT_MINUTES", 5) * 60

# ==================== INTERNATIONALIZATION CONFIGURATION ====================
LANGUAGE_CODE = 'vi'
TIME_ZONE = 'Asia/Ho_Chi_Minh'
USE_I18N = True
USE_TZ = True


# ==================== STATIC FILES CONFIGURATION ====================
STATIC_URL = '/static/'
STATIC_ROOT = BASE_DIR / 'staticfiles'
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

#
MANAGE_SYS_URL_PREFIX = '/manage-sys/'
MANAGE_SYS_SESSION_SECONDS = 2 * 60 * 60


TRUST_PROXY_HEADERS=True