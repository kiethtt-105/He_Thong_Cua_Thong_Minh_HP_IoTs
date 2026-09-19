# smartlock_django/smartlock_django/settings.py
import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent

# Load .env
from dotenv import load_dotenv
load_dotenv()


#==================== SECURITY CONFIGURATION ====================
SECRET_KEY = os.environ.get("DJANGO_SECRET_KEY")
DEBUG = os.environ.get("DEBUG", "False") == "True"


#==================== CACHE CONFIGURATION ====================
CACHES = {
    'default': {
        'BACKEND': 'django.core.cache.backends.db.DatabaseCache',
        'LOCATION': 'email_cache',           # tạo bảng email_cache trong DB
        'OPTIONS': {
            'MAX_ENTRIES': 10000,            # tối đa 10.000 email trong cache
            'TIMEOUT': 60 * 60 * 24,         # 1 ngày
        },
    }
}


#==================== HOST CONFIGURATION ====================
ALLOWED_HOSTS = [h.strip() for h in os.environ.get("ALLOWED_HOSTS", "localhost,127.0.0.1").split(",") if h.strip()]
if DEBUG and not ALLOWED_HOSTS:
    ALLOWED_HOSTS = ["localhost", "127.0.0.1", "0.0.0.0"]

if not DEBUG:
    ALLOWED_HOSTS = ["*.vercel.app", "127.0.0.1", "localhost"]

#==================== APPLICATION CONFIGURATION ====================
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
]


#==================== MIDDLEWARE CONFIGURATION ====================
MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
    'allauth.account.middleware.AccountMiddleware',
    'django_otp.middleware.OTPMiddleware',           
]

#==================== URL CONFIGURATION ====================
ROOT_URLCONF = 'smartlock_django.urls'


#==================== TEMPLATE CONFIGURATION ====================
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


#==================== WSGI/ASGI CONFIGURATION ====================
WSGI_APPLICATION = 'smartlock_django.wsgi.application'
ASGI_APPLICATION = 'smartlock_django.asgi.application'


#==================== DATABASE CONFIGURATION ====================
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.postgresql',
        'NAME': os.environ.get("DB_NAME"),
        'USER': os.environ.get("DB_USER"),
        'PASSWORD': os.environ.get("DB_PASSWORD"),
        'HOST': os.environ.get("DB_HOST"),
        'PORT': os.environ.get("DB_PORT", "5432"),
    }
}


#==================== AUTH CONFIGURATION ====================
AUTH_USER_MODEL = 'smartlock.User'


#==================== LOGIN/LOGOUT CONFIGURATION ====================
LOGIN_URL = 'smartlock:login'
LOGIN_REDIRECT_URL = 'smartlock:dashboard'
LOGOUT_REDIRECT_URL = 'smartlock:login'


#==================== EMAIL CONFIGURATION ====================
EMAIL_BACKEND = "django.core.mail.backends.smtp.EmailBackend"
EMAIL_HOST = os.environ.get("EMAIL_HOST")
EMAIL_PORT = int(os.environ.get("EMAIL_PORT", 465))
EMAIL_USE_SSL = os.environ.get("EMAIL_USE_SSL", "True").lower() == "true"
EMAIL_HOST_USER = os.environ.get("EMAIL_HOST_USER")
EMAIL_HOST_PASSWORD = os.environ.get("EMAIL_HOST_PASSWORD")
DEFAULT_FROM_EMAIL = os.environ.get("DEFAULT_FROM_EMAIL")
EMAIL_TIMEOUT = int(os.environ.get("EMAIL_TIMEOUT", 10))
EMAIL_BATCH_SIZE = int(os.environ.get("EMAIL_BATCH_SIZE", 100))


#==================== INTERNATIONALIZATION CONFIGURATION ====================
LANGUAGE_CODE = 'vi'
TIME_ZONE = 'Asia/Ho_Chi_Minh'
USE_I18N = True
USE_TZ = True


# ==================== STATIC FILES CONFIGURATION ====================
STATIC_URL = 'static/'


#==================== MEDIA FILES CONFIGURATION ====================
SUPABASE_URI = os.environ.get("SUPABASE_URI")


#==================== CSRF TRUSTED ORIGINS CONFIGURATION ====================
CSRF_TRUSTED_ORIGINS = [
    "http://127.0.0.1", "http://127.0.0.1:8000", "http://localhost", "http://localhost:8000",
    "https://he-thong-cua-thong-minh-hp-iots.vercel.app",
]


#==================== EMAIL CONFIGURATION ====================
EMAIL_TIMEOUT = int(os.environ.get("EMAIL_TIMEOUT", 10))


#==================== LOGGING CONFIGURATION ====================
LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'formatters': {
        'verbose': {'format': '[{asctime}] {levelname} {name}: {message}', 'style': '{'},
    },
    'handlers': {
        'console': {'class': 'logging.StreamHandler', 'formatter': 'verbose'},
        'file': {
            'class': 'logging.FileHandler',
            'filename': BASE_DIR / 'smartlock.log',
            'formatter': 'verbose',
            'encoding': 'utf-8',
        },
    },
    'loggers': {
        'smartlock': {'handlers': ['console', 'file'], 'level': 'DEBUG', 'propagate': False},
    },
}