# smartlock_django/settings_test.py
"""Settings riêng cho test: SQLite trong RAM, cache/email locmem, không đụng Supabase/.env thật.
Chạy: python manage.py test smartlock.api --settings=smartlock_django.settings_test -v 2"""
import os

from cryptography.fernet import Fernet

# Đặt TRƯỚC khi import settings gốc (settings.py/models.py bắt buộc có các biến này).
os.environ.setdefault('DJANGO_SECRET_KEY', 'test-secret-key-not-for-production')
os.environ.setdefault('FERNET_KEY', Fernet.generate_key().decode())
os.environ.setdefault('SHARE_CODE_PEPPER', 'test-pepper')

from .settings import *  # noqa: E402,F401,F403

DEBUG = False
ALLOWED_HOSTS = ['*', 'testserver']
DATABASES = {'default': {'ENGINE': 'django.db.backends.sqlite3', 'NAME': ':memory:'}}
CACHES = {'default': {'BACKEND': 'django.core.cache.backends.locmem.LocMemCache'}}
EMAIL_BACKEND = 'django.core.mail.backends.locmem.EmailBackend'
DEFAULT_FROM_EMAIL = 'Smart Lock <noreply@example.com>'
SESSION_COOKIE_SECURE = False
CSRF_COOKIE_SECURE = False
PASSWORD_HASHERS = ['django.contrib.auth.hashers.MD5PasswordHasher']   # nhanh hơn khi test
# Tạo bảng thẳng từ models (tránh migration có thể dùng SQL riêng của Postgres).
MIGRATION_MODULES = {'smartlock': None}