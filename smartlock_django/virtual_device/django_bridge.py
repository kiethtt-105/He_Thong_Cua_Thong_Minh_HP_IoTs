# virtual_device/django_bridge.py
"""Chỉ các lệnh quản trị (provision / claim / info / ping ...) mới cần Django. `run` KHÔNG cần,
nên có thể chạy khoá ảo trên máy khác chỉ với paho-mqtt + identity.json."""
import os
import sys

from . import config


def boot():
    import django
    from django.apps import apps
    if apps.ready:
        return
    if str(config.PROJECT_ROOT) not in sys.path:
        sys.path.insert(0, str(config.PROJECT_ROOT))
    os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'smartlock_django.settings')
    try:
        django.setup()
    except RuntimeError as e:       # thiếu FERNET_KEY / SHARE_CODE_PEPPER trong .env
        raise SystemExit(f'Không khởi động được Django: {e}')
