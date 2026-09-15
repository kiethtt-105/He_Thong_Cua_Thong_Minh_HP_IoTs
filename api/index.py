"""
Vercel Python runtime tìm một biến WSGI/ASGI callable trong file này.
Nó chỉ import lại app Django đã cấu hình sẵn ở smart_lock/wsgi.py.
"""
import os
import sys
from pathlib import Path

# Cho phép import "smart_lock" và "accounts" từ thư mục gốc repo
sys.path.append(str(Path(__file__).resolve().parent.parent))

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'smart_lock.settings')

from django.core.wsgi import get_wsgi_application  # noqa: E402

app = get_wsgi_application()
