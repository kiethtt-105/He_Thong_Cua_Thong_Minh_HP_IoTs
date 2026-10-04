"""
WSGI config for smartlock_django project.

It exposes the WSGI callable as a module-level variable named ``application``.
Vercel requires a variable named ``app``.

For more information on this file, see
https://docs.djangoproject.com/en/5.2/howto/deployment/wsgi/
"""

import os
import sys
from pathlib import Path

from django.core.wsgi import get_wsgi_application

# Thêm thư mục smartlock_django/ (chứa manage.py) vào sys.path
sys.path.append(str(Path(__file__).resolve().parent.parent))
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'smartlock_django.settings')

application = get_wsgi_application()
app = application
