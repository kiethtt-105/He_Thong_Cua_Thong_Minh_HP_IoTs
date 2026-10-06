"""Gắn vào urls gốc của project (smartlock_django/urls.py):

    path('api/', include('smartlock.api.urls'))

    /api/app/...       -> app/            APP di động + WEB (Bearer | cookie + CSRF)
    /api/device/...    -> device/urls.py  THIẾT BỊ (firmware; X-Device-Code + Secret)
    /api/webhooks/...  -> device/urls.py  server-to-server (broker MQTT gọi vào)
    /api/system/...    -> device/urls.py  công khai: health, config

Giữ nguyên namespace 'smartlock_api' và toàn bộ name= của route cũ.
"""
from django.urls import include, path

from .device import urls as device_urls

app_name = 'smartlock_api'

urlpatterns = [
    path('app/', include('smartlock.api.app.urls')),
    path('device/', include(device_urls.device_patterns)),
    path('webhooks/', include(device_urls.webhook_patterns)),
    path('system/', include(device_urls.system_patterns)),
]
