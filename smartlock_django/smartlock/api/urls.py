"""
Gắn vào urls gốc của project (smartlock_django/urls.py):

    path('api/', include('smartlock.api.urls'))

    /api/app/...       -> app/       API dùng chung APP di động + WEB (Bearer | cookie + CSRF)
    /api/device/...    -> device/    API cho THIẾT BỊ (firmware; X-Device-Code + Secret)
    /api/webhooks/...  -> webhooks/  server-to-server (broker MQTT gọi vào)
    /api/system/...    -> system/    công khai: health, config

Mỗi nhóm có prefix riêng nên thứ tự khai báo không còn quan trọng.
"""
from django.urls import include, path

app_name = 'smartlock_api'

urlpatterns = [
    path('app/', include('smartlock.api.app.urls')),
    path('device/', include('smartlock.api.device.urls')),
    path('webhooks/', include('smartlock.api.webhooks.urls')),
    path('system/', include('smartlock.api.system.urls')),
]
