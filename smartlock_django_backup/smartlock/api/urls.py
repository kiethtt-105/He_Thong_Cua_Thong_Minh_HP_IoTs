"""
Gắn vào urls gốc của project (smartlock_django/urls.py):

    path('api/v1/', include('smartlock.api.urls'))

    /api/v1/device/...  -> api/lock/  (API cho KHOÁ / firmware)
    /api/v1/...         -> api/app/   (API cho APP di động)
"""
from django.urls import include, path

app_name = 'smartlock_api'

urlpatterns = [
    path('device/', include('smartlock.api.lock.urls')),   # phải đứng trước app (cùng prefix /api/v1/)
    path('', include('smartlock.api.app.urls')),
]
