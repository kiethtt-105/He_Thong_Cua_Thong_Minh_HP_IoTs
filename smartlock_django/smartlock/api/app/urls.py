"""Route API dùng chung cho APP (Bearer) và WEB (session cookie + CSRF) - gắn dưới /api/app/ (xem api/urls.py).

Giữ nguyên tên route (namespace 'smartlock_api') nên template {% url 'smartlock_api:...' %} không đổi.
Các nhóm KHÔNG được khai báo app_name riêng, nếu không sẽ làm đổi namespace.
"""
from django.urls import include, path

urlpatterns = [
    path('', include('smartlock.api.app.auth.urls')),
    path('', include('smartlock.api.app.account.urls')),
    path('', include('smartlock.api.app.devices.urls')),
    path('', include('smartlock.api.app.access.urls')),
    path('', include('smartlock.api.app.activity.urls')),
]
