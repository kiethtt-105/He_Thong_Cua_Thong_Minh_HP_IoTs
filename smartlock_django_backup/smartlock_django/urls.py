#smartlock_django/urls.py
from django.contrib import admin
from django.urls import include, path
from django.conf import settings


urlpatterns = [
    path('admin/', admin.site.urls),
    path(settings.MANAGE_SYS_URL_PREFIX.strip('/') + '/', include('manage_sys.urls')),
    path('', include('smartlock.urls', namespace='smartlock')),
    path('api/v1/', include('smartlock.api.urls')),
]
