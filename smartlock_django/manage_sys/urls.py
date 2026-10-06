# manage_sys/urls.py
from django.urls import include, path

from . import views as v

app_name = 'manage_sys'

urlpatterns = [
    # API JSON dùng chung cho web + app: <prefix>api/v1/...
    path('api/v1/', include('manage_sys.api.urls')),

    path('', v.dashboard, name='dashboard'),
    path('login/', v.login_view, name='login'),
    path('logout/', v.logout_view, name='logout'),

    path('users/', v.users_list, name='users'),
    path('users/<uuid:user_id>/', v.user_detail, name='user-detail'),

    path('devices/', v.devices_list, name='devices'),
    path('devices/new/', v.device_create, name='device-create'),
    path('devices/<uuid:device_id>/', v.device_detail, name='device-detail'),
    path('devices/<uuid:device_id>/link/', v.device_link_status, name='device-link'),
    path('devices/<uuid:device_id>/secret/', v.device_secret, name='device-secret'),

    path('logs/', v.audit_logs, name='logs'),
    path('logs/logins/', v.login_attempts, name='login-attempts'),

    path('announcements/', v.announcements, name='announcements'),
    path('settings/', v.settings_system, name='settings'),
]