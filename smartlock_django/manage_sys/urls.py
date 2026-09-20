# manage_sys/urls.py
from django.urls import path

from . import views

app_name = 'manage_sys'

urlpatterns = [
    path('', views.dashboard, name='dashboard'),
    path('login/', views.login_view, name='login'),
    path('logout/', views.logout_view, name='logout'),

    path('users/', views.users_list, name='users'),
    path('users/<uuid:user_id>/', views.user_detail, name='user-detail'),

    path('devices/', views.devices_list, name='devices'),
    path('devices/<uuid:device_id>/', views.device_detail, name='device-detail'),

    path('support/', views.support_list, name='support'),
    path('support/<uuid:request_id>/', views.support_detail, name='support-detail'),

    path('logs/', views.audit_logs, name='logs'),
    path('logs/logins/', views.login_attempts, name='login-attempts'),

    path('announcements/', views.announcements, name='announcements'),
    path('settings/', views.settings_system, name='settings'),
]
