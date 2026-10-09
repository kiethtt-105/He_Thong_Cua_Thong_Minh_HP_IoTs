# smartlock/urls.py

from django.urls import path
from . import views

app_name = 'smartlock'

urlpatterns = [
    path('', views.dashboard, name='dashboard'),
    path('login/', views.login_view, name='login'),
    path('logout/', views.logout_view, name='logout'),
    path('register/', views.register, name='register'),
    path('verify-email/<uuid:token>/', views.verify_email, name='verify_email'),
    path('password-reset/', views.password_reset_request, name='password_reset'),
    path('reset-password/<uidb64>/<token>/', views.reset_password, name='reset_password_confirm'),

    path('devices/', views.devices_list, name='devices-list'),
    path('devices/claim/', views.device_claim, name='device-claim'),
    path('devices/<uuid:device_id>/', views.device_detail, name='device-detail'),
    path('devices/<uuid:device_id>/live/', views.live_page, name='device-live'),

    path('nfc/tags/', views.nfc_tags, name='nfc-tags'),
    path('nfc/reader/', views.nfc_reader, name='nfc-reader'),
    path('access/door-pins/', views.door_pins, name='door-pins'),
    path('access/face-profiles/', views.face_profiles, name='face-profiles'),
    path('access/history/', views.access_events_history, name='access-history'),
    path('shares/', views.shares_manage, name='shares'),

    path('notifications/', views.notifications_list, name='notifications'),
    path('profile/', views.profile, name='profile'),
    path('audit/logs/', views.audit_logs, name='audit-logs'),


    path('demo/system-logs/', views.public_system_logs, name='public-system-logs'),
    path('demo/system-logs/data/', views.public_system_logs_api, name='public-system-logs-data'),
    path('demo/system-logs/overview/', views.overview_api, name='sysview-overview'),
    path('demo/system-logs/events/', views.events_api, name='sysview-events'),
    path('demo/system-logs/db/tables/', views.db_tables_api, name='sysview-db-tables'),
    path('demo/system-logs/api/', views.api_api, name='sysview-api'),
    path('demo/system-logs/channels/', views.channels_api, name='sysview-channels'),
    path('demo/system-logs/db/rows/', views.db_rows_api, name='sysview-db-rows'),
]
