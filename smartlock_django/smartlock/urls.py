from django.urls import path
from . import views

app_name = 'smartlock'

urlpatterns = [
    # ====================== ADMIN-SYS (Admin riêng) ======================
    path('admin-sys/login/', views.admin_login, name='admin-sys-login'),
    path('admin-sys/logout/', views.admin_logout, name='admin-sys-logout'),
    path('admin-sys/dashboard/', views.admin_dashboard, name='admin-sys-dashboard'),
    path('admin-sys/users/', views.admin_users_list, name='admin-sys-users-list'),
    path('admin-sys/users/<uuid:user_id>/', views.admin_user_detail, name='admin-sys-user-detail'),
    path('admin-sys/devices/', views.admin_devices_list, name='admin-sys-devices-list'),
    path('admin-sys/devices/<uuid:device_id>/', views.admin_device_detail, name='admin-sys-device-detail'),
    path('admin-sys/support/', views.admin_support_requests, name='admin-sys-support-requests'),
    path('admin-sys/support/<uuid:request_id>/', views.admin_support_request_detail, name='admin-sys-support-request-detail'),
    path('admin-sys/logs/', views.admin_audit_logs, name='admin-sys-audit-logs'),
    path('admin-sys/settings/', views.admin_settings_system, name='admin-sys-settings-system'),

    # ====================== USER ROUTES (User thường) ======================
    path('', views.dashboard, name='dashboard'),
    path('login/', views.login_view, name='login'),                    # User thường
    path('logout/', views.logout_view, name='logout'),
    path('register/', views.register, name='register'),
    path('verify-email/resend/', views.resend_verification, name='resend_verification'),
    path('verify-email/<uuid:token>/', views.verify_email, name='verify_email'),
    path('password-reset/', views.password_reset_request, name='password_reset'),
    path('reset-password/<uidb64>/<token>/', views.reset_password, name='reset_password_confirm'),

    path('devices/', views.devices_list, name='devices-list'),
    path('devices/<uuid:device_id>/', views.device_detail, name='device-detail'),
    path('devices/add/', views.device_add, name='device-add'),
    path('devices/<uuid:device_id>/command/', views.device_command, name='device-command'),

    path('nfc/tags/', views.nfc_tags, name='nfc-tags'),
    path('nfc/reader/', views.nfc_reader, name='nfc-reader'),

    path('share/codes/', views.share_codes, name='share-codes'),
    path('share/request/', views.share_request, name='share-request'),

    path('support/requests/', views.support_requests, name='support-requests'),
    path('support/requests/<uuid:request_id>/', views.support_request_detail, name='support-request-detail'),

    path('permissions/manage/', views.permissions_manage, name='permissions-manage'),
    path('settings/system/', views.settings_system, name='settings-system'),
    path('notifications/', views.notifications_list, name='notifications'),
    path('profile/', views.profile, name='profile'),
    path('audit/logs/', views.audit_logs, name='audit-logs'),
]