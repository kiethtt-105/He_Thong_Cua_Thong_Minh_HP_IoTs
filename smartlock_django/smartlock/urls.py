from django.urls import path
from . import views

app_name = 'smartlock'

urlpatterns = [
    # ====================== ADMIN-SYS (Admin riêng – tên khác) ======================
    path('manage-sys/login/', views.login_view, name='manage-sys-login'),
    path('manage-sys/logout/', views.manage_logout, name='manage-sys-logout'),
    path('manage-sys/dashboard/', views.manage_dashboard, name='manage-sys-dashboard'),
    path('manage-sys/users/', views.manage_users_list, name='manage-sys-users-list'),
    path('manage-sys/users/<uuid:user_id>/', views.manage_user_detail, name='manage-sys-user-detail'),
    path('manage-sys/devices/', views.manage_devices_list, name='manage-sys-devices-list'),
    path('manage-sys/devices/<uuid:device_id>/', views.manage_device_detail, name='manage-sys-device-detail'),
    path('manage-sys/support/', views.manage_support_requests, name='manage-sys-support-requests'),
    path('manage-sys/support/<uuid:request_id>/', views.manage_support_request_detail, name='manage-sys-support-request-detail'),
    path('manage-sys/logs/', views.manage_audit_logs, name='manage-sys-audit-logs'),
    path('manage-sys/settings/', views.manage_settings_system, name='manage-sys-settings-system'),

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