from django.urls import path
from . import views

app_name = 'smartlock'

urlpatterns = [
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

    # ====================== SYNC: cache mã hoá về máy sau login ======================
    path('api/sync/', views.sync_bootstrap, name='sync-bootstrap'),

    # ====================== MQTT (server-to-server, không phải route cho người dùng) ======================
    path('api/mqtt/auth/', views.mqtt_auth_webhook, name='mqtt-auth'),

    path('nfc/tags/', views.nfc_tags, name='nfc-tags'),
    path('nfc/reader/', views.nfc_reader, name='nfc-reader'),

    path('share/codes/', views.share_codes, name='share-codes'),
    path('share/request/', views.share_request, name='share-request'),

    path('support/requests/', views.support_requests, name='support-requests'),
    path('support/requests/<uuid:request_id>/', views.support_request_detail, name='support-request-detail'),

    path('permissions/manage/', views.permissions_manage, name='permissions-manage'),
    path('automation-rules/', views.automation_rules_manage, name='automation-rules'),
    path('settings/system/', views.settings_system, name='settings-system'),
    path('settings/announcements/', views.announcements_manage, name='announcements-manage'),
    path('notifications/', views.notifications_list, name='notifications'),
    path('profile/', views.profile, name='profile'),
    path('audit/logs/', views.audit_logs, name='audit-logs'),

    # ====================== 2FA ======================
    # Trang xác thực (login / bật / tắt) - chỉ vào được khi có phiên pending_2fa
    path('two-factor/verify/', views.verify_2fa, name='tf-verify'),
    path('two-factor/verify/email/send/', views.verify_email_send, name='tf-verify-email-send'),
    path('two-factor/verify/passkey/options/', views.verify_passkey_options, name='tf-verify-passkey-options'),
    path('two-factor/verify/passkey/finish/', views.verify_passkey_finish, name='tf-verify-passkey-finish'),
    path('two-factor/cancel/', views.cancel_2fa, name='tf-cancel'),

    # Cài đặt 2FA (từ trang profile)
    path('two-factor/enable/', views.enable_2fa, name='tf-enable'),
    path('two-factor/disable/', views.disable_2fa, name='tf-disable'),
    path('two-factor/totp/begin/', views.totp_begin, name='tf-totp-begin'),
    path('two-factor/totp/confirm/', views.totp_confirm, name='tf-totp-confirm'),
    path('two-factor/totp/cancel/', views.totp_cancel, name='tf-totp-cancel'),
    path('two-factor/email/send/', views.email_send, name='tf-email-send'),
    path('two-factor/email/confirm/', views.email_confirm, name='tf-email-confirm'),
    path('two-factor/passkey/options/', views.passkey_register_options, name='tf-passkey-options'),
    path('two-factor/passkey/register/', views.passkey_register, name='tf-passkey-register'),
    path('two-factor/passkey/<uuid:cred_id>/delete/', views.passkey_delete, name='tf-passkey-delete'),
    path('two-factor/remove/<str:method>/', views.remove_method, name='tf-remove-method'),
    path('two-factor/backup/regenerate/', views.backup_regenerate, name='tf-backup-regenerate'),
]