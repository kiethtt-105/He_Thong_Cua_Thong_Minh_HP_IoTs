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
    path('devices/add/', views.device_add, name='device-add'),         # ĐÃ ĐÓNG: chuyển sang device-claim (chỉ admin tạo khoá)
    path('devices/claim/', views.device_claim, name='device-claim'),   # user tự thêm khoá bằng code + secret
    path('devices/<uuid:device_id>/command/', views.device_command, name='device-command'),
    path('devices/<uuid:device_id>/ble-ticket/', views.device_ble_ticket, name='device-ble-ticket'),   # app: vé Bluetooth
    path('devices/<uuid:device_id>/nfc-ticket/', views.device_nfc_ticket, name='device-nfc-ticket'),   # app: vé NFC giả lập thẻ

    path('devices/<uuid:device_id>/live/', views.live_page, name='device-live'),
    path('devices/<uuid:device_id>/live/data/', views.live_data, name='device-live-data'),

    # ====================== SYNC: cache mã hoá về máy sau login ======================
    path('api/sync/', views.sync_bootstrap, name='sync-bootstrap'),

    # ====================== MQTT (server-to-server, không phải route cho người dùng) ======================
    path('api/mqtt/auth/', views.mqtt_auth_webhook, name='mqtt-auth'),
    path('api/mqtt/acl/', views.mqtt_acl_webhook, name='mqtt-acl'),

    path('nfc/tags/', views.nfc_tags, name='nfc-tags'),
    path('nfc/reader/', views.nfc_reader, name='nfc-reader'),
    path('access/door-pins/', views.door_pins, name='door-pins'),
    path('access/face-profiles/', views.face_profiles, name='face-profiles'),
    path('access/face-profiles/enroll/', views.face_enroll, name='face-enroll'),   # quét camera -> JSON (không nhập vector)
    path('access/face-profiles/<uuid:profile_id>/delete/', views.face_profile_delete, name='face-profile-delete'),
    path('access/history/', views.access_events_history, name='access-history'),

    # Chia sẻ khoá: chủ nhập email/username + chọn quyền -> có hiệu lực ngay, người nhận được báo qua email + app.
    path('shares/', views.shares_manage, name='shares'),

    path('notifications/', views.notifications_list, name='notifications'),
    path('api/events/', views.events_poll, name='events'),          # popup trong trang (poll)
    path('profile/', views.profile, name='profile'),
    path('audit/logs/', views.audit_logs, name='audit-logs'),

    # ====================== DEMO: xem toàn bộ log hệ thống real-time, KHÔNG cần đăng nhập ======================
    # Chỉ dùng khi demo/bảo vệ đồ án - nhớ gỡ hoặc chặn route này trước khi deploy thật.
    path('demo/system-logs/', views.public_system_logs, name='public-system-logs'),
    path('demo/system-logs/data/', views.public_system_logs_api, name='public-system-logs-data'),

    # ====================== 2FA ======================
    path('two-factor/verify/', views.verify_2fa, name='tf-verify'),
    path('two-factor/verify/email/send/', views.verify_email_send, name='tf-verify-email-send'),
    path('two-factor/verify/passkey/options/', views.verify_passkey_options, name='tf-verify-passkey-options'),
    path('two-factor/verify/passkey/finish/', views.verify_passkey_finish, name='tf-verify-passkey-finish'),
    path('two-factor/cancel/', views.cancel_2fa, name='tf-cancel'),

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

]