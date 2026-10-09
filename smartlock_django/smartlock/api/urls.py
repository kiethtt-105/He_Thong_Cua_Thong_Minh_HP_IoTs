"""TẤT CẢ route API ở một nơi. Gắn vào urls gốc của project:  path('api/', include('smartlock.api.urls'))

    /api/app/...       NGƯỜI DÙNG: APP (Bearer) + WEB (cookie + CSRF)   -> account.py (tài khoản) · locks.py (khoá)
    /api/device/...    KHOÁ (firmware; X-Device-Code + Secret)          -> device.py
    /api/webhooks/...  broker MQTT gọi vào (X-Webhook-Secret)           -> device.py
    /api/system/...    công khai: health, config                        -> device.py

Giữ nguyên namespace 'smartlock_api' và name= của route cũ => template {% url 'smartlock_api:...' %} không đổi.
"""
from django.urls import include, path

from . import account as acc, device as dev, locks

app_name = 'smartlock_api'

app_patterns = [
    # ---------- xác thực ----------
    path('auth/csrf/', acc.csrf, name='csrf'),
    path('auth/register/', acc.register, name='register'),
    path('auth/login/', acc.login, name='login'),
    path('auth/2fa/verify/', acc.two_factor_verify, name='2fa-verify'),
    path('auth/2fa/email/send/', acc.two_factor_email_send, name='2fa-email-send'),
    path('auth/2fa/passkey/options/', acc.two_factor_passkey_options, name='2fa-passkey-options'),   # web
    path('auth/2fa/passkey/finish/', acc.two_factor_passkey_finish, name='2fa-passkey-finish'),     # web
    path('auth/refresh/', acc.refresh, name='refresh'),
    path('auth/logout/', acc.logout, name='logout'),
    path('auth/resend-verification/', acc.resend_verification, name='resend-verification'),
    path('auth/password-reset/', acc.password_reset, name='password-reset'),
    path('auth/password-reset/check/', acc.password_reset_check, name='password-reset-check'),
    path('auth/password-reset/confirm/', acc.password_reset_confirm, name='password-reset-confirm'),
    path('auth/verify-email/', acc.verify_email, name='verify-email'),

    # ---------- tài khoản ----------
    path('me/', acc.me, name='me'),                                                 # GET · PATCH · DELETE (xoá tài khoản)
    path('me/export/', locks.me_export, name='me-export'),                           # tải dữ liệu cá nhân (JSON)
    path('me/password/', acc.change_password, name='change-password'),
    path('me/sessions/', acc.sessions_list, name='sessions'),                       # GET danh sách · DELETE đăng xuất mọi phiên khác
    path('me/sessions/<uuid:session_id>/', acc.session_revoke, name='session-revoke'),
    path('me/push-token/', acc.push_token, name='push-token'),
    path('me/two-factor/', acc.two_factor_status, name='2fa-status'),
    path('me/two-factor/totp/begin/', acc.totp_begin, name='2fa-totp-begin'),
    path('me/two-factor/totp/confirm/', acc.totp_confirm, name='2fa-totp-confirm'),
    path('me/two-factor/email/send/', acc.email_send, name='2fa-setup-email-send'),
    path('me/two-factor/email/confirm/', acc.email_confirm, name='2fa-setup-email-confirm'),
    path('me/two-factor/passkey/options/', acc.passkey_options, name='2fa-setup-passkey-options'),      # web
    path('me/two-factor/passkey/register/', acc.passkey_register, name='2fa-setup-passkey-register'),   # web
    path('me/two-factor/passkeys/<uuid:cred_id>/remove/', acc.passkey_remove, name='2fa-passkey-remove'),
    path('me/two-factor/methods/<str:method>/remove/', acc.method_remove, name='2fa-method-remove'),

    # ---------- dữ liệu tổng hợp ----------
    path('bootstrap/', locks.bootstrap, name='bootstrap'),
    path('snapshot/', locks.snapshot, name='snapshot'),                            # toàn bộ dữ liệu của user (ETag/304)

    # ---------- khoá + lệnh ----------
    path('devices/', locks.devices_list, name='devices'),
    path('devices/claim/', locks.device_claim, name='device-claim'),
    path('devices/<uuid:device_id>/', locks.device_detail, name='device-detail'),   # GET · PATCH · DELETE (gỡ khoá)
    path('devices/<uuid:device_id>/live/', locks.device_live, name='device-live'),
    path('devices/<uuid:device_id>/status-history/', locks.device_status_history, name='device-status-history'),
    path('devices/<uuid:device_id>/commands/', locks.device_command, name='device-command'),
    path('devices/<uuid:device_id>/commands/history/', locks.device_commands_list, name='device-commands'),
    path('commands/<uuid:command_id>/', locks.command_status, name='command-status'),
    path('devices/<uuid:device_id>/ble-ticket/', locks.device_ble_ticket, name='ble-ticket'),
    path('devices/<uuid:device_id>/nfc-ticket/', locks.device_nfc_ticket, name='nfc-ticket'),
    path('devices/<uuid:device_id>/rotate-secret/', locks.device_rotate_secret, name='device-rotate-secret'),
    path('devices/<uuid:device_id>/clear-lockout/', locks.device_clear_lockout, name='device-clear-lockout'),

    # ---------- PIN khách · thẻ NFC · đầu đọc · khuôn mặt ----------
    path('devices/<uuid:device_id>/pins/', locks.device_pins, name='device-pins'),
    path('pins/<uuid:pin_id>/', locks.pin_revoke, name='pin-revoke'),               # PATCH nhãn/gia hạn · DELETE thu hồi
    path('cards/', locks.cards_list, name='cards'),
    path('cards/<uuid:card_id>/', locks.card_detail, name='card-detail'),
    path('cards/<uuid:card_id>/devices/<uuid:device_id>/', locks.card_link, name='card-link'),
    path('devices/<uuid:device_id>/cards/', locks.card_register, name='card-register'),
    path('devices/<uuid:device_id>/nfc-readers/', locks.device_readers, name='nfc-readers'),
    path('nfc-readers/<uuid:reader_id>/', locks.reader_detail, name='nfc-reader'),
    path('nfc-logs/', locks.nfc_logs, name='nfc-logs'),
    path('devices/<uuid:device_id>/faces/', locks.device_faces, name='device-faces'),
    path('faces/<uuid:profile_id>/', locks.face_delete, name='face-delete'),

    # ---------- chia sẻ khoá ----------
    path('permissions/', locks.permissions_catalog, name='permissions'),
    path('devices/<uuid:device_id>/shares/', locks.device_shares, name='device-shares'),
    path('shares/incoming/', locks.shares_incoming, name='shares-incoming'),
    path('shares/<uuid:share_id>/', locks.share_detail, name='share-detail'),       # PATCH quyền / gia hạn · DELETE thu hồi
    path('shares/<uuid:share_id>/leave/', locks.share_leave, name='share-leave'),

    # ---------- lịch sử · thông báo ----------
    path('history/', locks.access_history, name='history'),
    path('audit/', locks.audit_logs, name='audit'),
    path('notifications/', locks.notifications, name='notifications'),
    path('notifications/read/', locks.notifications_read, name='notifications-read'),
    path('notifications/<uuid:notification_id>/', locks.notification_delete, name='notification-delete'),
    path('events/', locks.events_poll, name='events'),
    path('announcements/', locks.announcements, name='announcements'),
]

device_patterns = [
    path('config/', dev.dev_config, name='dev-config'),
    path('heartbeat/', dev.heartbeat, name='dev-heartbeat'),
    path('commands/', dev.commands, name='dev-commands'),
    path('ack/', dev.ack, name='dev-ack'),
    path('access/rfid/', dev.access_rfid, name='dev-access-rfid'),
    path('access/pin/', dev.access_pin, name='dev-access-pin'),
    path('access/face/', dev.access_face, name='dev-access-face'),
    path('access/phone/', dev.access_phone, name='dev-access-phone'),
    path('events/', dev.event, name='dev-event'),                                   # 1 sự kiện hoặc lô offline
    path('ota/', dev.ota_report, name='dev-ota'),
]

webhook_patterns = [
    path('mqtt/auth/', dev.mqtt_auth, name='webhook-mqtt-auth'),
    path('mqtt/acl/', dev.mqtt_acl, name='webhook-mqtt-acl'),
]

system_patterns = [
    path('health/', dev.health, name='system-health'),
    path('config/', dev.system_config, name='system-config'),
]

urlpatterns = [
    path('app/', include(app_patterns)),
    path('device/', include(device_patterns)),
    path('webhooks/', include(webhook_patterns)),
    path('system/', include(system_patterns)),
]
