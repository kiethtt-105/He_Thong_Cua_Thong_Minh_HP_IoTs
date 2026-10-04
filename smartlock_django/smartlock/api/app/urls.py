"""Route API v1 dùng chung cho APP (Bearer) và WEB (session cookie + CSRF) - gắn dưới /api/v1/ (xem api/urls.py)."""
from django.urls import path

from . import account, auth, cards, commands, devices, faces, history, notifications, pins, readers, shares

urlpatterns = [
    # ---------------- Xác thực (app) ----------------
    path('auth/csrf/', auth.csrf, name='csrf'),                                   # web: lấy CSRF cookie/token
    path('auth/register/', auth.register, name='register'),
    path('auth/login/', auth.login, name='login'),
    path('auth/2fa/verify/', auth.two_factor_verify, name='2fa-verify'),
    path('auth/2fa/email/send/', auth.two_factor_email_send, name='2fa-email-send'),
    path('auth/refresh/', auth.refresh, name='refresh'),
    path('auth/logout/', auth.logout, name='logout'),
    path('auth/resend-verification/', auth.resend_verification, name='resend-verification'),
    path('auth/password-reset/', auth.password_reset, name='password-reset'),
    path('auth/password-reset/confirm/', auth.password_reset_confirm, name='password-reset-confirm'),
    path('auth/verify-email/', auth.verify_email, name='verify-email'),

    # ---------------- Tài khoản ----------------
    path('me/', account.me, name='me'),
    path('me/password/', account.change_password, name='change-password'),
    path('me/sessions/', account.sessions_list, name='sessions'),
    path('me/sessions/<uuid:session_id>/', account.session_revoke, name='session-revoke'),
    path('me/push-token/', account.push_token, name='push-token'),
    path('me/two-factor/', account.two_factor_status, name='2fa-status'),
    path('bootstrap/', account.bootstrap, name='bootstrap'),

    # ---------------- Khoá ----------------
    path('devices/', devices.devices_list, name='devices'),
    path('devices/claim/', devices.device_claim, name='device-claim'),
    path('devices/<uuid:device_id>/', devices.device_detail, name='device-detail'),
    path('devices/<uuid:device_id>/live/', devices.device_live, name='device-live'),
    path('devices/<uuid:device_id>/commands/', commands.device_command, name='device-command'),            # POST gửi lệnh
    path('devices/<uuid:device_id>/commands/history/', commands.device_commands_list, name='device-commands'),
    path('commands/<uuid:command_id>/', commands.command_status, name='command-status'),
    path('devices/<uuid:device_id>/ble-ticket/', commands.device_ble_ticket, name='ble-ticket'),
    path('devices/<uuid:device_id>/nfc-ticket/', commands.device_nfc_ticket, name='nfc-ticket'),

    # ---------------- Mã PIN khách ----------------
    path('devices/<uuid:device_id>/pins/', pins.device_pins, name='device-pins'),
    path('pins/<uuid:pin_id>/', pins.pin_revoke, name='pin-revoke'),

    # ---------------- Thẻ NFC / đầu đọc ----------------
    path('cards/', cards.cards_list, name='cards'),
    path('cards/<uuid:card_id>/', cards.card_detail, name='card-detail'),
    path('cards/<uuid:card_id>/devices/<uuid:device_id>/', cards.card_link, name='card-link'),
    path('devices/<uuid:device_id>/cards/', cards.card_register, name='card-register'),
    path('devices/<uuid:device_id>/nfc-readers/', readers.device_readers, name='nfc-readers'),
    path('nfc-readers/<uuid:reader_id>/', readers.reader_detail, name='nfc-reader'),

    # ---------------- Khuôn mặt ----------------
    path('devices/<uuid:device_id>/faces/', faces.device_faces, name='device-faces'),
    path('faces/<uuid:profile_id>/', faces.face_delete, name='face-delete'),

    # ---------------- Chia sẻ khoá ----------------
    path('permissions/', shares.permissions_catalog, name='permissions'),
    path('devices/<uuid:device_id>/shares/', shares.device_shares, name='device-shares'),
    path('shares/incoming/', shares.shares_incoming, name='shares-incoming'),
    path('shares/<uuid:share_id>/', shares.share_detail, name='share-detail'),
    path('shares/<uuid:share_id>/leave/', shares.share_leave, name='share-leave'),

    # ---------------- Lịch sử / thông báo ----------------
    path('history/', history.access_history, name='history'),
    path('audit/', history.audit_logs, name='audit'),
    path('notifications/', notifications.notifications, name='notifications'),
    path('notifications/read/', notifications.notifications_read, name='notifications-read'),
    path('notifications/<uuid:notification_id>/', notifications.notification_delete, name='notification-delete'),
    path('events/', notifications.events_poll, name='events'),
]
