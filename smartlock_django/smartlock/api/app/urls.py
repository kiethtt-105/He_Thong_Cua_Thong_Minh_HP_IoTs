"""Route API dùng chung cho APP (Bearer) và WEB (session cookie + CSRF) - gắn dưới /api/app/ (xem api/urls.py).

Giữ nguyên name= của route (namespace 'smartlock_api') nên template {% url 'smartlock_api:...' %} không đổi.
"""
from django.urls import path

from . import access, account, activity, auth, devices
from . import two_factor as tf

urlpatterns = [
    # ---------------- auth ----------------
    path('auth/csrf/', auth.csrf, name='csrf'),                                   # web: lấy CSRF cookie/token
    path('auth/register/', auth.register, name='register'),
    path('auth/login/', auth.login, name='login'),
    path('auth/2fa/verify/', auth.two_factor_verify, name='2fa-verify'),
    path('auth/2fa/email/send/', auth.two_factor_email_send, name='2fa-email-send'),
    path('auth/2fa/passkey/options/', auth.two_factor_passkey_options, name='2fa-passkey-options'),   # web
    path('auth/2fa/passkey/finish/', auth.two_factor_passkey_finish, name='2fa-passkey-finish'),     # web
    path('auth/refresh/', auth.refresh, name='refresh'),
    path('auth/logout/', auth.logout, name='logout'),
    path('auth/resend-verification/', auth.resend_verification, name='resend-verification'),
    path('auth/password-reset/', auth.password_reset, name='password-reset'),
    path('auth/password-reset/check/', auth.password_reset_check, name='password-reset-check'),
    path('auth/password-reset/confirm/', auth.password_reset_confirm, name='password-reset-confirm'),
    path('auth/verify-email/', auth.verify_email, name='verify-email'),

    # ---------------- account  /me, /bootstrap, /snapshot ----------------
    path('me/', account.me, name='me'),
    path('me/password/', account.change_password, name='change-password'),
    path('me/sessions/', account.sessions_list, name='sessions'),
    path('me/sessions/<uuid:session_id>/', account.session_revoke, name='session-revoke'),
    path('me/push-token/', account.push_token, name='push-token'),
    path('me/two-factor/', account.two_factor_status, name='2fa-status'),
    path('me/two-factor/totp/begin/', tf.totp_begin, name='2fa-totp-begin'),
    path('me/two-factor/totp/confirm/', tf.totp_confirm, name='2fa-totp-confirm'),
    path('me/two-factor/email/send/', tf.email_send, name='2fa-setup-email-send'),
    path('me/two-factor/email/confirm/', tf.email_confirm, name='2fa-setup-email-confirm'),
    path('me/two-factor/passkey/options/', tf.passkey_options, name='2fa-setup-passkey-options'),     # web
    path('me/two-factor/passkey/register/', tf.passkey_register, name='2fa-setup-passkey-register'),  # web
    path('me/two-factor/passkeys/<uuid:cred_id>/remove/', tf.passkey_remove, name='2fa-passkey-remove'),
    path('me/two-factor/methods/<str:method>/remove/', tf.method_remove, name='2fa-method-remove'),
    path('bootstrap/', account.bootstrap, name='bootstrap'),
    path('snapshot/', account.snapshot, name='snapshot'),      # toàn bộ dữ liệu của user (ETag/304) - web poll 2-5s

    # ---------------- devices  khoá + lệnh ----------------
    path('devices/', devices.devices_list, name='devices'),
    path('devices/claim/', devices.device_claim, name='device-claim'),
    path('devices/<uuid:device_id>/', devices.device_detail, name='device-detail'),
    path('devices/<uuid:device_id>/live/', devices.device_live, name='device-live'),
    path('devices/<uuid:device_id>/commands/', devices.device_command, name='device-command'),            # POST gửi lệnh
    path('devices/<uuid:device_id>/commands/history/', devices.device_commands_list, name='device-commands'),
    path('commands/<uuid:command_id>/', devices.command_status, name='command-status'),
    path('devices/<uuid:device_id>/ble-ticket/', devices.device_ble_ticket, name='ble-ticket'),
    path('devices/<uuid:device_id>/nfc-ticket/', devices.device_nfc_ticket, name='nfc-ticket'),


    # ---------------- Mã PIN khách ----------------
    # ---------------- access  PIN · thẻ · mặt · chia sẻ ----------------
    path('devices/<uuid:device_id>/pins/', access.device_pins, name='device-pins'),
    path('pins/<uuid:pin_id>/', access.pin_revoke, name='pin-revoke'),

    # ---------------- Thẻ NFC / đầu đọc ----------------
    path('cards/', access.cards_list, name='cards'),
    path('cards/<uuid:card_id>/', access.card_detail, name='card-detail'),
    path('cards/<uuid:card_id>/devices/<uuid:device_id>/', access.card_link, name='card-link'),
    path('devices/<uuid:device_id>/cards/', access.card_register, name='card-register'),
    path('devices/<uuid:device_id>/nfc-readers/', access.device_readers, name='nfc-readers'),
    path('nfc-readers/<uuid:reader_id>/', access.reader_detail, name='nfc-reader'),

    # ---------------- Khuôn mặt ----------------
    path('devices/<uuid:device_id>/faces/', access.device_faces, name='device-faces'),
    path('faces/<uuid:profile_id>/', access.face_delete, name='face-delete'),

    # ---------------- Chia sẻ khoá ----------------
    path('permissions/', access.permissions_catalog, name='permissions'),
    path('devices/<uuid:device_id>/shares/', access.device_shares, name='device-shares'),
    path('shares/incoming/', access.shares_incoming, name='shares-incoming'),
    path('shares/<uuid:share_id>/', access.share_detail, name='share-detail'),
    path('shares/<uuid:share_id>/leave/', access.share_leave, name='share-leave'),

    # ---------------- activity  lịch sử · thông báo ----------------
    path('history/', activity.access_history, name='history'),
    path('audit/', activity.audit_logs, name='audit'),
    path('notifications/', activity.notifications, name='notifications'),
    path('notifications/read/', activity.notifications_read, name='notifications-read'),
    path('notifications/<uuid:notification_id>/', activity.notification_delete, name='notification-delete'),
    path('events/', activity.events_poll, name='events'),
    path('announcements/', activity.announcements, name='announcements'),
]
