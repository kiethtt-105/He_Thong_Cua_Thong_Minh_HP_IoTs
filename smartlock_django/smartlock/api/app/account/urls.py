"""Tài khoản của tôi - /api/app/me/..., /api/app/bootstrap/"""
from django.urls import path

from . import two_factor as tf
from . import views as account

urlpatterns = [
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
]
