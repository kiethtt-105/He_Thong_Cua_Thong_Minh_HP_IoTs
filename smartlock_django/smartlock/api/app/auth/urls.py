"""Xác thực (app + web) - /api/app/auth/..."""
from django.urls import path

from . import views as auth

urlpatterns = [
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
    path('auth/password-reset/confirm/', auth.password_reset_confirm, name='password-reset-confirm'),
    path('auth/verify-email/', auth.verify_email, name='verify-email'),
]
