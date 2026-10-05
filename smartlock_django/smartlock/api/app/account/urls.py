"""Tài khoản của tôi - /api/app/me/..., /api/app/bootstrap/"""
from django.urls import path

from . import views as account

urlpatterns = [
    path('me/', account.me, name='me'),
    path('me/password/', account.change_password, name='change-password'),
    path('me/sessions/', account.sessions_list, name='sessions'),
    path('me/sessions/<uuid:session_id>/', account.session_revoke, name='session-revoke'),
    path('me/push-token/', account.push_token, name='push-token'),
    path('me/two-factor/', account.two_factor_status, name='2fa-status'),
    path('bootstrap/', account.bootstrap, name='bootstrap'),
]
