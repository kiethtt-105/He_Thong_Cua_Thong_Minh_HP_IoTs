# manage_sys/api/urls.py  -> được include tại  <MANAGE_SYS_URL_PREFIX>api/v1/
from django.urls import path

from . import announcements as ann, auth, dashboard, devices as dev, logs, settings_api, users as usr

app_name = 'manage_sys_api'

urlpatterns = [
    # --- auth ---
    path('auth/csrf/', auth.csrf_view, name='csrf'),
    path('auth/login/', auth.login_view, name='login'),
    path('auth/logout/', auth.logout_view, name='logout'),
    path('auth/refresh/', auth.refresh_view, name='refresh'),
    path('auth/me/', auth.me_view, name='me'),

    path('dashboard/', dashboard.dashboard_view, name='dashboard'),

    # --- users ---
    path('users/', usr.users_view, name='users'),
    path('users/<uuid:user_id>/', usr.user_detail_view, name='user-detail'),
    path('users/<uuid:user_id>/activate/', usr.user_activate_view, name='user-activate'),
    path('users/<uuid:user_id>/deactivate/', usr.user_deactivate_view, name='user-deactivate'),
    path('users/<uuid:user_id>/unlock/', usr.user_unlock_view, name='user-unlock'),
    path('users/<uuid:user_id>/reset-link/', usr.user_reset_link_view, name='user-reset-link'),
    path('users/<uuid:user_id>/grant-admin/', usr.user_grant_admin_view, name='user-grant-admin'),
    path('users/<uuid:user_id>/revoke-admin/', usr.user_revoke_admin_view, name='user-revoke-admin'),

    # --- devices ---
    path('devices/', dev.devices_view, name='devices'),
    path('devices/<uuid:device_id>/', dev.device_detail_view, name='device-detail'),
    path('devices/<uuid:device_id>/link/', dev.device_link_view, name='device-link'),
    path('devices/<uuid:device_id>/maintenance/', dev.device_maintenance_view, name='device-maintenance'),
    path('devices/<uuid:device_id>/ping/', dev.device_ping_view, name='device-ping'),
    path('devices/<uuid:device_id>/claim/', dev.device_claim_view, name='device-claim'),
    path('devices/<uuid:device_id>/remove-owner/', dev.device_remove_owner_view, name='device-remove-owner'),
    path('devices/<uuid:device_id>/rotate-secret/', dev.device_rotate_secret_view, name='device-rotate-secret'),

    # --- logs ---
    path('logs/', logs.audit_logs_view, name='logs'),
    path('logs/logins/', logs.login_attempts_view, name='login-attempts'),

    # --- announcements / settings ---
    path('announcements/', ann.announcements_view, name='announcements'),
    path('announcements/<uuid:announcement_id>/', ann.announcement_detail_view, name='announcement-detail'),
    path('announcements/<uuid:announcement_id>/active/', ann.announcement_active_view, name='announcement-active'),
    path('settings/', settings_api.settings_view, name='settings'),
]
