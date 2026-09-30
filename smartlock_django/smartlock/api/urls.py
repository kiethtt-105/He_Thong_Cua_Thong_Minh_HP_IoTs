# smartlock/api/urls.py  —  gắn tại /api/v1/ (xem smartlock/urls.py)
from django.urls import path

from . import auth_views as a
from . import views as v

urlpatterns = [
    # ---------- Công khai ----------
    path('app/config/', v.AppConfigView.as_view(), name='api-app-config'),

    # ---------- Xác thực ----------
    path('auth/register/', a.RegisterView.as_view(), name='api-register'),
    path('auth/resend-verification/', a.ResendVerificationView.as_view(), name='api-resend-verification'),
    path('auth/login/', a.LoginView.as_view(), name='api-login'),
    path('auth/2fa/send-email/', a.TwoFactorSendEmailView.as_view(), name='api-2fa-send-email'),
    path('auth/2fa/verify/', a.TwoFactorVerifyView.as_view(), name='api-2fa-verify'),
    path('auth/refresh/', a.RefreshView.as_view(), name='api-refresh'),
    path('auth/logout/', a.LogoutView.as_view(), name='api-logout'),
    path('auth/logout-all/', a.LogoutAllView.as_view(), name='api-logout-all'),
    path('auth/password/forgot/', a.ForgotPasswordView.as_view(), name='api-password-forgot'),
    path('auth/password/change/', a.ChangePasswordView.as_view(), name='api-password-change'),

    # ---------- Tài khoản & phiên ----------
    path('me/', v.MeView.as_view(), name='api-me'),
    path('me/sessions/', v.SessionListView.as_view(), name='api-sessions'),
    path('me/sessions/<uuid:session_id>/', v.SessionDetailView.as_view(), name='api-session-detail'),
    path('me/push-token/', v.PushTokenView.as_view(), name='api-push-token'),

    # ---------- Đồng bộ ----------
    path('sync/', v.SyncView.as_view(), name='api-sync'),

    # ---------- Thiết bị ----------
    path('devices/', v.DeviceListCreateView.as_view(), name='api-devices'),
    path('devices/<uuid:device_id>/', v.DeviceDetailView.as_view(), name='api-device-detail'),
    path('devices/<uuid:device_id>/command/', v.DeviceCommandView.as_view(), name='api-device-command'),
    path('devices/<uuid:device_id>/status-history/', v.DeviceStatusHistoryView.as_view(), name='api-device-status'),
    path('devices/<uuid:device_id>/access-events/', v.DeviceAccessEventsView.as_view(), name='api-device-events'),
    path('commands/<uuid:command_id>/', v.CommandDetailView.as_view(), name='api-command-detail'),

    # ---------- Chia sẻ & quyền ----------
    path('permissions/', v.PermissionListView.as_view(), name='api-permissions'),
    path('share/codes/', v.ShareCodeListCreateView.as_view(), name='api-share-codes'),
    path('share/codes/<uuid:code_id>/', v.ShareCodeDetailView.as_view(), name='api-share-code-detail'),
    path('share/redeem/', v.ShareRedeemView.as_view(), name='api-share-redeem'),
    path('share/my-accesses/', v.MyAccessListView.as_view(), name='api-my-accesses'),
    path('share/my-accesses/<uuid:access_id>/', v.MyAccessDetailView.as_view(), name='api-my-access-detail'),
    path('devices/<uuid:device_id>/accesses/', v.DeviceAccessListView.as_view(), name='api-device-accesses'),
    path('devices/<uuid:device_id>/accesses/<uuid:access_id>/', v.DeviceAccessDetailView.as_view(),
         name='api-device-access-detail'),

    # ---------- PIN khách / khuôn mặt / thẻ ----------
    path('devices/<uuid:device_id>/door-pins/', v.DoorPinListCreateView.as_view(), name='api-door-pins'),
    path('devices/<uuid:device_id>/door-pins/<uuid:pin_id>/revoke/', v.DoorPinRevokeView.as_view(),
         name='api-door-pin-revoke'),
    path('devices/<uuid:device_id>/face-profiles/', v.FaceProfileListCreateView.as_view(), name='api-face-profiles'),
    path('devices/<uuid:device_id>/face-profiles/<uuid:profile_id>/', v.FaceProfileDetailView.as_view(),
         name='api-face-profile-detail'),
    path('cards/', v.CardListCreateView.as_view(), name='api-cards'),
    path('cards/<uuid:card_id>/', v.CardDetailView.as_view(), name='api-card-detail'),

    # ---------- Tự động hoá ----------
    path('automation-rules/meta/', v.RuleMetaView.as_view(), name='api-rule-meta'),
    path('automation-rules/', v.RuleListCreateView.as_view(), name='api-rules'),
    path('automation-rules/<uuid:rule_id>/', v.RuleDetailView.as_view(), name='api-rule-detail'),
    path('automation-rules/<uuid:rule_id>/logs/', v.RuleLogListView.as_view(), name='api-rule-logs'),

    # ---------- Thông báo / nhật ký ----------
    path('notifications/', v.NotificationListView.as_view(), name='api-notifications'),
    path('notifications/unread-count/', v.NotificationUnreadCountView.as_view(), name='api-notif-unread'),
    path('notifications/read-all/', v.NotificationReadAllView.as_view(), name='api-notif-read-all'),
    path('notifications/<uuid:notification_id>/', v.NotificationDetailView.as_view(), name='api-notif-detail'),
    path('announcements/', v.AnnouncementListView.as_view(), name='api-announcements'),
    path('audit-logs/', v.AuditLogListView.as_view(), name='api-audit-logs'),
]
