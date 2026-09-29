# smartlock/api/urls.py
from django.urls import path
from django.views.decorators.csrf import ensure_csrf_cookie

from . import views as v

app_name = 'api'

urlpatterns = [
    path('csrf/', ensure_csrf_cookie(v.CsrfView.as_view()), name='csrf'),
    path('meta/', v.MetaView.as_view(), name='meta'),

    # tài khoản / tổng quan
    path('me/', v.MeView.as_view(), name='me'),
    path('me/password/', v.ChangePasswordView.as_view(), name='change-password'),
    path('dashboard/', v.DashboardView.as_view(), name='dashboard'),
    path('announcements/', v.AnnouncementListView.as_view(), name='announcements'),

    # thiết bị
    path('devices/', v.DeviceListCreateView.as_view(), name='devices'),
    path('devices/<uuid:device_id>/', v.DeviceDetailView.as_view(), name='device-detail'),
    path('devices/<uuid:device_id>/status-logs/', v.DeviceStatusLogListView.as_view(), name='device-status-logs'),
    path('devices/<uuid:device_id>/command/', v.DeviceCommandView.as_view(), name='device-command'),
    path('devices/<uuid:device_id>/commands/', v.DeviceCommandListView.as_view(), name='device-commands'),
    path('devices/<uuid:device_id>/commands/<uuid:command_id>/', v.DeviceCommandDetailView.as_view(),
         name='device-command-detail'),

    # phân quyền & chia sẻ
    path('permissions/', v.PermissionListView.as_view(), name='permissions'),
    path('devices/<uuid:device_id>/accesses/', v.DeviceAccessListCreateView.as_view(), name='device-accesses'),
    path('devices/<uuid:device_id>/accesses/<uuid:access_id>/', v.DeviceAccessDetailView.as_view(),
         name='device-access-detail'),
    path('my-accesses/', v.MyAccessListView.as_view(), name='my-accesses'),
    path('share-codes/', v.ShareCodeListCreateView.as_view(), name='share-codes'),
    path('share-codes/redeem/', v.ShareCodeRedeemView.as_view(), name='share-code-redeem'),
    path('share-codes/<uuid:code_id>/', v.ShareCodeDetailView.as_view(), name='share-code-detail'),

    # NFC / thẻ
    path('devices/<uuid:device_id>/nfc-readers/', v.NfcReaderListCreateView.as_view(), name='nfc-readers'),
    path('devices/<uuid:device_id>/nfc-readers/<uuid:reader_id>/', v.NfcReaderDetailView.as_view(),
         name='nfc-reader-detail'),
    path('devices/<uuid:device_id>/nfc-logs/', v.NfcLogListView.as_view(), name='nfc-logs'),
    path('devices/<uuid:device_id>/nfc-cards/', v.NfcCardRegisterView.as_view(), name='nfc-card-register'),
    path('nfc-cards/', v.AccessCardListView.as_view(), name='nfc-cards'),
    path('nfc-cards/<uuid:card_id>/', v.AccessCardDetailView.as_view(), name='nfc-card-detail'),

    # PIN khách / khuôn mặt / lịch sử ra vào
    path('devices/<uuid:device_id>/door-pins/', v.DoorPinListCreateView.as_view(), name='door-pins'),
    path('devices/<uuid:device_id>/door-pins/<uuid:pin_id>/revoke/', v.DoorPinRevokeView.as_view(),
         name='door-pin-revoke'),
    path('devices/<uuid:device_id>/face-profiles/', v.FaceProfileListCreateView.as_view(), name='face-profiles'),
    path('devices/<uuid:device_id>/face-profiles/<uuid:profile_id>/', v.FaceProfileDetailView.as_view(),
         name='face-profile-detail'),
    path('access-events/', v.AccessEventListView.as_view(), name='access-events'),

    # hỗ trợ
    path('support-requests/', v.SupportRequestListCreateView.as_view(), name='support-requests'),
    path('support-requests/<uuid:request_id>/', v.SupportRequestDetailView.as_view(), name='support-request-detail'),
    path('support-requests/<uuid:request_id>/cancel/', v.SupportRequestCancelView.as_view(),
         name='support-request-cancel'),

    # thông báo
    path('notifications/', v.NotificationListView.as_view(), name='notifications'),
    path('notifications/unread-count/', v.NotificationUnreadCountView.as_view(), name='notifications-unread'),
    path('notifications/read-all/', v.NotificationReadAllView.as_view(), name='notifications-read-all'),
    path('notifications/read/', v.NotificationDeleteReadView.as_view(), name='notifications-delete-read'),
    path('notifications/<uuid:notification_id>/', v.NotificationDetailView.as_view(), name='notification-detail'),
    path('notifications/<uuid:notification_id>/read/', v.NotificationReadView.as_view(), name='notification-read'),

    # luật tự động hoá
    path('automation-rules/', v.AutomationRuleListCreateView.as_view(), name='automation-rules'),
    path('automation-rules/<uuid:rule_id>/', v.AutomationRuleDetailView.as_view(), name='automation-rule-detail'),
    path('automation-rules/<uuid:rule_id>/toggle/', v.AutomationRuleToggleView.as_view(),
         name='automation-rule-toggle'),
    path('automation-rules/<uuid:rule_id>/logs/', v.AutomationRuleLogListView.as_view(),
         name='automation-rule-logs'),

    # nhật ký
    path('audit-logs/', v.AuditLogListView.as_view(), name='audit-logs'),

     path('login/', v.ApiLoginView.as_view(), name='login'),
]