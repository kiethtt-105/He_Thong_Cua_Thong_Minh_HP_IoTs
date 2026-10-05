"""Lịch sử / nhật ký / thông báo - /api/app/history/, /audit/, /notifications/, /events/, /announcements/"""
from django.urls import path

from . import announcements, history, notifications

urlpatterns = [
    path('history/', history.access_history, name='history'),
    path('audit/', history.audit_logs, name='audit'),
    path('notifications/', notifications.notifications, name='notifications'),
    path('notifications/read/', notifications.notifications_read, name='notifications-read'),
    path('notifications/<uuid:notification_id>/', notifications.notification_delete, name='notification-delete'),
    path('events/', notifications.events_poll, name='events'),
    path('announcements/', announcements.announcements, name='announcements'),
]
