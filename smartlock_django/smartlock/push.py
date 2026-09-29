# smartlock/push.py
"""
Đẩy thông báo tới app Android qua Firebase Cloud Messaging (FCM).

Mỗi khi có Notification mới (cảnh báo pin yếu, mở cửa sai liên tiếp, chia sẻ quyền...) - dù tạo từ
views, rules_engine hay access_control - signal post_save sẽ gửi push tới mọi phiên app đang đăng nhập
của người nhận có fcm_token và push_enabled.

Bật bằng cách cài `pip install firebase-admin` và đặt MỘT trong hai biến môi trường:
  FIREBASE_CREDENTIALS_JSON   nội dung JSON service account (tiện cho Vercel/Docker)
  GOOGLE_APPLICATION_CREDENTIALS  đường dẫn file JSON service account
Chưa cấu hình -> push bị bỏ qua êm, không ảnh hưởng luồng khác.

Payload data gửi kèm (mọi giá trị là chuỗi) để app điều hướng khi bấm vào thông báo:
  notification_id, type, severity, device_id (rỗng nếu không gắn thiết bị)
Kênh Android: smartlock_info | smartlock_warning | smartlock_critical (app phải tạo các channel này).
"""
import json
import logging
import os

from django.db import transaction
from django.db.models.signals import post_save
from django.utils import timezone

logger = logging.getLogger('smartlock.push')

_app = None
_initialised = False


def _get_app():
    global _app, _initialised
    if _initialised:
        return _app
    _initialised = True
    try:
        import firebase_admin
        from firebase_admin import credentials
    except ImportError:
        logger.info('push: chưa cài firebase-admin, bỏ qua push.')
        return None
    raw = os.environ.get('FIREBASE_CREDENTIALS_JSON')
    path = os.environ.get('GOOGLE_APPLICATION_CREDENTIALS')
    try:
        if raw:
            cred = credentials.Certificate(json.loads(raw))
        elif path:
            cred = credentials.Certificate(path)
        else:
            logger.info('push: chưa cấu hình thông tin Firebase, bỏ qua push.')
            return None
        _app = firebase_admin.initialize_app(cred, {'httpTimeout': 5}, name='smartlock-push')
    except Exception:
        logger.exception('push: khởi tạo Firebase thất bại')
        _app = None
    return _app


def send_notification_push(notification_id) -> int:
    """Gửi push cho 1 Notification. Trả số tin gửi thành công. Không bao giờ ném lỗi."""
    try:
        from .models import MobileSession, Notification
        notification = Notification.objects.filter(pk=notification_id).first()
        if not notification:
            return 0
        sessions = list(MobileSession.objects.filter(
            user_id=notification.user_id, revoked_at__isnull=True, expires_at__gt=timezone.now(),
            push_enabled=True).exclude(fcm_token=''))
        if not sessions:
            return 0
        app = _get_app()
        if app is None:
            return 0
        from firebase_admin import messaging

        data = {'notification_id': str(notification.id), 'type': notification.type,
                'severity': notification.severity,
                'device_id': str(notification.device_id) if notification.device_id else ''}
        critical = notification.severity == 'critical'
        messages = [messaging.Message(
            token=s.fcm_token,
            notification=messaging.Notification(title=notification.title[:100],
                                                body=notification.message[:300]),
            data=data,
            android=messaging.AndroidConfig(
                priority='high' if critical else 'normal',
                notification=messaging.AndroidNotification(channel_id=f'smartlock_{notification.severity}')),
        ) for s in sessions]
        batch = messaging.send_each(messages, app=app)

        dead = (messaging.UnregisteredError, messaging.SenderIdMismatchError)
        sent = 0
        for session, resp in zip(sessions, batch.responses):
            if resp.success:
                sent += 1
            elif isinstance(resp.exception, dead):     # token hết hạn/gỡ app -> dọn
                MobileSession.objects.filter(pk=session.pk).update(fcm_token='')
            else:
                logger.warning('push: gửi thất bại tới phiên %s: %s', session.pk, resp.exception)
        return sent
    except Exception:
        logger.exception('push: lỗi không mong đợi khi gửi push')
        return 0


def _on_notification_saved(sender, instance, created, **kwargs):
    if created:
        transaction.on_commit(lambda: send_notification_push(instance.pk))


def register_signals():
    """Gọi 1 lần trong AppConfig.ready()."""
    from .models import Notification
    post_save.connect(_on_notification_saved, sender=Notification, dispatch_uid='push_on_notification')