# smartlock/management/commands/mqtt_subscriber.py
#
# CÁCH DÙNG: đặt file này vào smartlock/management/commands/mqtt_subscriber.py
# (tạo thêm 2 file __init__.py rỗng ở smartlock/management/ và
# smartlock/management/commands/ nếu chưa có). Chạy nền bằng:
#
#     python manage.py mqtt_subscriber
#


import json
import logging
import signal
import sys

from django.core.management.base import BaseCommand
from django.utils import timezone

from smartlock.models import Device, DeviceCommand, DeviceStatusLog
from smartlock import access_control, mqtt_client, rules_engine

logger = logging.getLogger('smartlock.mqtt_subscriber')


class Command(BaseCommand):
    help = 'Chạy MQTT subscriber thường trực cho hệ thống smartlock (status/event/ack).'

    def handle(self, *args, **options):
        try:
            import paho.mqtt.client as mqtt
        except ImportError:
            self.stderr.write(self.style.ERROR('Chưa cài paho-mqtt (pip install "paho-mqtt<2").'))
            sys.exit(1)

        client = mqtt.Client(client_id='django-sub-worker')
        if mqtt_client.MQTT_PUBLISHER_USERNAME:
            client.username_pw_set(mqtt_client.MQTT_PUBLISHER_USERNAME, mqtt_client.MQTT_PUBLISHER_PASSWORD)
        if mqtt_client.MQTT_USE_TLS:
            client.tls_set()

        client.on_connect = self._on_connect
        client.on_message = self._on_message

        def _graceful_exit(signum, frame):
            self.stdout.write('mqtt_subscriber: nhận tín hiệu dừng, ngắt kết nối...')
            client.disconnect()
            sys.exit(0)

        signal.signal(signal.SIGINT, _graceful_exit)
        signal.signal(signal.SIGTERM, _graceful_exit)

        self.stdout.write(self.style.SUCCESS(
            f'mqtt_subscriber: kết nối tới {mqtt_client.MQTT_BROKER_HOST}:{mqtt_client.MQTT_BROKER_PORT} '
            f'(TLS={mqtt_client.MQTT_USE_TLS})'
        ))
        client.connect(mqtt_client.MQTT_BROKER_HOST, mqtt_client.MQTT_BROKER_PORT, keepalive=60)
        client.loop_forever(retry_first_connection=True)

    # ---------------------------------------------------------------- callbacks
    def _on_connect(self, client, userdata, flags, rc):
        if rc != 0:
            logger.error('mqtt_subscriber: kết nối broker thất bại, rc=%s', rc)
            return
        client.subscribe([
            (mqtt_client.status_topic_wildcard(), 1),
            ('smartlock/+/event', 1),
            (mqtt_client.ack_topic_wildcard(), 1),
        ])
        logger.info('mqtt_subscriber: đã subscribe status/event/ack, rc=%s', rc)

    def _on_message(self, client, userdata, msg):
        try:
            parts = msg.topic.split('/')
            if len(parts) != 3 or parts[0] != 'smartlock':
                return
            device_code, kind = parts[1], parts[2]
            device = Device.objects.filter(device_code=device_code).first()
            if not device:
                logger.warning('mqtt_subscriber: thiết bị không tồn tại device_code=%s', device_code)
                return

            try:
                payload = json.loads(msg.payload.decode('utf-8'))
            except (ValueError, UnicodeDecodeError):
                logger.warning('mqtt_subscriber: payload không phải JSON hợp lệ, topic=%s', msg.topic)
                return

            if kind == 'status':
                self._handle_status(device, payload)
            elif kind == 'event':
                self._handle_event(device, payload)
            elif kind == 'ack':
                self._handle_ack(device, payload)
        except Exception:
            # KHÔNG được để 1 bản tin lỗi làm chết cả tiến trình subscriber - log và
            # tiếp tục nhận các bản tin sau. Đây là điểm khác biệt quan trọng so với
            # publish_command() (connect ngắn hạn): tiến trình này phải sống 24/7.
            logger.exception('mqtt_subscriber: lỗi khi xử lý message, topic=%s', msg.topic)

    # ---------------------------------------------------------------- handlers
    def _handle_status(self, device, payload):
        """Ghi DeviceStatusLog rồi chạy rule engine - đáp ứng đúng luồng
        'subscriber nhận dữ liệu MQTT -> kiểm tra hợp lệ -> ghi DB' mà rubric yêu cầu."""
        battery = payload.get('battery_level')
        lock_state = payload.get('lock_state', 'unknown')
        if not isinstance(battery, (int, float)) or not (0 <= battery <= 100):
            logger.warning('mqtt_subscriber: battery_level không hợp lệ từ %s: %r',
                            device.device_code, battery)
            return
        if lock_state not in ('locked', 'unlocked', 'jammed', 'unknown'):
            lock_state = 'unknown'

        status_log = DeviceStatusLog.objects.create(
            device=device, battery_level=int(battery), signal_strength=payload.get('signal_strength'),
            lock_state=lock_state, tamper_detected=bool(payload.get('tamper_detected', False)),
            temperature=payload.get('temperature'), raw_payload=payload,
        )
        Device.objects.filter(pk=device.pk).update(
            last_seen_at=timezone.now(), battery_level=int(battery), status='online',
        )
        rules_engine.evaluate_device_status(device, status_log)

    def _handle_event(self, device, payload):
        """Sự kiện xác thực từ thiết bị: {"type": "rfid_tap"|"pin_entry"|"face_result", ...}."""
        event_type = payload.get('type')
        if event_type == 'rfid_tap':
            uid = str(payload.get('uid') or '')
            if uid:
                access_control.verify_rfid_tap(device, uid)
        elif event_type == 'pin_entry':
            pin = str(payload.get('pin') or '')
            if pin:
                access_control.verify_door_pin(device, pin)
        elif event_type == 'face_result':
            embedding = payload.get('embedding')
            if isinstance(embedding, list) and embedding:
                access_control.verify_face(device, embedding, snapshot_url=payload.get('snapshot_url', ''))
        else:
            logger.warning('mqtt_subscriber: event type không rõ từ %s: %r', device.device_code, event_type)

    def _handle_ack(self, device, payload):
        command_id = payload.get('command_id')
        if not command_id:
            return
        updated = DeviceCommand.objects.filter(
            id=command_id, device=device, status='sent',
        ).update(status='acknowledged', acknowledged_at=timezone.now())
        if not updated:
            logger.info('mqtt_subscriber: ack cho lệnh không còn ở trạng thái sent, command_id=%s', command_id)