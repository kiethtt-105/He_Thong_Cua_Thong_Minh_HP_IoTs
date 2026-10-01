# smartlock/management/commands/mqtt_subscriber.py
"""
MQTT subscriber thường trực (thay cho mqtt_bridge + mark_offline_devices cũ).

    python manage.py mqtt_subscriber                       # chạy cả luồng nền kiểm tra offline
    python manage.py mqtt_subscriber --no-offline-check    # tắt luồng đó (nếu bạn tự chạy cron)

Đây là tiến trình chạy liên tục: KHÔNG chạy được trên Vercel (serverless), hãy chạy trên laptop/VPS.
"""
import json
import logging
import signal
import sys
import threading
import time

from django.core.management.base import BaseCommand
from django.db import close_old_connections
from django.utils import timezone

from smartlock import services
from smartlock.models import Device, DeviceCommand, DeviceStatusLog

logger = logging.getLogger('smartlock.mqtt_subscriber')

OFFLINE_CHECK_INTERVAL_SECONDS = 60
LOCK_STATES = ('locked', 'unlocked', 'jammed', 'unknown')


class Command(BaseCommand):
    help = 'Chạy MQTT subscriber thường trực (status / event / ack) + kiểm tra thiết bị offline.'

    def add_arguments(self, parser):
        parser.add_argument('--no-offline-check', action='store_true',
                            help='Không chạy luồng nền đánh dấu thiết bị offline.')

    def handle(self, *args, **options):
        try:
            import paho.mqtt.client as mqtt
        except ImportError:
            self.stderr.write(self.style.ERROR('Chưa cài paho-mqtt (pip install "paho-mqtt<2").'))
            sys.exit(1)

        client = mqtt.Client(client_id='django-sub-worker')
        if services.MQTT_PUBLISHER_USERNAME:
            client.username_pw_set(services.MQTT_PUBLISHER_USERNAME, services.MQTT_PUBLISHER_PASSWORD)
        if services.MQTT_USE_TLS:
            client.tls_set()
        client.on_connect = self._on_connect
        client.on_message = self._on_message
        client.reconnect_delay_set(min_delay=1, max_delay=30)

        def _graceful_exit(signum, frame):
            self.stdout.write('mqtt_subscriber: nhận tín hiệu dừng, ngắt kết nối...')
            client.disconnect()
            sys.exit(0)

        signal.signal(signal.SIGINT, _graceful_exit)
        signal.signal(signal.SIGTERM, _graceful_exit)

        if not options['no_offline_check']:
            threading.Thread(target=self._offline_loop, daemon=True, name='offline-check').start()

        self.stdout.write(self.style.SUCCESS(
            f'mqtt_subscriber: kết nối tới {services.MQTT_BROKER_HOST}:{services.MQTT_BROKER_PORT} '
            f'(TLS={services.MQTT_USE_TLS})'))
        client.connect(services.MQTT_BROKER_HOST, services.MQTT_BROKER_PORT, keepalive=60)
        client.loop_forever(retry_first_connection=True)

    # ---------------------------------------------------------------- nền: thiết bị offline
    def _offline_loop(self):
        while True:
            time.sleep(OFFLINE_CHECK_INTERVAL_SECONDS)
            try:
                close_old_connections()
                n = services.mark_offline_devices()
                if n:
                    logger.warning('mqtt_subscriber: %s thiết bị chuyển sang offline', n)
            except Exception:
                logger.exception('mqtt_subscriber: lỗi khi kiểm tra thiết bị offline')
            finally:
                close_old_connections()

    # ---------------------------------------------------------------- callbacks
    def _on_connect(self, client, userdata, flags, rc):
        if rc != 0:
            logger.error('mqtt_subscriber: kết nối broker thất bại, rc=%s', rc)
            return
        client.subscribe([(services.STATUS_TOPIC, 1), (services.EVENT_TOPIC, 1), (services.ACK_TOPIC, 1)])
        logger.info('mqtt_subscriber: đã subscribe status/event/ack')

    def _on_message(self, client, userdata, msg):
        # 1 bản tin lỗi không được làm chết tiến trình (phải sống 24/7).
        close_old_connections()
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
            if not isinstance(payload, dict):
                return

            if kind == 'status':
                self._handle_status(device, payload)
            elif kind == 'event':
                self._handle_event(device, payload)
            elif kind == 'ack':
                self._handle_ack(device, payload)
        except Exception:
            logger.exception('mqtt_subscriber: lỗi khi xử lý message, topic=%s', msg.topic)
        finally:
            close_old_connections()

    # ---------------------------------------------------------------- handlers
    def _handle_status(self, device, payload):
        battery = payload.get('battery_level')
        if isinstance(battery, bool) or not isinstance(battery, (int, float)) or not (0 <= battery <= 100):
            logger.warning('mqtt_subscriber: battery_level không hợp lệ từ %s: %r', device.device_code, battery)
            return
        lock_state = payload.get('lock_state', 'unknown')
        if lock_state not in LOCK_STATES:
            lock_state = 'unknown'

        status_log = DeviceStatusLog.objects.create(
            device=device, battery_level=int(battery), signal_strength=payload.get('signal_strength'),
            lock_state=lock_state, tamper_detected=bool(payload.get('tamper_detected', False)),
            raw_payload=payload,
        )
        fields = {'last_seen_at': timezone.now(), 'battery_level': int(battery)}
        # Chỉ tự chuyển 'online' khi thiết bị đang online/offline. Nếu ép 'online' cho thiết bị
        # provisioning/revoked (owner = NULL) sẽ vi phạm constraint chk_devices_owner_vs_status,
        # và cũng ghi đè quyết định của admin (maintenance).
        if device.status in ('online', 'offline'):
            fields['status'] = 'online'
        Device.objects.filter(pk=device.pk).update(**fields)
        services.evaluate_device_status(device, status_log)

    def _handle_event(self, device, payload):
        event_type = payload.get('type')
        if not device.owner_id:
            logger.warning('mqtt_subscriber: bỏ qua event %r từ %s (thiết bị chưa có chủ)',
                           event_type, device.device_code)
            return
        if event_type == 'rfid_tap':
            uid = str(payload.get('uid') or '')
            if uid:
                services.verify_rfid_tap(device, uid)
        elif event_type == 'pin_entry':
            pin = str(payload.get('pin') or '')
            if pin:
                services.verify_door_pin(device, pin)
        elif event_type == 'face_result':
            embedding = payload.get('embedding')
            if isinstance(embedding, list) and embedding:
                services.verify_face(device, embedding, snapshot_url=payload.get('snapshot_url', ''))
        elif event_type == 'ble_unlock':
            services.record_ble_unlock(
                device, ticket=str(payload.get('ticket') or ''),
                ok=payload.get('result', 'ok') == 'ok', reason=payload.get('reason'), at=payload.get('at'))
        else:
            logger.warning('mqtt_subscriber: event type không rõ từ %s: %r', device.device_code, event_type)

    def _handle_ack(self, device, payload):
        command_id = payload.get('command_id')
        if not command_id:
            return
        cmd = DeviceCommand.objects.filter(
            pk=command_id, device=device, status__in=('pending', 'sent')).first()
        if not cmd:
            logger.info('mqtt_subscriber: ack cho lệnh không còn chờ, command_id=%s', command_id)
            return
        token = payload.get('token')
        if token and token != cmd.command_token_hash:     # chống ack giả mạo / nhầm lệnh
            logger.warning('mqtt_subscriber: token ack không khớp, command_id=%s', command_id)
            return
        cmd.status = 'failed' if payload.get('result', 'ok') == 'failed' else 'acknowledged'
        cmd.acknowledged_at = timezone.now()
        cmd.save(update_fields=['status', 'acknowledged_at'])