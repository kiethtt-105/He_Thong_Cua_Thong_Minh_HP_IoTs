# smartlock/management/commands/mqtt_bridge.py
"""
Chạy: python manage.py mqtt_bridge
"""
import json
import logging

from django.core.management.base import BaseCommand
from django.utils import timezone

from smartlock.models import Device, DeviceCommand, DeviceStatusLog
from smartlock.mqtt_client import (
    MQTT_BROKER_HOST, MQTT_BROKER_PORT, MQTT_USE_TLS,
    status_topic_wildcard, ack_topic_wildcard,
)

logger = logging.getLogger('smartlock.mqtt_bridge')

import os
BRIDGE_USERNAME = os.environ.get('MQTT_BRIDGE_USERNAME', '')
BRIDGE_PASSWORD = os.environ.get('MQTT_BRIDGE_PASSWORD', '')


def _device_code_from_topic(topic: str) -> str:
    # smartlock/<device_code>/status  ->  <device_code>
    parts = topic.split('/')
    return parts[1] if len(parts) >= 3 else ''


def _handle_status(payload: dict):
    device_code = payload.get('device_code') or ''
    device = Device.objects.filter(device_code=device_code).first()
    if not device:
        logger.warning('mqtt status: không tìm thấy device_code=%s', device_code)
        return

    DeviceStatusLog.objects.create(
        device=device,
        battery_level=int(payload.get('battery_level', device.battery_level)),
        signal_strength=payload.get('signal_strength'),
        lock_state=payload.get('lock_state', 'unknown'),
        tamper_detected=bool(payload.get('tamper_detected', False)),
        temperature=payload.get('temperature'),
        raw_payload=payload,
    )

    update_fields = {'last_seen_at': timezone.now(), 'battery_level': int(payload.get('battery_level', device.battery_level))}
    # Chỉ tự chuyển sang 'online' nếu thiết bị đang không ở trạng thái quản trị đặc biệt
    # (maintenance/revoked/provisioning) - tránh 1 gói tin trạng thái ghi đè quyết định của admin.
    if device.status in ('online', 'offline'):
        update_fields['status'] = 'online'
    Device.objects.filter(pk=device.pk).update(**update_fields)


def _handle_ack(payload: dict):
    command_id = payload.get('command_id')
    token = payload.get('token') or ''
    result = payload.get('result') or 'failed'
    cmd = DeviceCommand.objects.filter(pk=command_id, status__in=['pending', 'sent']).first()
    if not cmd:
        logger.warning('mqtt ack: command_id=%s không tồn tại hoặc đã xử lý', command_id)
        return
    # token thiết bị gửi lại phải khớp đúng command_token_hash đã publish lúc gửi lệnh -
    # tránh trường hợp ack giả mạo/nhầm lệnh.
    if token != cmd.command_token_hash:
        logger.warning('mqtt ack: token không khớp cho command_id=%s', command_id)
        return
    cmd.status = 'acknowledged' if result == 'ok' else 'failed'
    cmd.acknowledged_at = timezone.now()
    cmd.save(update_fields=['status', 'acknowledged_at'])


class Command(BaseCommand):
    help = 'Chạy MQTT bridge (subscribe status/ack từ thiết bị, chạy nền dài hạn).'

    def handle(self, *args, **options):
        try:
            import paho.mqtt.client as mqtt
        except ImportError:
            self.stderr.write('Chưa cài paho-mqtt. Chạy: pip install "paho-mqtt<2"')
            return

        def on_connect(client, userdata, flags, rc):
            if rc == 0:
                self.stdout.write(self.style.SUCCESS('Đã kết nối broker MQTT.'))
                client.subscribe([(status_topic_wildcard(), 1), (ack_topic_wildcard(), 1)])
            else:
                self.stderr.write(f'Kết nối broker thất bại, rc={rc}')

        def on_message(client, userdata, msg):
            try:
                payload = json.loads(msg.payload.decode('utf-8'))
            except Exception:
                logger.warning('mqtt: payload không phải JSON hợp lệ trên topic %s', msg.topic)
                return
            payload.setdefault('device_code', _device_code_from_topic(msg.topic))
            try:
                if msg.topic.endswith('/status'):
                    _handle_status(payload)
                elif msg.topic.endswith('/ack'):
                    _handle_ack(payload)
            except Exception:
                logger.exception('mqtt: lỗi xử lý message topic %s', msg.topic)

        def on_disconnect(client, userdata, rc):
            self.stdout.write(self.style.WARNING(f'Mất kết nối broker (rc={rc}), paho sẽ tự reconnect...'))

        client = mqtt.Client(client_id='smartlock-bridge')
        if BRIDGE_USERNAME:
            client.username_pw_set(BRIDGE_USERNAME, BRIDGE_PASSWORD)
        if MQTT_USE_TLS:
            client.tls_set()
        client.on_connect = on_connect
        client.on_message = on_message
        client.on_disconnect = on_disconnect
        client.reconnect_delay_set(min_delay=1, max_delay=30)

        client.connect(MQTT_BROKER_HOST, MQTT_BROKER_PORT, keepalive=60)
        client.loop_forever()  # block vĩnh viễn, tự động reconnect khi rớt mạng