# smartlock/management/commands/mqtt_subscriber.py
"""Subscriber MQTT: nhận status / ack / event từ thiết bị (thật lẫn ảo) và đẩy vào hệ thống.

Chạy:  python manage.py mqtt_subscriber        (chạy 1 tiến trình duy nhất)

Topic (khớp ACL trong api/webhooks/mqtt.py (mqtt_acl)):
  smartlock/<device_code>/status   thiết bị -> server   trạng thái định kỳ + LWT
  smartlock/<device_code>/ack      thiết bị -> server   kết quả lệnh
  smartlock/<device_code>/event    thiết bị -> server   quẹt thẻ / nhập PIN / mặt / BLE / NFC
  smartlock/<device_code>/cmd      server  -> thiết bị  (do services.dispatch_command publish)

Lưu ý: KHÔNG gọi services.register_face từ đây (docstring của nó chỉ cho phép từ giao diện app/web).
"""
import hmac
import json
import logging
import threading
import time
import uuid

from django.core.management.base import BaseCommand
from django.db import close_old_connections
from django.utils import timezone

from smartlock import services
from smartlock.models import Device, DeviceCommand, DeviceStatusLog

logger = logging.getLogger('smartlock.mqtt')

MAX_PAYLOAD = 64 * 1024            # chặn payload quá lớn (embedding mặt 128 số ~ 3KB)
STATUS_LOG_MIN_INTERVAL = 60       # ghi DeviceStatusLog tối đa 1 lần/phút/thiết bị (trừ khi đổi trạng thái)
MAINTENANCE_EVERY = 30             # giây: đánh dấu offline + hết hạn lệnh
LOCK_STATES = {'locked', 'unlocked', 'jammed', 'unknown'}


class Command(BaseCommand):
    help = 'Subscriber MQTT: nhận status/ack/event từ thiết bị.'

    def handle(self, *args, **opts):
        try:
            import paho.mqtt.client as mqtt
        except ImportError:
            self.stderr.write('Thiếu paho-mqtt:  pip install "paho-mqtt<2"')
            return

        sub = _Subscriber()
        # session bền + client_id cố định: broker giữ tin QoS1 khi subscriber tạm dừng
        client = mqtt.Client(client_id='django-subscriber', clean_session=False)
        if services.MQTT_PUBLISHER_USERNAME:
            client.username_pw_set(services.MQTT_PUBLISHER_USERNAME, services.MQTT_PUBLISHER_PASSWORD)
        if services.MQTT_USE_TLS:
            client.tls_set()
        client.on_connect = sub.on_connect
        client.on_message = sub.on_message
        client.reconnect_delay_set(min_delay=1, max_delay=30)
        client.connect_async(services.MQTT_BROKER_HOST, services.MQTT_BROKER_PORT, keepalive=30)
        client.loop_start()
        self.stdout.write(f'MQTT subscriber -> {services.MQTT_BROKER_HOST}:{services.MQTT_BROKER_PORT}')
        try:
            while True:
                time.sleep(MAINTENANCE_EVERY)
                sub.maintenance()
        except KeyboardInterrupt:
            pass
        finally:
            client.loop_stop()
            client.disconnect()


class _Subscriber:
    def __init__(self):
        self._last_log = {}          # device_id -> (monotonic, lock_state, tamper)
        self._lock = threading.Lock()

    # ------------------------------------------------------------ kết nối
    def on_connect(self, client, userdata, flags, rc):
        if rc != 0:
            logger.error('MQTT connect thất bại rc=%s (kiểm tra MQTT_PUBLISHER_USERNAME/PASSWORD)', rc)
            return
        for topic in (services.STATUS_TOPIC, services.ACK_TOPIC, services.EVENT_TOPIC):
            client.subscribe(topic, qos=1)
        logger.info('MQTT connected, đã subscribe status/ack/event')

    # ------------------------------------------------------------ nhận tin
    def on_message(self, client, userdata, msg):
        try:
            parts = msg.topic.split('/')
            if len(parts) != 3 or parts[0] != 'smartlock' or len(msg.payload) > MAX_PAYLOAD:
                return
            _, code, channel = parts
            try:
                data = json.loads(msg.payload.decode('utf-8'))
            except (ValueError, UnicodeDecodeError):
                logger.warning('payload không phải JSON từ %s', code)
                return
            if not isinstance(data, dict):
                return
            close_old_connections()
            device = Device.objects.filter(device_code=code).first()
            if not device:
                return
            handler = {'status': self.on_status, 'ack': self.on_ack, 'event': self.on_event}.get(channel)
            if handler:
                handler(device, data)
        except Exception:
            logger.exception('lỗi xử lý %s', msg.topic)
        finally:
            close_old_connections()

    # ------------------------------------------------------------ status
    def on_status(self, device, d):
        # LWT / tắt máy: {"state": "offline"}
        if d.get('state') == 'offline' or d.get('online') is False:
            Device.objects.filter(pk=device.pk, status='online').update(status='offline')
            return
        services.touch_device(device, firmware=d.get('firmware'), battery=d.get('battery'))

        lock_state = d.get('lock_state') if d.get('lock_state') in LOCK_STATES else 'unknown'
        tamper = bool(d.get('tamper'))
        now = time.monotonic()
        with self._lock:
            prev = self._last_log.get(device.pk)
            changed = prev is None or prev[1] != lock_state or prev[2] != tamper
            if not changed and now - prev[0] < STATUS_LOG_MIN_INTERVAL:
                return
            self._last_log[device.pk] = (now, lock_state, tamper)

        try:
            battery = max(0, min(100, int(d.get('battery', device.battery_level))))
        except (TypeError, ValueError):
            battery = device.battery_level
        DeviceStatusLog.objects.create(
            device=device, battery_level=battery, lock_state=lock_state, tamper_detected=tamper,
            signal_strength=_int_or_none(d.get('rssi')), temperature=_dec_or_none(d.get('temperature')),
            raw_payload=d)
        if tamper and (prev is None or not prev[2]) and device.owner_id:
            services.notify(device.owner, 'Cảnh báo phá khoá',
                            f'Khoá "{device.name}" phát hiện tác động bất thường.',
                            severity='critical', device=device, type_='TAMPER')

    # ------------------------------------------------------------ ack
    def on_ack(self, device, d):
        services.touch_device(device)
        try:
            cmd_id = uuid.UUID(str(d.get('command_id')))
        except ValueError:
            return
        cmd = (DeviceCommand.objects.select_related('device', 'issued_by')
               .filter(pk=cmd_id, device=device).first())
        if not cmd or cmd.status not in ('pending', 'sent'):
            return
        # thiết bị phải gửi lại đúng token đã nhận trong lệnh
        if not hmac.compare_digest(str(d.get('token', '')), cmd.command_token_hash):
            logger.warning('ack sai token: cmd=%s device=%s', cmd.pk, device.device_code)
            return
        if cmd.expires_at < timezone.now():
            DeviceCommand.objects.filter(pk=cmd.pk).update(status='expired')
            return
        ok = bool(d.get('ok', True))
        new_status = 'acknowledged' if ok else 'failed'
        DeviceCommand.objects.filter(pk=cmd.pk).update(status=new_status, acknowledged_at=timezone.now())
        cmd.status = new_status
        services.announce_command_result(cmd, ok=ok)

    # ------------------------------------------------------------ event
    def on_event(self, device, d):
        services.touch_device(device)
        kind = str(d.get('type', '')).lower()
        if kind == 'boot':
            services.touch_device(device, firmware=d.get('firmware'))
        elif kind == 'rfid' and d.get('uid'):
            services.verify_rfid_tap(device, str(d['uid']))
        elif kind == 'pin' and d.get('pin'):
            services.verify_door_pin(device, str(d['pin']))
        elif kind == 'face' and isinstance(d.get('embedding'), list):
            try:
                emb = [float(x) for x in d['embedding'][:services.FACE_DIM]]
            except (TypeError, ValueError):
                return
            services.verify_face(device, emb, snapshot_url=str(d.get('snapshot_url', ''))[:500])
        elif kind == 'ble':
            services.record_ble_unlock(device, ticket=str(d.get('ticket', '')),
                                       ok=bool(d.get('ok', True)), reason=d.get('reason'), at=d.get('at'))
        elif kind == 'nfc_phone':
            services.record_nfc_phone_unlock(device, ticket=str(d.get('ticket', '')),
                                             ok=bool(d.get('ok', True)), reason=d.get('reason'), at=d.get('at'))
        else:
            logger.info('event không hỗ trợ từ %s: %s', device.device_code, kind)

    # ------------------------------------------------------------ định kỳ
    def maintenance(self):
        try:
            close_old_connections()
            offline = services.mark_offline_devices()
            expired = (DeviceCommand.objects.filter(status__in=('pending', 'sent'), expires_at__lt=timezone.now())
                       .update(status='expired'))
            if offline or expired:
                logger.info('maintenance: %d thiết bị offline, %d lệnh hết hạn', offline, expired)
        except Exception:
            logger.exception('maintenance lỗi')
        finally:
            close_old_connections()


def _int_or_none(v):
    try:
        return int(v)
    except (TypeError, ValueError):
        return None


def _dec_or_none(v):
    try:
        return round(float(v), 1)
    except (TypeError, ValueError):
        return None
