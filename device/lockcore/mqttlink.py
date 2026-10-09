"""Kênh MQTT (TUỲ CHỌN): nhận lệnh nhanh qua smartlock/<code>/cmd. HTTP polling vẫn chạy song song làm đường dự phòng.
Đăng nhập: username = device_code, password = secret (đúng như trang admin ghi)."""
import json
import ssl
import threading
import uuid


class MqttLink:
    def __init__(self, ctl):
        self.ctl = ctl
        self.client = None
        self.connected = False
        self.error = ''

    def start(self, m, code, secret):
        try:
            import paho.mqtt.client as mqtt
        except ImportError:
            self.error = 'Chưa cài paho-mqtt (pip install paho-mqtt)'
            self.ctl.log('MQTT: ' + self.error, 'warn')
            return
        self.code, self.tele = code, bool(m.get('publish_telemetry'))
        cid = f'{code}-{uuid.uuid4().hex[:6]}'
        try:
            c = mqtt.Client(callback_api_version=mqtt.CallbackAPIVersion.VERSION1, client_id=cid)   # paho 2.x
        except AttributeError:
            c = mqtt.Client(client_id=cid)                                                         # paho 1.x
        c.username_pw_set(code, secret)
        if m.get('tls', True):
            c.tls_set(ca_certs=m.get('ca_file') or None, cert_reqs=ssl.CERT_REQUIRED)
            if m.get('tls_insecure'):
                c.tls_insecure_set(True)      # broker local dùng chứng chỉ tự ký
        c.reconnect_delay_set(2, 30)
        c.on_connect = self._on_connect
        c.on_disconnect = self._on_disconnect
        c.on_message = self._on_message
        self.client = c
        try:
            c.connect_async(m.get('host', 'localhost'), int(m.get('port', 8883)), keepalive=30)
            c.loop_start()
        except Exception as e:
            self.error = str(e)
            self.ctl.log(f'MQTT lỗi: {e}', 'warn')

    def _on_connect(self, c, ud, flags, rc):
        self.connected = rc == 0
        if rc == 0:
            self.error = ''
            c.subscribe(f'smartlock/{self.code}/cmd', qos=1)
            self.ctl.log('MQTT đã kết nối, subscribe smartlock/%s/cmd' % self.code, 'ok')
        else:
            self.error = f'connect rc={rc} (4/5 = sai user/secret hoặc ACL)'
            self.ctl.log('MQTT bị từ chối: ' + self.error, 'warn')

    def _on_disconnect(self, c, ud, rc):
        self.connected = False
        if rc != 0:
            self.ctl.log('MQTT mất kết nối, tự nối lại...', 'warn')

    def _on_message(self, c, ud, msg):
        try:
            data = json.loads(msg.payload.decode('utf-8'))
        except ValueError:
            return
        threading.Thread(target=self.ctl.handle_command, args=(data, 'mqtt'), daemon=True).start()

    def publish(self, sub, payload):
        """sub: status | ack | event  (chỉ gửi khi bật publish_telemetry - phía server chưa chắc có subscriber)."""
        if self.client and self.connected and self.tele:
            try:
                self.client.publish(f'smartlock/{self.code}/{sub}', json.dumps(payload), qos=1)
            except Exception:
                pass

    def stop(self):
        if self.client:
            try:
                self.client.loop_stop()
                self.client.disconnect()
            except Exception:
                pass
        self.client, self.connected = None, False
