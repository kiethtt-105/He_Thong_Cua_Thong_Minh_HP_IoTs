"""Kênh MQTT (TUỲ CHỌN): nhận lệnh nhanh qua smartlock/<code>/cmd. HTTP polling vẫn chạy song song làm đường dự phòng.
Đăng nhập: username = device_code, password = secret.

Dev tunnel của VS Code chỉ chuyển tiếp HTTP/HTTPS -> MQTT đi qua tunnel phải dùng WebSocket (wss://).
Cấu hình trong config.json -> "mqtt":
  {"enabled": true, "url": "wss://<tunnel-id>-9001.<region>.devtunnels.ms"}        # cách ngắn gọn
  hoặc từng trường: transport (websockets|tcp), host, port, path, tls, tls_insecure, ca_file ...
url hỗ trợ: wss:// ws:// mqtts:// mqtt://   (url ghi đè host/port/path/tls/transport)
"""
import json
import ssl
import threading
import uuid
from urllib.parse import urlparse

TUNNEL_HEADERS = {'X-Tunnel-Skip-AntiPhishing-Page': 'true'}     # dev tunnel bỏ trang cảnh báo khi mở WebSocket


def resolve(m):
    """Chuẩn hoá cấu hình mqtt -> dict đầy đủ (dùng cả cho UI/CLI hiển thị)."""
    r = {'transport': m.get('transport') or 'tcp', 'host': m.get('host') or 'localhost', 'port': m.get('port'),
         'path': m.get('path') or '/', 'tls': m.get('tls', True) is not False}
    u = (m.get('url') or '').strip()
    if u:
        p = urlparse(u)
        if p.scheme not in ('wss', 'ws', 'mqtts', 'mqtt') or not p.hostname:
            raise ValueError('mqtt.url phải dạng wss://host[:port][/path] | ws:// | mqtts:// | mqtt://')
        r['transport'] = 'websockets' if p.scheme in ('ws', 'wss') else 'tcp'
        r['tls'] = p.scheme in ('wss', 'mqtts')
        r['host'] = p.hostname
        r['port'] = p.port
        r['path'] = p.path or '/'
    if not r['port']:
        r['port'] = (443 if r['tls'] else 80) if r['transport'] == 'websockets' else (8883 if r['tls'] else 1883)
    r['port'] = int(r['port'])
    return r


class MqttLink:
    def __init__(self, ctl):
        self.ctl = ctl
        self.client = None
        self.connected = False
        self.error = ''
        self.target = ''

    def start(self, m, code, secret):
        try:
            import paho.mqtt.client as mqtt
        except ImportError:
            self.error = 'Chưa cài paho-mqtt (pip install paho-mqtt)'
            self.ctl.log('MQTT: ' + self.error, 'warn')
            return
        try:
            r = resolve(m)
        except ValueError as e:
            self.error = str(e)
            self.ctl.log('MQTT: ' + self.error, 'err')
            return
        ws = r['transport'] == 'websockets'
        self.target = '%s://%s:%s%s' % (('wss' if r['tls'] else 'ws') if ws else ('mqtts' if r['tls'] else 'mqtt'),
                                       r['host'], r['port'], r['path'] if ws else '')
        self.code, self.tele = code, bool(m.get('publish_telemetry'))
        cid = f'{code}-{uuid.uuid4().hex[:6]}'
        kw = {'client_id': cid, 'transport': 'websockets' if ws else 'tcp'}
        try:
            c = mqtt.Client(callback_api_version=mqtt.CallbackAPIVersion.VERSION1, **kw)   # paho 2.x
        except AttributeError:
            c = mqtt.Client(**kw)                                                          # paho 1.x
        c.username_pw_set(code, secret)
        if ws:
            headers = dict(TUNNEL_HEADERS)
            headers.update(m.get('headers') or {})
            c.ws_set_options(path=r['path'], headers=headers)
        if r['tls']:
            c.tls_set(ca_certs=m.get('ca_file') or None, cert_reqs=ssl.CERT_REQUIRED)
            if m.get('tls_insecure'):
                c.tls_insecure_set(True)      # broker dùng chứng chỉ tự ký
        c.reconnect_delay_set(2, 30)
        c.on_connect = self._on_connect
        c.on_disconnect = self._on_disconnect
        c.on_message = self._on_message
        self.client = c
        try:
            c.connect_async(r['host'], r['port'], keepalive=int(m.get('keepalive') or 30))
            c.loop_start()
            self.ctl.log('MQTT: đang nối %s' % self.target)
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
