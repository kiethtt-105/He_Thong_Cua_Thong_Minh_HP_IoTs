#!/usr/bin/env python
"""
Khoá thông minh ẢO - giả lập firmware ESP32 để test server Django khi chưa có thiết bị thật.

Giao thức (khớp smartlock/services.py + views.mqtt_auth_webhook):
  - Kết nối broker: username = device_code, password = provisioning secret GỐC.
  - Subscribe  smartlock/<code>/cmd      (server -> khoá)
  - Publish    smartlock/<code>/status   (định kỳ: pin, trạng thái khoá...)
               smartlock/<code>/ack      (trả lời lệnh, kèm command_id + token)
               smartlock/<code>/event    (quẹt thẻ, nhập PIN, mở bằng BLE/NFC điện thoại, tamper)
  - Vé BLE/NFC được khoá TỰ kiểm tra chữ ký + hạn (offline), rồi mới báo sự kiện lên server.

Chạy:  python virtual_lock.py --code SL-DEMO-001 --secret <secret>
"""
import argparse
import collections
import hashlib
import hmac
import json
import os
import random
import shlex
import sys
import threading
import time

try:
    import paho.mqtt.client as mqtt
except ImportError:
    sys.exit('Thiếu paho-mqtt. Chạy: pip install -r requirements.txt')

TICKET_LABELS = {'ble': b'ble-ticket-v1', 'nfc': b'nfc-phone-ticket-v1'}
EVENT_TYPE = {'rfid': 'rfid', 'pin': 'pin', 'ble': 'ble_unlock', 'nfc': 'nfc_phone_unlock', 'tamper': 'tamper'}


def load_dotenv(path):
    if os.path.exists(path):
        for line in open(path, encoding='utf-8'):
            line = line.strip()
            if line and not line.startswith('#') and '=' in line:
                k, v = line.split('=', 1)
                os.environ.setdefault(k.strip(), v.strip().strip('"\''))


class VirtualLock:
    def __init__(self, a):
        self.code, self.secret = a.code, a.secret
        self.secret_hash = hashlib.sha256(self.secret.encode()).hexdigest()  # = Device.provisioning_secret_hash
        self.mac = a.mac
        self.firmware = a.firmware
        self.status_every = a.status_every
        self.relock_after = a.relock_after
        self.drain = a.drain
        self.ack_delay = a.ack_delay
        self.fail_rate = a.fail_rate
        self.json_mode = a.json
        self.out_lock = threading.Lock()
        self.cmd_topic = f'smartlock/{self.code}/cmd'
        self.t = lambda ch: f'smartlock/{self.code}/{ch}'

        self.state = {'lock_state': 'locked', 'battery': a.battery, 'signal': -55,
                      'tamper': False, 'temperature': 27.0}
        self.buzzer_until = 0.0
        self.cards = set()               # UID thẻ lưu cục bộ (ADD_CARD/REMOVE_CARD)
        self.pending = collections.deque(maxlen=200)   # sự kiện lúc mất mạng -> gửi bù (kèm 'at')
        self.started = time.time()
        self.relock_timer = None
        self.mutex = threading.RLock()
        self.stop = threading.Event()

        try:
            self.c = mqtt.Client(mqtt.CallbackAPIVersion.VERSION1, client_id=f'vlock-{self.code}')
        except AttributeError:           # paho-mqtt 1.x
            self.c = mqtt.Client(client_id=f'vlock-{self.code}')
        self.c.username_pw_set(self.code, self.secret)
        self.c.on_connect, self.c.on_message, self.c.on_disconnect = self._on_connect, self._on_message, self._on_disc
        self.c.reconnect_delay_set(1, 15)
        self.host, self.port = a.host, a.port
        self.connected = False

    # ------------------------------------------------------------ log
    def emit(self, ev, **kw):
        """Chế độ --json: mỗi dòng stdout là 1 JSON (VS Code extension đọc)."""
        with self.out_lock:
            print(json.dumps({'ev': ev, **kw}, ensure_ascii=False), flush=True)

    def log(self, msg):
        if self.json_mode:
            return self.emit('log', t=time.strftime('%H:%M:%S'), msg=msg)
        print(f'[{time.strftime("%H:%M:%S")}] {msg}', flush=True)

    def ui_state(self):
        d = self.snapshot()
        d.update({'connected': self.connected, 'buzzer': time.time() < self.buzzer_until,
                  'pending': len(self.pending), 'cards': sorted(self.cards), 'host': self.host, 'port': self.port,
                  'config': {'fail_rate': self.fail_rate, 'ack_delay': self.ack_delay,
                            'relock_after': self.relock_after, 'drain': self.drain,
                            'status_every': self.status_every}})
        return d

    def ui_loop(self):
        while not self.stop.wait(1.0):
            self.emit('state', **self.ui_state())

    # ------------------------------------------------------------ MQTT
    def _on_connect(self, c, u, flags, rc):
        if rc != 0:
            self.log(f'❌ Broker từ chối (rc={rc}). Sai device_code/secret hoặc webhook auth chưa cho phép.')
            return
        self.connected = True
        c.subscribe(self.cmd_topic, qos=1)
        self.log(f'✅ Đã kết nối broker {self.host}:{self.port}, nghe {self.cmd_topic}')
        self.publish_status()
        while self.pending:                       # gửi bù sự kiện offline
            ch, payload = self.pending.popleft()
            self._pub(ch, payload)

    def _on_disc(self, c, u, rc):
        self.connected = False
        self.log(f'⚠️  Mất kết nối (rc={rc}), sẽ tự nối lại...')

    def _pub(self, channel, payload):
        info = self.c.publish(self.t(channel), json.dumps(payload, ensure_ascii=False), qos=1)
        return info.rc == mqtt.MQTT_ERR_SUCCESS

    def send(self, channel, payload, queue=False):
        if self.connected and self._pub(channel, payload):
            return True
        if queue:
            self.pending.append((channel, payload))
            self.log(f'📥 Offline: xếp hàng sự kiện {payload.get("type")}')
        return False

    # ------------------------------------------------------------ nhận lệnh
    def _on_message(self, c, u, msg):
        try:
            data = json.loads(msg.payload.decode())
        except ValueError:
            return self.log(f'Bỏ qua payload không phải JSON: {msg.payload[:80]!r}')
        cmd = str(data.get('command', '')).upper()
        self.log(f'⬇️  Lệnh {cmd} (nguồn={data.get("source")}, id={str(data.get("command_id", ""))[:8]})')
        threading.Thread(target=self.handle_command, args=(cmd, data), daemon=True).start()

    def handle_command(self, cmd, data):
        time.sleep(self.ack_delay)                # mô phỏng độ trễ cơ khí/mạng
        ok = random.random() >= self.fail_rate
        with self.mutex:
            if cmd == 'UNLOCK' and ok:
                self.set_lock('unlocked', auto_relock=True)
            elif cmd == 'LOCK' and ok:
                self.set_lock('locked')
            elif cmd == 'PING':
                pass
            elif cmd == 'REBOOT':
                self.log('🔁 Reboot giả lập...'); self.started = time.time()
            elif cmd == 'RESET':
                self.log('🧹 Factory reset: xoá thẻ cục bộ'); self.cards.clear()
            elif cmd == 'ADD_CARD':
                uid = (data.get('uid') or data.get('card_uid') or '').upper()
                if uid: self.cards.add(uid)
            elif cmd == 'REMOVE_CARD':
                self.cards.discard((data.get('uid') or data.get('card_uid') or '').upper())
            elif cmd == 'OTA_UPDATE':
                self.firmware = str(data.get('version') or self.firmware)
                self.log(f'⬆️  OTA -> firmware {self.firmware}')
            elif cmd == 'BUZZER_ALERT':
                self.buzzer_until = time.time() + 10
                self.log(f'🚨 CÒI KÊU 10s (lý do: {data.get("reason")})')
        if data.get('command_id'):                # BUZZER_ALERT không có command_id -> không ack
            self.send('ack', {'command_id': data['command_id'], 'command': cmd, 'token': data.get('token'),
                              'status': 'ok' if ok else 'failed', 'lock_state': self.state['lock_state'],
                              'ts': int(time.time())})
        self.publish_status()

    # ------------------------------------------------------------ phần cứng giả
    def set_lock(self, new, auto_relock=False):
        with self.mutex:
            self.state['lock_state'] = new
            self.log('🔓 CỬA MỞ' if new == 'unlocked' else '🔒 CỬA KHOÁ')
            if self.relock_timer:
                self.relock_timer.cancel()
            if auto_relock and new == 'unlocked' and self.relock_after > 0:
                self.relock_timer = threading.Timer(self.relock_after, self._relock)
                self.relock_timer.daemon = True
                self.relock_timer.start()

    def _relock(self):
        self.set_lock('locked')
        self.publish_status()

    def snapshot(self):
        s = self.state
        return {'device_code': self.code, 'lock_state': s['lock_state'], 'battery': s['battery'],
                'battery_level': s['battery'], 'signal_strength': s['signal'], 'signal': s['signal'],
                'tamper_detected': s['tamper'], 'temperature': s['temperature'],
                'firmware': self.firmware, 'firmware_version': self.firmware, 'mac': self.mac,
                'uptime': int(time.time() - self.started), 'ts': int(time.time())}

    def publish_status(self):
        self.send('status', self.snapshot())
        if self.json_mode:
            self.emit('state', **self.ui_state())

    def status_loop(self):
        while not self.stop.wait(self.status_every):
            with self.mutex:
                s = self.state
                s['signal'] = max(-90, min(-40, s['signal'] + random.randint(-3, 3)))
                s['temperature'] = round(max(15, min(45, s['temperature'] + random.uniform(-.3, .3))), 1)
                if self.drain:
                    s['battery'] = max(0, s['battery'] - self.drain)
            self.publish_status()

    # ------------------------------------------------------------ sự kiện từ người dùng (gõ ở console)
    def event(self, kind, **extra):
        self.send('event', {'type': EVENT_TYPE[kind], 'device_code': self.code, 'at': int(time.time()), **extra},
                  queue=True)

    def verify_ticket(self, kind, ticket):
        """Khoá TỰ kiểm tra vé (giống firmware): chữ ký HMAC + hạn. Trả (ok, reason)."""
        try:
            user_hex, exp_s, sig = ticket.strip().split('.')
            exp = int(exp_s)
        except ValueError:
            return False, 'BAD_FORMAT'
        key = hmac.new(self.secret_hash.encode(), TICKET_LABELS[kind], hashlib.sha256).digest()
        good = hmac.new(key, f'{self.code}|{user_hex}|{exp}'.encode(), hashlib.sha256).hexdigest()[:32]
        if not hmac.compare_digest(sig, good):
            return False, 'INVALID_TICKET'
        if exp < time.time():
            return False, 'TICKET_EXPIRED'
        return True, None

    # ------------------------------------------------------------ console
    HELP = """Lệnh:
  tap <UID>        quẹt thẻ RFID (vd: tap 04:A1:B2:C3)  -> server so khớp rồi gửi UNLOCK
  pin <mã>         nhập PIN trên bàn phím                 -> server kiểm tra rồi gửi UNLOCK
  ble <vé>         mở bằng vé Bluetooth (khoá tự kiểm tra chữ ký/hạn rồi báo log)
  nfc <vé>         mở bằng vé NFC điện thoại
  tamper [on|off]  giả lập cạy phá
  battery <0-100>  đặt mức pin           signal <dBm>  đặt tín hiệu
  lock | unlock    thao tác tại chỗ (nút/chìa cơ)
  offline | online ngắt/nối mạng (sự kiện lúc offline được gửi bù)
  status           in & gửi trạng thái      help   quit"""

    def console(self):
        print(self.HELP)
        while not self.stop.is_set():
            try:
                parts = shlex.split(input('lock> '))
            except (EOFError, KeyboardInterrupt):
                break
            if not parts:
                continue
            c, args = parts[0].lower(), parts[1:]
            try:
                self.run(c, args)
            except Exception as e:  # noqa: BLE001
                self.log(f'Lỗi: {e!r}')
        self.shutdown()

    def run(self, c, args):
        if c in ('quit', 'exit'):
            self.stop.set()
        elif c == 'help':
            print(self.HELP)
        elif c == 'tap':
            self.log(f'💳 Quẹt thẻ {args[0]}'); self.event('rfid', uid=args[0])
        elif c == 'pin':
            self.log('⌨️  Nhập PIN'); self.event('pin', pin=args[0])
        elif c in ('ble', 'nfc'):
            ok, reason = self.verify_ticket(c, args[0])
            self.log(f'📱 Vé {c.upper()}: ' + ('HỢP LỆ -> mở cửa' if ok else f'TỪ CHỐI ({reason})'))
            if ok:
                self.set_lock('unlocked', auto_relock=True)
            self.event(c, ticket=args[0], ok=ok, reason=reason)
            self.publish_status()
        elif c == 'tamper':
            self.state['tamper'] = (args[0] != 'off') if args else True
            self.log(f'🛠️  tamper={self.state["tamper"]}')
            if self.state['tamper']:
                self.event('tamper')
            self.publish_status()
        elif c == 'battery':
            self.state['battery'] = max(0, min(100, int(args[0]))); self.publish_status()
        elif c == 'signal':
            self.state['signal'] = int(args[0]); self.publish_status()
        elif c in ('lock', 'unlock'):
            self.set_lock('locked' if c == 'lock' else 'unlocked', auto_relock=(c == 'unlock')); self.publish_status()
        elif c == 'offline':
            self.c.disconnect(); self.c.loop_stop(); self.log('📴 Ngắt mạng')
        elif c == 'online':
            self.c.loop_start(); self.c.reconnect()
        elif c == 'set':
            key, val = args[0], float(args[1])
            if key not in ('fail_rate', 'ack_delay', 'relock_after', 'drain', 'status_every'):
                raise ValueError(f'tham số lạ: {key}')
            setattr(self, key, int(val) if key == 'drain' else val)
            self.log(f'⚙️  {key} = {val}'); self.publish_status()
        elif c == 'buzzer':
            self.buzzer_until = time.time() + (0 if args and args[0] == 'off' else 10); self.publish_status()
        elif c == 'status':
            print(json.dumps(self.snapshot(), indent=2, ensure_ascii=False)); self.publish_status()
        else:
            print('Không hiểu lệnh. Gõ "help".')

    def json_loop(self):
        for line in sys.stdin:
            line = line.strip()
            if not line:
                continue
            try:
                m = json.loads(line)
                self.run(str(m['cmd']).lower(), [str(x) for x in m.get('args', [])])
            except Exception as e:  # noqa: BLE001
                self.log(f'❌ Lệnh lỗi: {e!r}')
            if self.stop.is_set():
                break
        self.shutdown()

    def start(self):
        self.log(f'Khởi động khoá ảo {self.code} (MAC {self.mac}, fw {self.firmware})')
        self.c.connect_async(self.host, self.port, keepalive=30)
        self.c.loop_start()
        threading.Thread(target=self.status_loop, daemon=True).start()
        if self.json_mode:
            threading.Thread(target=self.ui_loop, daemon=True).start()
            self.emit('ready', code=self.code)
            self.json_loop()
        else:
            self.console()

    def shutdown(self):
        self.stop.set()
        self.c.loop_stop()
        self.c.disconnect()
        self.log('Đã tắt khoá ảo.')


def main():
    here = os.path.dirname(os.path.abspath(__file__))
    load_dotenv(os.path.join(here, '.env'))
    e = os.environ.get
    p = argparse.ArgumentParser(description='Khoá thông minh ảo (MQTT)')
    p.add_argument('--code', default=e('VDEV_CODE'), help='device_code (cũng là MQTT username)')
    p.add_argument('--secret', default=e('VDEV_SECRET'), help='provisioning secret gốc (MQTT password)')
    p.add_argument('--host', default=e('MQTT_HOST', 'localhost'))
    p.add_argument('--port', type=int, default=int(e('MQTT_PORT', 1883)))
    p.add_argument('--mac', default=e('VDEV_MAC', 'AA:BB:CC:00:00:01'))
    p.add_argument('--firmware', default=e('VDEV_FIRMWARE', '1.0.0-sim'))
    p.add_argument('--battery', type=int, default=int(e('VDEV_BATTERY', 100)))
    p.add_argument('--drain', type=int, default=0, help='%% pin tụt mỗi lần gửi status (0 = không tụt)')
    p.add_argument('--status-every', type=float, default=15, help='giây giữa 2 lần gửi status')
    p.add_argument('--relock-after', type=float, default=5, help='tự khoá lại sau N giây (0 = không)')
    p.add_argument('--ack-delay', type=float, default=0.3, help='độ trễ trước khi ack (giây)')
    p.add_argument('--json', action='store_true', help='giao tiếp JSON qua stdin/stdout (cho VS Code extension)')
    p.add_argument('--fail-rate', type=float, default=0.0, help='xác suất lệnh thất bại (0-1) để test lỗi')
    a = p.parse_args()
    if not a.code or not a.secret:
        p.error('Cần --code và --secret (hoặc VDEV_CODE / VDEV_SECRET trong .env)')
    VirtualLock(a).start()


if __name__ == '__main__':
    main()
