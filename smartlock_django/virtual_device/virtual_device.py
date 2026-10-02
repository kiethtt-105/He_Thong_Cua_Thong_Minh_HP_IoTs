#!/usr/bin/env python3
"""
Thiết bị khoá thông minh ẢO (giả lập đầy đủ như khoá thật) - nói đúng giao thức MQTT của hệ thống smartlock.

    pip install "paho-mqtt<2"
    python virtual_device.py                 # dùng thiết bị gần nhất (chưa có -> tự tạo 1 thiết bị mới)
    python virtual_device.py --new           # tạo thiết bị MỚI (xuất toàn bộ thông tin ra devices/<code>/device_info.txt)
    python virtual_device.py --code DEV-XXXX # chạy lại thiết bị cũ
    python virtual_device.py --list          # liệt kê thiết bị đã tạo
    python virtual_device.py --port 8765 --broker localhost:1883

Mở  http://localhost:8765/       -> giao diện khoá (bàn phím, thẻ, camera, BLE, NFC, pin, Wi-Fi...)
    http://localhost:8765/json   -> trang JSON live (trạng thái + mọi bản tin MQTT)
Mỗi thiết bị có thư mục devices/<code>/: identity.json, device_info.txt, activity.log, state.json, messages.jsonl
(mở state.json / messages.jsonl bằng VS Code + Live Server / JSON viewer cũng xem live được).
"""
import argparse, hashlib, hmac, json, os, queue, random, re, secrets, subprocess, sys, threading, time
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parent
DEVICES_DIR = ROOT / 'devices'
STATIC = ROOT / 'static'
PROJECT_DIR = ROOT.parent          # thư mục chứa manage.py
FIRMWARE = '1.0.0-virtual'
STATUS_INTERVAL = 30               # giây; server coi offline sau 180s
RELOCK_SECONDS = 5
LABELS = {'ble': b'ble-ticket-v1', 'nfc': b'nfc-phone-ticket-v1'}   # đúng services.PHONE_CHANNELS


def load_dotenv():
    for p in (PROJECT_DIR / '.env', ROOT / '.env'):
        if p.exists():
            for line in p.read_text(encoding='utf-8', errors='ignore').splitlines():
                m = re.match(r'\s*([A-Z_][A-Z0-9_]*)\s*=\s*(.*)\s*$', line)
                if m and not line.lstrip().startswith('#'):
                    os.environ.setdefault(m.group(1), m.group(2).strip().strip('"\''))


def now_iso():
    return datetime.now(timezone.utc).astimezone().isoformat(timespec='seconds')


def sha256(s):
    return hashlib.sha256(str(s).encode()).hexdigest()


# ------------------------------------------------------------------ danh tính thiết bị
def new_identity(name=None, location=''):
    code = f'DEV-{secrets.token_hex(4).upper()}'
    secret = secrets.token_hex(16)
    mac = ':'.join(f'{b:02X}' for b in [0x02] + [random.randint(0, 255) for _ in range(5)])
    return {'device_code': code, 'secret': secret, 'secret_hash': sha256(secret), 'mac': mac,
            'name': name or f'Khoá ảo {code[-4:]}', 'location': location or 'Phòng demo',
            'firmware': FIRMWARE, 'created_at': now_iso(), 'ble_name': f'SmartLock-{code[-4:]}'}


def write_device_info(d, ident, broker):
    host, port, tls = broker
    txt = f"""==================== THÔNG TIN KHOÁ (xuất lúc {now_iso()}) ====================
Tên khoá          : {ident['name']}
Vị trí            : {ident['location']}
Device code       : {ident['device_code']}
Provisioning secret: {ident['secret']}      <-- nhập vào ô "secret" khi thêm khoá (device-claim)
MAC               : {ident['mac']}
Bluetooth name    : {ident['ble_name']}
Firmware          : {ident['firmware']}
Chế độ            : simulated (thiết bị ảo)

--- MQTT (khoá thật nạp y hệt vào firmware) ---
Broker            : {host}:{port}  (TLS={tls})
Username          : {ident['device_code']}
Password          : {ident['secret']}
Subscribe         : smartlock/{ident['device_code']}/cmd
Publish           : smartlock/{ident['device_code']}/status | event | ack

--- Lưu trong DB (server chỉ giữ hash) ---
provisioning_secret_hash = {ident['secret_hash']}
(khoá vé BLE/NFC = HMAC-SHA256(key=secret_hash, msg=nhãn kênh))

--- Cách đưa khoá vào hệ thống ---
1) Đăng ký khoá vào DB (trạng thái provisioning, chưa có chủ), chạy trong thư mục chứa manage.py:
     python manage.py register_virtual_device "{(d / 'identity.json')}"
   (hoặc bấm nút "Đăng ký vào DB" trên giao diện thiết bị ảo)
2) Chạy broker MQTT + `python manage.py mqtt_subscriber`, rồi chạy thiết bị ảo để nó gửi status (khoá phải "đang kết nối").
3) Trên web: Thiết bị > Thêm khoá bằng mã (/devices/claim/) -> nhập Device code + Secret ở trên.
4) Sau khi claim xong khoá chuyển online; điều khiển, cấp PIN/thẻ/khuôn mặt/BLE/NFC như khoá thật.
"""
    (d / 'device_info.txt').write_text(txt, encoding='utf-8')


def device_dir(code):
    return DEVICES_DIR / code


def list_devices():
    out = []
    for p in sorted(DEVICES_DIR.glob('*/identity.json'), key=lambda x: x.stat().st_mtime):
        try:
            out.append(json.loads(p.read_text(encoding='utf-8')))
        except Exception:
            pass
    return out


# ------------------------------------------------------------------ thiết bị
class VirtualLock:
    def __init__(self, ident, broker):
        self.ident, self.broker = ident, broker
        self.code = ident['device_code']
        self.dir = device_dir(self.code)
        self.dir.mkdir(parents=True, exist_ok=True)
        self.lock = threading.RLock()
        self.subs = []                       # hàng đợi SSE
        self.messages = []                   # vòng đệm bản tin MQTT + log
        self.s = {'lock_state': 'locked', 'battery_level': 100, 'signal_strength': -52, 'tamper_detected': False,
                  'wifi': True, 'bluetooth': True, 'nfc': True, 'buzzer': False, 'led': 'red',
                  'mqtt': 'disconnected', 'keypad': '', 'last_event': '', 'drain': False,
                  'claimed_hint': 'chưa biết'}
        self.wallet = {'cards': [], 'tickets': {'ble': '', 'nfc': ''}}
        self._load_wallet()
        self.offline_queue = []
        self.client = None
        self._relock_timer = None
        self._buzzer_timer = None
        self.log(f'Khởi động thiết bị {self.code} firmware {FIRMWARE}')

    # ---- lưu trữ / log
    def _load_wallet(self):
        p = self.dir / 'wallet.json'
        if p.exists():
            try:
                self.wallet.update(json.loads(p.read_text(encoding='utf-8')))
            except Exception:
                pass
        if not self.wallet['cards']:
            self.wallet['cards'] = [{'name': 'Thẻ A', 'uid': secrets.token_hex(4).upper()},
                                    {'name': 'Thẻ lạ', 'uid': secrets.token_hex(4).upper()}]
            self._save_wallet()

    def _save_wallet(self):
        (self.dir / 'wallet.json').write_text(json.dumps(self.wallet, ensure_ascii=False, indent=2), encoding='utf-8')

    def _push(self, kind, data):
        item = {'t': now_iso(), 'kind': kind, **data}
        with self.lock:
            self.messages.append(item)
            del self.messages[:-300]
            for q in list(self.subs):
                try:
                    q.put_nowait(('msg', item))
                except queue.Full:
                    pass
        with open(self.dir / 'messages.jsonl', 'a', encoding='utf-8') as f:
            f.write(json.dumps(item, ensure_ascii=False) + '\n')
        return item

    def log(self, text, level='info'):
        item = self._push('log', {'level': level, 'text': text})
        with open(self.dir / 'activity.log', 'a', encoding='utf-8') as f:
            f.write(f"{item['t']} [{level.upper()}] {text}\n")
        print(f"[{self.code}] {text}")

    def snapshot(self):
        with self.lock:
            return {'identity': {k: v for k, v in self.ident.items() if k != 'secret_hash'},
                    'broker': {'host': self.broker[0], 'port': self.broker[1], 'tls': self.broker[2]},
                    'state': dict(self.s), 'wallet': self.wallet, 'queued_events': len(self.offline_queue),
                    'topics': {'cmd': f'smartlock/{self.code}/cmd', 'status': f'smartlock/{self.code}/status',
                               'event': f'smartlock/{self.code}/event', 'ack': f'smartlock/{self.code}/ack'},
                    'updated_at': now_iso()}

    def changed(self):
        snap = self.snapshot()
        tmp = self.dir / 'state.json.tmp'
        tmp.write_text(json.dumps(snap, ensure_ascii=False, indent=2), encoding='utf-8')
        os.replace(tmp, self.dir / 'state.json')
        with self.lock:
            for q in list(self.subs):
                try:
                    q.put_nowait(('state', snap))
                except queue.Full:
                    pass

    # ---- MQTT
    def start_mqtt(self):
        try:
            import paho.mqtt.client as mqtt
        except ImportError:
            self.log('Chưa cài paho-mqtt: pip install "paho-mqtt<2"', 'error')
            return
        try:
            c = mqtt.Client(mqtt.CallbackAPIVersion.VERSION1, client_id=self.code)   # paho 2.x
        except AttributeError:
            c = mqtt.Client(client_id=self.code)                                      # paho 1.x
        c.username_pw_set(self.code, self.ident['secret'])
        if self.broker[2]:
            c.tls_set()
        c.on_connect, c.on_disconnect, c.on_message = self._on_connect, self._on_disconnect, self._on_message
        c.reconnect_delay_set(1, 15)
        self.client = c
        threading.Thread(target=self._mqtt_connect_loop, daemon=True).start()
        threading.Thread(target=self._status_loop, daemon=True).start()
        threading.Thread(target=self._battery_loop, daemon=True).start()

    def _mqtt_connect_loop(self):
        started = False
        while True:
            if self.s['wifi'] and not started:
                try:
                    self.client.connect(self.broker[0], self.broker[1], keepalive=60)
                    self.client.loop_start()
                    started = True
                except Exception as e:
                    self.s['mqtt'] = f'lỗi: {e}'
                    self.changed()
            elif not self.s['wifi'] and started:
                self.client.loop_stop()
                try:
                    self.client.disconnect()
                except Exception:
                    pass
                started = False
                self.s['mqtt'] = 'wifi tắt'
                self.changed()
            time.sleep(3)

    def _on_connect(self, c, u, flags, rc, *a):
        if rc != 0:
            msg = {4: 'sai user/secret', 5: 'broker từ chối (auth/ACL)'}.get(rc, f'rc={rc}')
            self.s['mqtt'] = f'từ chối: {msg}'
            self.log(f'MQTT kết nối thất bại: {msg}', 'error')
            self.changed()
            return
        c.subscribe(f'smartlock/{self.code}/cmd', 1)
        self.s['mqtt'] = 'connected'
        self.log(f'MQTT đã kết nối {self.broker[0]}:{self.broker[1]}, subscribe smartlock/{self.code}/cmd')
        self.changed()
        self.publish_status()
        self._flush_queue()

    def _on_disconnect(self, c, u, rc, *a):
        if self.s['wifi']:
            self.s['mqtt'] = 'disconnected'
            self.log(f'MQTT mất kết nối rc={rc}', 'warning')
            self.changed()

    def _pub(self, channel, payload, qos=1):
        topic = f'smartlock/{self.code}/{channel}'
        self._push('mqtt_out', {'topic': topic, 'payload': payload})
        if self.client and self.s['mqtt'] == 'connected':
            self.client.publish(topic, json.dumps(payload, ensure_ascii=False), qos=qos)
            return True
        return False

    def publish_status(self):
        s = self.s
        return self._pub('status', {
            'battery_level': int(s['battery_level']), 'lock_state': s['lock_state'],
            'signal_strength': int(s['signal_strength']), 'tamper_detected': bool(s['tamper_detected']),
            'firmware': FIRMWARE, 'mac': self.ident['mac'], 'ip': '192.168.1.%d' % (hash(self.code) % 200 + 20)})

    def send_event(self, payload, queue_if_offline=False):
        ok = self._pub('event', payload)
        if not ok and queue_if_offline:
            self.offline_queue.append(payload)
            self.log(f"Offline: lưu hàng đợi sự kiện {payload.get('type')} (gửi lại khi có mạng)", 'warning')
        self.changed()
        return ok

    def _flush_queue(self):
        q, self.offline_queue = self.offline_queue, []
        for p in q:
            self.log(f"Gửi lại sự kiện offline {p.get('type')}")
            self._pub('event', p)
        if q:
            self.changed()

    def _status_loop(self):
        while True:
            time.sleep(STATUS_INTERVAL)
            if self.s['mqtt'] == 'connected':
                self.publish_status()

    def _battery_loop(self):
        while True:
            time.sleep(20)
            if self.s['drain'] and self.s['battery_level'] > 0:
                self.s['battery_level'] -= 1
                self.changed()

    # ---- nhận lệnh từ server
    def _on_message(self, c, u, msg):
        try:
            p = json.loads(msg.payload.decode('utf-8'))
        except Exception:
            self.log('Nhận cmd không phải JSON', 'warning')
            return
        self._push('mqtt_in', {'topic': msg.topic, 'payload': p})
        cmd = str(p.get('command', '')).upper()
        result = 'ok'
        if cmd == 'UNLOCK':
            self.set_lock('unlocked', f"lệnh từ xa ({p.get('source', '?')})", auto_relock=True)
        elif cmd == 'LOCK':
            self.set_lock('locked', f"lệnh từ xa ({p.get('source', '?')})")
        elif cmd == 'PING':
            self.log('PING từ server -> ack')
        elif cmd == 'BUZZER_ALERT':
            self.buzz(10, f"cảnh báo {p.get('reason', '')}")
        elif cmd == 'REBOOT':
            self.log('REBOOT: khởi động lại giả lập 3s', 'warning')
            threading.Thread(target=self._reboot, daemon=True).start()
        elif cmd in ('RESET',):
            self.log('RESET nhận được (giả lập: chỉ ghi log)', 'warning')
        else:
            result = 'failed'
            self.log(f'Lệnh không hỗ trợ: {cmd}', 'warning')
        if p.get('command_id'):
            self._pub('ack', {'command_id': p['command_id'], 'token': p.get('token'), 'result': result})

    def _reboot(self):
        self.s['led'] = 'off'
        self.changed()
        time.sleep(3)
        self.s['led'] = 'red' if self.s['lock_state'] == 'locked' else 'green'
        self.log('Khởi động lại xong')
        self.publish_status()
        self.changed()

    # ---- phần cứng
    def set_lock(self, state, why, auto_relock=False):
        with self.lock:
            if self._relock_timer:
                self._relock_timer.cancel()
            self.s['lock_state'] = state
            self.s['led'] = 'green' if state == 'unlocked' else 'red'
            if state == 'unlocked':
                self.s['battery_level'] = max(0, self.s['battery_level'] - 0)
            if auto_relock:
                self._relock_timer = threading.Timer(RELOCK_SECONDS, self.set_lock, ('locked', 'tự khoá lại'))
                self._relock_timer.daemon = True
                self._relock_timer.start()
        self.log(f"Servo: {'MỞ' if state == 'unlocked' else 'KHOÁ'} cửa - {why}")
        self.publish_status()
        self.changed()

    def buzz(self, seconds, why=''):
        self.s['buzzer'] = True
        self.log(f'Còi kêu {seconds}s {why}', 'warning')
        self.changed()
        if self._buzzer_timer:
            self._buzzer_timer.cancel()
        self._buzzer_timer = threading.Timer(seconds, self._buzz_off)
        self._buzzer_timer.daemon = True
        self._buzzer_timer.start()

    def _buzz_off(self):
        self.s['buzzer'] = False
        self.changed()

    # ---- tương tác người dùng
    def keypad(self, key):
        k = self.s['keypad']
        if key == '*':
            self.s['keypad'] = ''
        elif key == '#':
            pin, self.s['keypad'] = k, ''
            if not pin:
                return {'ok': False, 'message': 'Chưa nhập PIN'}
            return self._need_server('pin_entry', {'type': 'pin_entry', 'pin': pin[:16]}, 'PIN')
        elif key.isdigit() and len(k) < 16:
            self.s['keypad'] = k + key
        self.changed()
        return {'ok': True}

    def _need_server(self, label, payload, what):
        if not self.send_event(payload):
            self.log(f'{what}: không có mạng/MQTT nên không xác thực được (khoá thật cũng vậy)', 'warning')
            self.buzz(1, '(từ chối)')
            return {'ok': False, 'message': 'Offline: PIN/thẻ/khuôn mặt cần server xác thực'}
        self.log(f'{what}: đã gửi lên server, chờ lệnh UNLOCK')
        return {'ok': True, 'message': 'Đã gửi, chờ server'}

    def rfid_tap(self, uid):
        uid = re.sub(r'[\s:\-]', '', uid or '').upper()
        if not uid:
            return {'ok': False, 'message': 'UID trống'}
        return self._need_server('rfid', {'type': 'rfid_tap', 'uid': uid[:64]}, f'Thẻ {uid}')

    def face(self, embedding, snapshot_url=''):
        if not (isinstance(embedding, list) and 0 < len(embedding) <= 512):
            return {'ok': False, 'message': 'Embedding không hợp lệ'}
        return self._need_server('face', {'type': 'face_result', 'embedding': [float(x) for x in embedding],
                                          'snapshot_url': snapshot_url or ''}, 'Khuôn mặt')

    def _ticket_ok(self, ticket, kind):
        """Khoá TỰ kiểm tra vé (không cần mạng): chữ ký HMAC + hạn, giống services._ticket_sig."""
        try:
            user_hex, exp_s, sig = ticket.strip().split('.')
            exp = int(exp_s)
        except ValueError:
            return False, f'{kind.upper()}_INVALID_TICKET'
        key = hmac.new(self.ident['secret_hash'].encode(), LABELS[kind], hashlib.sha256).digest()
        want = hmac.new(key, f'{self.code}|{user_hex}|{exp}'.encode(), hashlib.sha256).hexdigest()[:32]
        if not hmac.compare_digest(sig, want):
            return False, f'{kind.upper()}_INVALID_TICKET'
        if exp < time.time():
            return False, f'{kind.upper()}_TICKET_EXPIRED'
        return True, None

    def phone_unlock(self, kind, ticket):
        name = 'Bluetooth' if kind == 'ble' else 'NFC điện thoại'
        if not self.s['bluetooth' if kind == 'ble' else 'nfc']:
            self.log(f'{name} đang tắt trên khoá', 'warning')
            return {'ok': False, 'message': f'{name} đang tắt'}
        ticket = (ticket or self.wallet['tickets'][kind]).strip()
        if not ticket:
            return {'ok': False, 'message': 'Chưa có vé (lấy từ app: ble-ticket / nfc-ticket)'}
        ok, reason = self._ticket_ok(ticket, kind)
        at = int(time.time())
        evt = {'type': 'ble_unlock' if kind == 'ble' else 'nfc_unlock', 'ticket': ticket[:200],
               'result': 'ok' if ok else 'denied', 'at': at}
        if reason:
            evt['reason'] = reason
        if ok:
            self.set_lock('unlocked', f'vé {name} hợp lệ (xác thực tại chỗ)', auto_relock=True)
        else:
            self.log(f'{name}: vé bị từ chối ({reason})', 'warning')
            self.buzz(1, '(từ chối)')
        self.send_event(evt, queue_if_offline=True)
        return {'ok': ok, 'message': 'Đã mở' if ok else f'Từ chối: {reason}'}

    def action(self, a):
        t = a.get('type')
        s = self.s
        if t == 'keypad':
            return self.keypad(str(a.get('key', '')))
        if t == 'rfid':
            return self.rfid_tap(a.get('uid', ''))
        if t == 'face':
            return self.face(a.get('embedding'), a.get('snapshot_url', ''))
        if t in ('ble', 'nfc'):
            if a.get('ticket'):
                self.wallet['tickets'][t] = a['ticket'].strip()
                self._save_wallet()
            return self.phone_unlock(t, a.get('ticket', ''))
        if t == 'toggle' and a.get('name') in ('wifi', 'bluetooth', 'nfc', 'drain', 'tamper_detected'):
            n = a['name']
            s[n] = bool(a.get('value'))
            self.log(f"{n} = {'BẬT' if s[n] else 'TẮT'}", 'warning' if n == 'tamper_detected' and s[n] else 'info')
            if n == 'tamper_detected' and s[n]:
                self.buzz(5, '(phát hiện cạy phá)')
            if n != 'wifi':
                self.publish_status()
        elif t == 'battery':
            s['battery_level'] = max(0, min(100, int(a.get('value', 100))))
            self.publish_status()
        elif t == 'signal':
            s['signal_strength'] = max(-100, min(-20, int(a.get('value', -52))))
        elif t == 'lock':
            self.set_lock('locked', 'nút vật lý trong nhà')
        elif t == 'unlock':
            self.set_lock('unlocked', 'núm xoay trong nhà', auto_relock=True)
        elif t == 'status':
            self.publish_status()
        elif t == 'card_add':
            self.wallet['cards'].append({'name': a.get('name') or 'Thẻ mới', 'uid': (a.get('uid') or secrets.token_hex(4)).upper()})
            self._save_wallet()
        elif t == 'card_del':
            self.wallet['cards'] = [c for c in self.wallet['cards'] if c['uid'] != a.get('uid')]
            self._save_wallet()
        elif t == 'set_secret':
            sec = (a.get('secret') or '').strip()
            if len(sec) < 8:
                return {'ok': False, 'message': 'Secret quá ngắn'}
            self.ident.update(secret=sec, secret_hash=sha256(sec))
            (self.dir / 'identity.json').write_text(json.dumps(self.ident, ensure_ascii=False, indent=2), encoding='utf-8')
            write_device_info(self.dir, self.ident, self.broker)
            self.log('Đã nạp secret mới (xoay secret) - kết nối lại MQTT', 'warning')
            if self.client:
                self.client.username_pw_set(self.code, sec)
                self.client.reconnect() if self.s['mqtt'] == 'connected' else None
        elif t == 'register_db':
            return register_in_db(self.dir / 'identity.json')
        else:
            return {'ok': False, 'message': 'Hành động không hợp lệ'}
        self.changed()
        return {'ok': True}


def register_in_db(identity_path):
    manage = PROJECT_DIR / 'manage.py'
    if not manage.exists():
        return {'ok': False, 'message': f'Không thấy {manage}. Chạy tay: python manage.py register_virtual_device "{identity_path}"'}
    r = subprocess.run([sys.executable, str(manage), 'register_virtual_device', str(identity_path)],
                       cwd=str(PROJECT_DIR), capture_output=True, text=True, timeout=120)
    return {'ok': r.returncode == 0, 'message': (r.stdout + r.stderr).strip()[-600:]}


# ------------------------------------------------------------------ web server
def make_handler(dev):
    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def _send(self, code, body, ctype='application/json; charset=utf-8'):
            if isinstance(body, (dict, list)):
                body = json.dumps(body, ensure_ascii=False).encode()
            elif isinstance(body, str):
                body = body.encode()
            self.send_response(code)
            self.send_header('Content-Type', ctype)
            self.send_header('Content-Length', str(len(body)))
            self.send_header('Cache-Control', 'no-store')
            self.send_header('Access-Control-Allow-Origin', '*')   # cho Live Server (cổng khác) đọc được
            self.end_headers()
            self.wfile.write(body)

        def do_OPTIONS(self):
            self.send_response(204)
            for k, v in (('Access-Control-Allow-Origin', '*'), ('Access-Control-Allow-Headers', 'Content-Type'),
                         ('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')):
                self.send_header(k, v)
            self.end_headers()

        def do_GET(self):
            path = self.path.split('?')[0]
            if path in ('/', '/index.html'):
                return self._send(200, (STATIC / 'index.html').read_bytes(), 'text/html; charset=utf-8')
            if path in ('/json', '/json.html'):
                return self._send(200, (STATIC / 'json.html').read_bytes(), 'text/html; charset=utf-8')
            if path in ('/api/state', '/state.json'):
                return self._send(200, dev.snapshot())
            if path == '/api/messages':
                return self._send(200, dev.messages[-300:])
            if path == '/api/info':
                return self._send(200, (dev.dir / 'device_info.txt').read_text(encoding='utf-8'), 'text/plain; charset=utf-8')
            if path == '/events':
                return self._sse()
            self._send(404, {'ok': False})

        def do_POST(self):
            if self.path != '/api/action':
                return self._send(404, {'ok': False})
            try:
                n = int(self.headers.get('Content-Length') or 0)
                data = json.loads(self.rfile.read(n) or b'{}')
                self._send(200, dev.action(data) or {'ok': True})
            except Exception as e:
                dev.log(f'Lỗi action: {e}', 'error')
                self._send(500, {'ok': False, 'message': str(e)})

        def _sse(self):
            q = queue.Queue(maxsize=200)
            dev.subs.append(q)
            self.send_response(200)
            self.send_header('Content-Type', 'text/event-stream')
            self.send_header('Cache-Control', 'no-cache')
            self.send_header('Access-Control-Allow-Origin', '*')
            self.end_headers()
            try:
                def w(ev, data):
                    self.wfile.write(f'event: {ev}\ndata: {json.dumps(data, ensure_ascii=False)}\n\n'.encode())
                    self.wfile.flush()
                w('state', dev.snapshot())
                for m in dev.messages[-100:]:
                    w('msg', m)
                while True:
                    try:
                        w(*q.get(timeout=15))
                    except queue.Empty:
                        self.wfile.write(b': ping\n\n')
                        self.wfile.flush()
            except (BrokenPipeError, ConnectionResetError, OSError):
                pass
            finally:
                if q in dev.subs:
                    dev.subs.remove(q)
    return H


def main():
    load_dotenv()
    ap = argparse.ArgumentParser(description='Thiết bị khoá thông minh ảo')
    ap.add_argument('--new', action='store_true', help='tạo thiết bị mới')
    ap.add_argument('--code', help='chạy thiết bị đã tạo')
    ap.add_argument('--list', action='store_true')
    ap.add_argument('--name'), ap.add_argument('--location', default='')
    ap.add_argument('--port', type=int, default=8765)
    ap.add_argument('--broker', default='', help='host:port (mặc định lấy từ .env MQTT_HOST/MQTT_PORT hoặc localhost:1883)')
    ap.add_argument('--tls', action='store_true')
    ap.add_argument('--register', action='store_true', help='tự đăng ký thiết bị vào DB (gọi manage.py) khi khởi động')
    a = ap.parse_args()

    DEVICES_DIR.mkdir(exist_ok=True)
    if a.list:
        for i in list_devices():
            print(f"{i['device_code']}  {i['name']}  {i['mac']}  {i['created_at']}")
        return
    host = os.environ.get('MQTT_BROKER_HOST') or os.environ.get('MQTT_HOST') or 'localhost'
    port = int(os.environ.get('MQTT_BROKER_PORT') or os.environ.get('MQTT_PORT') or 1883)
    if a.broker:
        host, _, p = a.broker.partition(':')
        port = int(p or 1883)
    tls = a.tls or os.environ.get('MQTT_BROKER_USE_TLS', '').lower() in ('1', 'true', 'yes')
    broker = (host, port, tls)

    existing = list_devices()
    if a.code:
        ident = next((i for i in existing if i['device_code'] == a.code.upper()), None)
        if not ident:
            sys.exit(f'Không có thiết bị {a.code} trong {DEVICES_DIR}')
    elif a.new or not existing:
        ident = new_identity(a.name, a.location)
        d = device_dir(ident['device_code'])
        d.mkdir(parents=True, exist_ok=True)
        (d / 'identity.json').write_text(json.dumps(ident, ensure_ascii=False, indent=2), encoding='utf-8')
        write_device_info(d, ident, broker)
        print(f"\n>>> Đã tạo thiết bị mới. Toàn bộ thông tin: {d / 'device_info.txt'}\n")
    else:
        ident = existing[-1]
    write_device_info(device_dir(ident['device_code']), ident, broker)

    if a.register:
        print('Đăng ký DB:', register_in_db(device_dir(ident['device_code']) / 'identity.json')['message'])

    dev = VirtualLock(ident, broker)
    dev.start_mqtt()
    dev.changed()
    srv = ThreadingHTTPServer(('0.0.0.0', a.port), make_handler(dev))
    print(f"Thiết bị {ident['device_code']}  |  UI: http://localhost:{a.port}/  |  JSON: http://localhost:{a.port}/json")
    print(f"Broker: {host}:{port} (TLS={tls})   Ctrl+C để dừng")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print('\nDừng.')


if __name__ == '__main__':
    main()
