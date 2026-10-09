"""Bộ điều khiển khoá - mô phỏng firmware ESP32: boot, heartbeat, nhận lệnh (HTTP polling + MQTT tuỳ chọn), mở khoá theo phán quyết server,
kiểm vé offline, hàng đợi sự kiện offline, cảnh báo (TAMPER / FORCED_OPEN / DOOR_LEFT_OPEN), OTA, tự khoá lại."""
import json
import random
import threading
import time
from collections import OrderedDict, deque

from . import netinfo, store, tickets
from .api import ApiError, DeviceApi, NetError
from .hal import SimHAL
from .mqttlink import MqttLink

SCAN = [('Home_WiFi_2.4G', -48, True), ('Office_Net', -61, True), ('Hotspot_Phone', -55, True), ('Cafe_Free', -72, False)]
VALID_EVENTS = ('BOOT', 'TAMPER', 'FORCED_OPEN', 'DOOR_LEFT_OPEN', 'LOW_BATTERY')


class Controller:
    def __init__(self, overrides=None):
        self.overrides = overrides or {}
        self.logs, self._seq = deque(maxlen=400), 0
        self._mtx = threading.RLock()
        self._stop = threading.Event()
        self._threads = []
        self.mqtt = None
        self.wifi_live = {}
        self.cfg = store.load_config()
        self._ensure_mac()
        self.hal = SimHAL(self.cfg['hardware'])
        self.hal.on_door_change = self._on_door
        self.api = DeviceApi(self._creds)
        self.api.timeout = float(self.cfg['network'].get('http_timeout_seconds') or 10)
        self._runtime_reset()

    # ------------------------------------------------------------------ tiện ích
    def _runtime_reset(self):
        rt = store.load(store.RUNTIME_PATH, {})
        self.sc = rt.get('sc') or {}      # cấu hình server gửi về - nạp lại từ flash để sau reboot/mất mạng vẫn biết cờ BLE/NFC...
        self.online, self.auth_failed = False, False
        self.wifi_up = True               # công tắc "Wi-Fi" mô phỏng
        self.offset = 0.0                 # lệch giờ so với server
        self.backoff_until = 0.0
        self.seen = OrderedDict((k, time.time()) for k in (rt.get('seen') or []))   # command_id đã xử lý (sống qua reboot)
        self.locked_out = bool(rt.get('locked_out'))
        self.last_hb = 0.0
        self.last_error = ''
        self.last_access = None
        self.booted_at = time.time()
        self._opened_at = None            # lúc mở khoá (để tự khoá lại)
        self._door_since = None
        self._door_warned = False
        self._ota_busy = False
        self._last_drain = time.time()
        self._hb_wake = threading.Event()
        self.queue = store.load(store.QUEUE_PATH, {'events': [], 'phone': []})

    def log(self, msg, lvl='info'):
        with self._mtx:
            self._seq += 1
            self.logs.append({'id': self._seq, 't': time.strftime('%H:%M:%S'), 'lvl': lvl, 'm': msg})
        print(f'[{time.strftime("%H:%M:%S")}] {msg}', flush=True)

    def now(self):
        return time.time() + self.offset

    def configured(self):
        c = self.cfg
        return bool(c.get('device_code') and c.get('secret') and self.server_url())

    def server_url(self):
        if self.overrides.get('server'):
            return self.overrides['server']
        s = self.cfg.get('server') or {}
        return (s.get('urls') or {}).get(s.get('active'), '')

    def _ensure_mac(self):
        hw = self.cfg['hardware']
        if not hw.get('mac'):
            hw['mac'] = 'A4:CF:12:%02X:%02X:%02X' % tuple(random.randint(0, 255) for _ in range(3))
            store.save_overrides({'hardware': {'mac': hw['mac']}})      # MAC cố định qua các lần chạy (như eFuse)

    def _reload_cfg(self):
        self.cfg = store.load_config()
        self._ensure_mac()
        self.hal.hw = self.cfg['hardware']
        self.api.timeout = float(self.cfg['network'].get('http_timeout_seconds') or 10)

    def _creds(self):
        return self.server_url(), self.cfg.get('device_code', ''), self.cfg.get('secret', '')

    # ------------------------------------------------------------------ vòng đời
    def start(self):
        if not self.configured():
            self.log('Chưa cấu hình -> chế độ SETUP (mở web UI để nhập Wi-Fi + thông tin từ trang admin)', 'warn')
            return
        self.boot()

    def boot(self):
        self._stop = threading.Event()
        self._runtime_reset()
        self.hal.lock_state = 'locked' if self.hal.lock_state != 'jammed' else 'jammed'
        self.log(f'BOOT  code={self.cfg["device_code"]}  fw={self.cfg["hardware"]["firmware"]}  mac={self.cfg["hardware"]["mac"]}  server={self.server_url()}', 'ok')
        m = self.cfg.get('mqtt') or {}
        if m.get('enabled'):
            self.mqtt = MqttLink(self)
            self.mqtt.start(m, self.cfg['device_code'], self.cfg['secret'])
        for fn in (self._hb_loop, self._poll_loop, self._tick_loop, self._wifi_loop):
            t = threading.Thread(target=fn, args=(self._stop,), daemon=True)
            t.start()
            self._threads.append(t)
        threading.Thread(target=self.raise_event, args=('BOOT',), daemon=True).start()

    def shutdown(self):
        self._stop.set()
        self._hb_wake.set()
        if self.mqtt:
            self.mqtt.stop()
            self.mqtt = None
        for t in self._threads:
            t.join(timeout=2)
        self._threads = []

    def reboot(self):
        self.log('REBOOT...', 'warn')
        self.shutdown()
        time.sleep(1.0)
        self._reload_cfg()
        self.boot()

    def factory_reset(self):
        self.log('FACTORY RESET: xoá cấu hình + hàng đợi -> về chế độ SETUP', 'warn')
        self.shutdown()
        store.clear_config()                 # chỉ xoá state/; config.json của bạn được giữ nguyên
        self._reload_cfg()
        self._runtime_reset()
        if self.configured():
            self.log('config.json đã đủ thông tin -> khởi động lại luôn', 'warn')
            self.boot()

    # ------------------------------------------------------------------ setup / provisioning
    def provision(self, d):
        ssid, pw = (d.get('ssid') or '').strip(), d.get('password') or ''
        code, secret = (d.get('device_code') or '').strip().upper(), (d.get('secret') or '').strip()
        url = (d.get('server') or '').strip().rstrip('/')
        if url.endswith('/api/device'):
            url = url[:-len('/api/device')]
        if self.wifi_host():
            cur = (netinfo.status(True).get('connected') or {}).get('ssid', '')
            if cur and ssid and ssid != cur:
                return False, (f'Giả lập dùng Wi-Fi THẬT của máy, mà máy đang nối "{cur}". Hãy chọn đúng mạng đó '
                               f'(hoặc đổi Wi-Fi của máy rồi bấm quét lại).')
            ssid, pw = ssid or cur or 'Ethernet', ''
        else:
            if not ssid:
                return False, 'Chưa chọn Wi-Fi.'
            known = {n: sec for n, _, sec in SCAN}
            if known.get(ssid, True) and len(pw) < 8:
                return False, f'Không kết nối được Wi-Fi "{ssid}": mật khẩu WPA2 phải từ 8 ký tự.'
        if not (url.startswith('http://') or url.startswith('https://')):
            return False, 'Server phải bắt đầu bằng http:// hoặc https://'
        if not code or not secret:
            return False, 'Thiếu mã thiết bị hoặc secret.'
        name = 'vercel' if 'vercel.app' in url else ('tunnel' if 'devtunnels' in url else ('local' if '127.0.0.1' in url or 'localhost' in url else 'server'))
        store.save_overrides({'wifi': {'ssid': ssid, 'password': pw}, 'server': {'active': name, 'urls': {name: url}},
                              'device_code': code, 'secret': secret})
        self._reload_cfg()
        self.shutdown()
        self.log(f'Đã lưu cấu hình, kết nối Wi-Fi "{ssid}" OK -> khởi động', 'ok')
        self.boot()
        return True, 'Đã lưu. Khoá đang khởi động và kết nối server...'

    def switch_server(self, name, url=None):
        urls = dict((self.cfg.get('server') or {}).get('urls') or {})
        if url:
            urls[name] = url.rstrip('/')
        if name not in urls:
            return False, 'Không có server tên đó.'
        store.save_overrides({'server': {'active': name, 'urls': urls}})
        self._reload_cfg()
        s = self.cfg['server']
        self.log(f'Đổi server -> {name}: {s["urls"][name]}', 'warn')
        self.auth_failed, self.backoff_until = False, 0
        self._hb_wake.set()
        return True, 'OK'

    # ------------------------------------------------------------------ gọi API
    def _call(self, name, *args):
        if not self.wifi_up:
            raise NetError('Wi-Fi tắt')
        if time.time() < self.backoff_until:
            raise NetError('đang chờ sau lỗi 429')
        try:
            res = getattr(self.api, name)(*args)
        except ApiError as e:
            self.online = True
            self.last_error = f'{e.code}: {e.message}'
            if e.code == 'DEVICE_AUTH_FAILED':
                if not self.auth_failed:
                    self.log('Server từ chối: mã thiết bị/secret sai (secret đã bị xoay?). Cấu hình lại secret.', 'err')
                self.auth_failed = True
            if e.status == 429:
                self.backoff_until = time.time() + float(e.retry_after or 60)
            raise
        except NetError as e:
            if self.online:
                self.log(f'Mất kết nối server: {e}', 'warn')
            self.online, self.last_error = False, str(e)
            raise
        if not self.online:
            self.log('Đã kết nối server', 'ok')
        self.online, self.auth_failed, self.last_error = True, False, ''
        if isinstance(res, dict) and 'unix_time' in res:
            self.offset = float(res['unix_time']) - time.time()
        return res

    def _save_runtime(self):
        with self._mtx:
            store.save(store.RUNTIME_PATH, {'sc': self.sc, 'locked_out': self.locked_out, 'seen': list(self.seen)[-100:]})

    def _apply_config(self, r):
        for k in ('status', 'has_owner', 'wifi_enabled', 'bluetooth_enabled', 'nfc_enabled', 'intervals', 'ticket_ttl_seconds',
                  'face', 'ota', 'nfc_auto_register'):
            if k in r:
                self.sc[k] = r[k]
        if 'locked_out' in r:
            self.locked_out = bool(r['locked_out'])
        self._save_runtime()
        ota = r.get('ota') or {}
        if ota.get('available') and self.cfg['hardware'].get('auto_ota'):
            threading.Thread(target=self.do_ota, args=(ota,), daemon=True).start()

    # ------------------------------------------------------------------ vòng lặp nền
    def _hb_payload(self):
        h = self.hal
        return {'battery': int(h.battery), 'signal': int(h.signal), 'lock_state': h.lock_state, 'tamper': bool(h.tamper),
                'temperature': h.temperature, 'firmware': self.cfg['hardware']['firmware'], 'mac': self.cfg['hardware']['mac']}

    def heartbeat(self):
        try:
            r = self._call('heartbeat', self._hb_payload())
        except (ApiError, NetError):
            return False
        self.last_hb = time.time()
        self._apply_config(r)
        for c in r.get('commands') or []:
            self.handle_command(c, 'http')
        self._flush_queue()
        if self.mqtt:
            self.mqtt.publish('status', self._hb_payload())
        return True

    def _hb_loop(self, stop):
        self.heartbeat()
        while not stop.is_set():
            iv = float(self.overrides.get('heartbeat') or self.cfg['network'].get('heartbeat_seconds')
                       or (self.sc.get('intervals') or {}).get('heartbeat_seconds', 60))
            if not self.online or self.last_error:
                iv = min(iv, 10.0)                 # chưa tới được server: thử lại sớm
            self._hb_wake.wait(iv)
            if stop.is_set():
                return
            if self._hb_wake.is_set():            # bị đánh thức vì đổi trạng thái: gộp các lần đổi liên tiếp
                self._hb_wake.clear()
                time.sleep(1.0)
            if self.auth_failed:
                stop.wait(30)
            self.heartbeat()

    def _poll_loop(self, stop):
        while not stop.is_set():
            iv = float(self.overrides.get('poll') or self.cfg['network'].get('poll_seconds')
                       or (self.sc.get('intervals') or {}).get('command_poll_seconds', 3))
            stop.wait(30 if self.auth_failed else iv)
            if stop.is_set() or not self.sc:          # chưa heartbeat được lần nào thì chưa poll
                continue
            if self.sc.get('wifi_enabled') is False:
                continue
            try:
                r = self._call('commands')
            except (ApiError, NetError):
                continue
            for c in r.get('commands') or []:
                self.handle_command(c, 'http')

    def _tick_loop(self, stop):
        hw = self.cfg['hardware']
        while not stop.wait(0.5):
            h, now = self.hal, time.time()
            drain = float(hw.get('battery_drain_minutes') or 0)
            if drain and now - self._last_drain >= drain * 60:
                self._last_drain, h.battery = now, max(0.0, h.battery - 1)
            if h.lock_state == 'unlocked' and self._opened_at and not h.door_open \
                    and now - self._opened_at >= float(hw.get('auto_lock_seconds', 5)):
                self._opened_at = None
                self.log('Tự khoá lại sau khi cửa đóng')
                self.hal.lock()
                self._wake()
            if h.door_open and self._door_since and not self._door_warned \
                    and now - self._door_since >= float(hw.get('door_left_open_seconds', 60)):
                self._door_warned = True
                self.raise_event('DOOR_LEFT_OPEN', {'seconds': int(now - self._door_since)})

    def wifi_host(self):
        return (self.cfg.get('wifi') or {}).get('source', 'host') == 'host'

    def _wifi_loop(self, stop):
        """Chế độ host: lấy SSID + RSSI thật của máy mỗi 10s (RSSI thật đi vào heartbeat)."""
        while not stop.is_set():
            if self.wifi_host():
                try:
                    self.wifi_live = netinfo.status(force=True)
                    c = self.wifi_live.get('connected')
                    if c and c.get('rssi') is not None:
                        self.hal.signal = c['rssi']
                except Exception as e:
                    self.wifi_live = {'error': str(e)}
            stop.wait(10)

    def wifi_scan(self):
        if not self.wifi_host():
            return {'source': 'simulated', 'current': '', 'error': '',
                    'networks': [{'ssid': s, 'rssi': r, 'secured': sec, 'connected': False} for s, r, sec in SCAN]}
        st = netinfo.status(force=True)
        return {'source': 'host', 'platform': st['platform'], 'current': (st['connected'] or {}).get('ssid', ''),
                'networks': st['networks'], 'error': st['error']}

    def _wake(self):
        self._hb_wake.set()

    # ------------------------------------------------------------------ cảm biến / sự kiện
    def _on_door(self, is_open):
        self.log('Cửa MỞ' if is_open else 'Cửa ĐÓNG')
        if is_open:
            self._door_since, self._door_warned = time.time(), False
            if self.hal.lock_state == 'locked':
                self.hal.beep('alarm')
                threading.Thread(target=self.raise_event, args=('FORCED_OPEN',), daemon=True).start()
        else:
            self._door_since = None
        self._wake()

    def set_tamper(self, on):
        self.hal.shock(on)
        if on:
            self.hal.beep('alarm')
            threading.Thread(target=self.raise_event, args=('TAMPER', {'source': 'accelerometer'}), daemon=True).start()
        self._wake()

    def raise_event(self, kind, data=None):
        ev = {'type': kind, 'at': int(self.now())}
        if data:
            ev['data'] = data
        self.log(f'EVENT {kind}', 'warn' if kind != 'BOOT' else 'info')
        try:
            self._call('events', ev)
        except ApiError as e:
            if e.status in (400, 409):
                return                       # lỗi nghiệp vụ: gửi lại cũng vô ích
            self._enqueue('events', ev)
        except NetError:
            self._enqueue('events', ev)
        if self.mqtt:
            self.mqtt.publish('event', ev)

    def _enqueue(self, kind, item):
        with self._mtx:
            q = self.queue.setdefault(kind, [])
            q.append(item)
            del q[:-int(self.cfg['network'].get('offline_queue_max') or 200)]
            store.save(store.QUEUE_PATH, self.queue)
        self.log(f'Offline: xếp hàng {kind} ({len(self.queue[kind])} đang chờ)', 'warn')

    def _flush_queue(self):
        for kind, fn, key in (('events', 'events', 'events'), ('phone', 'access_phone', None)):
            while True:
                with self._mtx:
                    batch = list(self.queue.get(kind, []))[:50]
                if not batch:
                    break
                try:
                    self._call(fn, {'events': batch} if kind == 'events' else batch)
                except ApiError as e:
                    if e.status not in (400, 409):
                        break
                except NetError:
                    return
                with self._mtx:
                    self.queue[kind] = self.queue[kind][len(batch):]
                    store.save(store.QUEUE_PATH, self.queue)
                self.log(f'Đã gửi bù {len(batch)} {kind} từ hàng đợi offline', 'ok')

    # ------------------------------------------------------------------ lệnh từ server
    def handle_command(self, c, via):
        cid, name, token = c.get('command_id'), str(c.get('command') or '').upper(), c.get('token')
        if not cid:
            return
        with self._mtx:
            if cid in self.seen:                       # cùng 1 lệnh có thể được trả lại nhiều lần (heartbeat + poll)
                return
            exp_in = c.get('expires_in')
            if exp_in is None and c.get('expires_at'):
                exp_in = float(c['expires_at']) - self.now()
            self.seen[cid] = time.time()
            while len(self.seen) > 200:
                self.seen.popitem(last=False)
        self._save_runtime()
        if exp_in is not None and exp_in <= 0:
            self.log(f'Bỏ lệnh {name} đã hết hạn ({via})', 'warn')
            return
        self.log(f'LỆNH {name} qua {via.upper()} (source={c.get("source", "-")})', 'ok')
        ok, err, after = self._execute(name, c)
        ack = {'command_id': cid, 'token': token, 'success': ok, 'lock_state': self.hal.lock_state}
        if err:
            ack['error'] = err
        for i in range(3):
            try:
                self._call('ack', ack)
                break
            except ApiError as e:
                self.log(f'Ack lỗi: {e.code}', 'warn')
                if e.status in (403, 404):
                    break
            except NetError:
                time.sleep(1)
        if self.mqtt:
            self.mqtt.publish('ack', ack)
        self._wake()
        if after:
            after()

    def _execute(self, name, c):
        """-> (success, error, hàm chạy sau khi ack)"""
        if name == 'UNLOCK':
            ok = self.do_unlock('remote')
            return ok, None if ok else 'JAMMED', None
        if name == 'LOCK':
            self._opened_at = None
            ok = self.hal.lock()
            self.log('Khoá cửa' if ok else 'Kẹt chốt!', 'ok' if ok else 'err')
            return ok, None if ok else 'JAMMED', None
        if name == 'PING':
            return True, None, None
        if name == 'REBOOT':
            return True, None, lambda: threading.Thread(target=self.reboot, daemon=True).start()
        if name == 'OTA_UPDATE':
            threading.Thread(target=self.do_ota, args=(self.sc.get('ota') or {},), daemon=True).start()
            return True, None, None
        if name == 'RESET':
            return True, None, lambda: threading.Thread(target=self.factory_reset, daemon=True).start()
        if name in ('ADD_CARD', 'REMOVE_CARD'):
            return True, None, None
        return False, 'UNSUPPORTED', None

    def do_unlock(self, source):
        ok = self.hal.unlock()
        if ok:
            self._opened_at = time.time()
            self.hal.beep('ok')
            self.log(f'MỞ KHOÁ ({source})', 'ok')
        else:
            self.hal.beep('deny')
            self.log('Kẹt chốt, không mở được!', 'err')
        self._wake()
        return ok

    def do_ota(self, ota):
        if self._ota_busy or not ota.get('available'):
            self.log('OTA: không có bản mới' if not ota.get('available') else 'OTA đang chạy', 'warn')
            return
        self._ota_busy, ver = True, ota.get('version', '')
        try:
            self.log(f'OTA bắt đầu -> {ver}', 'warn')
            self._call('ota', {'status': 'started', 'version': ver})
            time.sleep(3)
            self.cfg['hardware']['firmware'] = ver
            store.save_overrides({'hardware': {'firmware': ver}})
            self._call('ota', {'status': 'success', 'version': ver})
            self.log(f'OTA xong, firmware {ver}', 'ok')
        except (ApiError, NetError) as e:
            self.log(f'OTA lỗi: {e}', 'err')
            try:
                self._call('ota', {'status': 'failed', 'version': ver, 'error': str(e)[:150]})
            except (ApiError, NetError):
                pass
        finally:
            self._ota_busy = False

    # ------------------------------------------------------------------ xác thực tại chỗ
    def _deny(self, method, reason):
        self.hal.beep('deny')
        self.log(f'{method}: TỪ CHỐI ({reason})', 'warn')
        self.last_access = {'method': method, 'granted': False, 'reason': reason, 't': time.time()}
        return self.last_access

    def _online_access(self, method, fn, *args):
        if self.locked_out:
            return self._deny(method, 'DEVICE_LOCKED_OUT')
        try:
            res = self._call(fn, *args)
        except ApiError as e:
            return self._deny(method, e.code)
        except NetError:
            return self._deny(method, 'OFFLINE (cần mạng để server phán quyết)')
        self.locked_out = bool(res.get('locked_out'))
        if res.get('granted'):
            self.log(f'{method}: server CHO PHÉP', 'ok')
            self.last_access = {'method': method, 'granted': True, 'reason': None, 't': time.time()}
            self.do_unlock(method.lower())
            return self.last_access
        return self._deny(method, res.get('reason') or 'DENIED')

    def tap_card(self, uid):
        if self.sc.get('nfc_enabled') is False:
            return self._deny('RFID', 'NFC_DISABLED')
        return self._online_access('RFID', 'access_rfid', ''.join(ch for ch in uid if ch.isalnum()).upper())

    def enter_pin(self, pin):
        pin = ''.join(ch for ch in pin if ch.isdigit())
        if not 4 <= len(pin) <= 8:
            return self._deny('PIN', 'PIN phải 4-8 chữ số')
        return self._online_access('PIN', 'access_pin', pin)

    def scan_face(self, embedding):
        dim = int((self.sc.get('face') or {}).get('dim', 128))
        if not isinstance(embedding, list) or len(embedding) != dim:
            return self._deny('FACE', f'embedding phải có {dim} số')
        return self._online_access('FACE', 'access_face', [float(x) for x in embedding])

    def phone_unlock(self, kind, ticket):
        """BLE / NFC điện thoại: khoá tự kiểm vé offline, rồi báo log về server (xếp hàng nếu mất mạng)."""
        flag = 'bluetooth_enabled' if kind == 'ble' else 'nfc_enabled'
        prefix = 'BLE' if kind == 'ble' else 'NFC_PHONE'
        ok, why = tickets.verify(self.cfg['secret'], self.cfg['device_code'], kind, ticket, self.now())
        if ok and self.sc.get(flag) is False:
            ok, why = False, 'NOT_ALLOWED'
        ev = {'channel': kind, 'ticket': ticket[:200], 'ok': ok, 'at': int(self.now())}
        if not ok:
            ev['reason'] = f'{prefix}_{why}'
        label = 'BLE' if kind == 'ble' else 'NFC-ĐT'
        if ok:
            self.log(f'{label}: vé hợp lệ (kiểm offline) -> mở', 'ok')
            self.last_access = {'method': label, 'granted': True, 'reason': None, 't': time.time()}
            self.do_unlock(kind)
        else:
            self._deny(label, ev['reason'])
        try:
            self._call('access_phone', [ev])
        except ApiError as e:
            if e.status not in (400, 409):
                self._enqueue('phone', ev)
        except NetError:
            self._enqueue('phone', ev)
        return self.last_access

    def manual_knob(self):
        """Núm xoay bên trong nhà: đổi trạng thái chốt không cần xác thực (như khoá cơ)."""
        if self.hal.lock_state == 'unlocked':
            self._opened_at = None
            self.hal.lock()
            self.log('Núm xoay: khoá')
        else:
            self.do_unlock('núm xoay trong nhà')
        self._wake()

    # ------------------------------------------------------------------ cho web UI
    def _wifi_name(self):
        live = ((self.wifi_live or {}).get('connected') or {}).get('ssid')
        return live or (self.cfg.get('wifi') or {}).get('ssid', '') or ('Ethernet / không rõ' if self.wifi_host() else '')

    def snapshot(self, since=0):
        h, c = self.hal, self.cfg
        with self._mtx:
            logs = [l for l in self.logs if l['id'] > since]
        return {
            'configured': self.configured(), 'device_code': c.get('device_code', ''), 'mac': c['hardware'].get('mac', ''),
            'firmware': c['hardware'].get('firmware', ''), 'wifi': {'ssid': self._wifi_name(), 'up': self.wifi_up, 'source': 'host' if self.wifi_host() else 'simulated',
                     'real': bool((self.wifi_live or {}).get('connected')), 'error': (self.wifi_live or {}).get('error', '')},
            'server': {'active': (c.get('server') or {}).get('active', ''), 'urls': (c.get('server') or {}).get('urls', {}),
                       'override': self.overrides.get('server', '')},
            'online': self.online, 'auth_failed': self.auth_failed, 'last_error': self.last_error,
            'last_hb_ago': int(time.time() - self.last_hb) if self.last_hb else None,
            'lock_state': h.lock_state, 'door_open': h.door_open, 'tamper': h.tamper, 'battery': int(h.battery), 'signal': h.signal,
            'temperature': h.base_temp, 'led': h.led, 'locked_out': self.locked_out,
            'server_cfg': {k: self.sc.get(k) for k in ('status', 'has_owner', 'wifi_enabled', 'bluetooth_enabled', 'nfc_enabled',
                                                      'nfc_auto_register', 'ota', 'intervals')},
            'mqtt': {'enabled': bool((c.get('mqtt') or {}).get('enabled')), 'connected': bool(self.mqtt and self.mqtt.connected),
                     'error': self.mqtt.error if self.mqtt else '', 'target': self.mqtt.target if self.mqtt else ''},
            'prefill': {'server': self.server_url(), 'device_code': c.get('device_code', ''), 'ssid': (c.get('wifi') or {}).get('ssid', ''),
                        'has_secret': bool(c.get('secret'))},
            'queue': {k: len(v) for k, v in self.queue.items()}, 'last_access': self.last_access,
            'uptime': int(time.time() - self.booted_at), 'logs': logs, 'seq': self._seq,
        }

    def action(self, d):
        a = d.get('action')
        if a == 'tap_card':    return self.tap_card(str(d.get('uid', '')))
        if a == 'pin':         return self.enter_pin(str(d.get('pin', '')))
        if a == 'face':
            if d.get('vector'):
                vec = d['vector']
                if not d.get('nosave'):
                    store.save(store.FACE_PATH, {'vector': vec})
            elif d.get('saved'):
                vec = store.load(store.FACE_PATH, {}).get('vector', [])
            else:
                vec = [round(random.uniform(-0.2, 0.2), 6) for _ in range(128)]
            return self.scan_face(vec)
        if a == 'save_face':
            vec = d.get('vector')
            if not isinstance(vec, list) or len(vec) != 128:
                return {'ok': False, 'message': 'embedding phải có 128 số'}
            store.save(store.FACE_PATH, {'vector': [float(x) for x in vec]})
            self.log('Đã lưu embedding khuôn mặt mẫu vào bộ nhớ khoá', 'ok')
            return {'ok': True}
        if a == 'make_ticket':
            kind = d.get('kind', 'ble')
            uh = ''.join(ch for ch in str(d.get('user_hex') or '01') if ch in '0123456789abcdefABCDEF').lower() or '01'
            ttl = max(10, min(int(d.get('ttl') or 120), 3600))
            if kind not in tickets.LABELS:
                return {'ok': False, 'message': 'kind phải là ble|nfc'}
            return {'ok': True, 'ticket': tickets.make(self.cfg['secret'], self.cfg['device_code'], kind, uh, int(self.now()) + ttl), 'expires_in': ttl}
        if a == 'phone':       return self.phone_unlock(d.get('kind', 'ble'), str(d.get('ticket', '')))
        if a == 'door':        self.hal.set_door(bool(d.get('open'))); return {'ok': True}
        if a == 'tamper':      self.set_tamper(bool(d.get('on'))); return {'ok': True}
        if a == 'knob':        self.manual_knob(); return {'ok': True}
        if a == 'battery':     self.hal.battery = max(0.0, min(100.0, float(d.get('value', 100)))); self._wake(); return {'ok': True}
        if a == 'signal':      self.hal.signal = int(d.get('value', -55)); return {'ok': True}
        if a == 'temp':        self.hal.base_temp = float(d.get('value', 27)); return {'ok': True}
        if a == 'jam':         self.cfg['hardware']['jam_chance'] = 1.0 if d.get('on') else 0.0; return {'ok': True}
        if a == 'wifi':
            self.wifi_up = bool(d.get('up'))
            self.log('Wi-Fi BẬT' if self.wifi_up else 'Wi-Fi TẮT (mô phỏng mất mạng)', 'warn')
            if self.wifi_up:
                self._wake()
            else:
                self.online = False
            return {'ok': True}
        if a == 'reboot':      threading.Thread(target=self.reboot, daemon=True).start(); return {'ok': True}
        if a == 'factory_reset': threading.Thread(target=self.factory_reset, daemon=True).start(); return {'ok': True}
        if a == 'switch_server':
            ok, msg = self.switch_server(d.get('name', ''), d.get('url'))
            return {'ok': ok, 'message': msg}
        if a == 'check_ota':
            threading.Thread(target=self.do_ota, args=(self.sc.get('ota') or {},), daemon=True).start()
            return {'ok': True}
        if a == 'heartbeat':   self._wake(); return {'ok': True}
        return {'ok': False, 'message': 'action không hỗ trợ'}
