# virtual_device/device.py
"""
Khoá thông minh ảo: đóng vai firmware ESP32.

MQTT (khớp services.py / mqtt_auth_webhook / mqtt_acl_webhook):
    username = device_code, password = provisioning secret (gốc)
    subscribe  smartlock/<code>/cmd
    publish    smartlock/<code>/status | ack | event

LOGIC ONLINE / OFFLINE
  * Online  : nối broker -> gửi status ngay + định kỳ (STATUS_INTERVAL). Server cập nhật last_seen_at,
              khoá có chủ tự chuyển offline -> online (services.touch_device).
  * Offline : mất mạng / broker sập / tự tắt Wi-Fi -> paho tự nối lại (backoff 1..60s). Server tự đánh
              'offline' sau 180s không có status (services.mark_offline_devices).
              - RFID / PIN / khuôn mặt: cần server xác thực  => offline thì TỪ CHỐI tại chỗ.
              - Bluetooth / NFC điện thoại: khoá TỰ kiểm tra vé HMAC + hạn => vẫn MỞ ĐƯỢC khi offline,
                sự kiện được xếp vào hàng đợi (state.json, sống sót qua mất điện) kèm mốc thời gian `at`,
                nối lại là đẩy lên để server ghi log đúng giờ xảy ra.
  * Lệnh cũ  : mặc định clean_session=True nên lệnh UNLOCK xếp hàng lúc mất mạng bị bỏ khi nối lại.
"""
import json
import logging
import queue
import random
import threading
import time
from collections import deque

import paho.mqtt.client as mqtt

from . import config, tickets
from .store import Store

CONNACK_TEXT = {
    1: 'sai phiên bản giao thức', 2: 'client id bị từ chối', 3: 'broker không sẵn sàng',
    4: 'SAI device_code/secret (hoặc secret đã bị xoay)', 5: 'không được phép (ACL / webhook từ chối)',
}

DEFAULT_STATE = {
    'lock_state': 'locked',          # locked | unlocked | jammed
    'battery_level': 100,
    'tamper_detected': False,
    'temperature': 27.0,
    'ble_on': True,                  # phần cứng radio của khoá (khác cờ bluetooth_enabled phía server)
    'nfc_on': True,
    'cards': [],                     # UID thẻ do lệnh ADD_CARD ghi vào bộ nhớ cục bộ
    'outbox': [],                    # sự kiện/ack chờ gửi khi có mạng trở lại
    'boot_count': 0,
}


def new_paho_client(client_id: str, clean_session: bool):
    try:        # paho-mqtt >= 2
        return mqtt.Client(mqtt.CallbackAPIVersion.VERSION1, client_id=client_id, clean_session=clean_session)
    except AttributeError:   # paho-mqtt 1.x (đúng với requirements: paho-mqtt<2)
        return mqtt.Client(client_id=client_id, clean_session=clean_session)


class VirtualLock:
    def __init__(self, profile='default', *, auto_lock=None, status_interval=None, battery_every=None):
        self.store = Store(profile)
        self.ident = self.store.load_identity()
        if not self.ident:
            raise SystemExit(f'Chưa có identity cho profile "{profile}". Chạy trước: '
                             f'python -m virtual_device provision --profile {profile}')
        self.code = self.ident['device_code']
        self.secret = self.ident['secret']
        self.sec_hash = tickets.secret_hash(self.secret)
        self.log = logging.getLogger(self.code)

        self.auto_lock = config.AUTO_LOCK_SECONDS if auto_lock is None else auto_lock
        self.status_interval = status_interval or config.STATUS_INTERVAL
        self.battery_every = config.BATTERY_DRAIN_EVERY if battery_every is None else battery_every

        self.s = {**DEFAULT_STATE, **self.store.load_state()}
        self.s['firmware_version'] = self.s.get('firmware_version') or self.ident.get('firmware_version') \
            or config.DEFAULT_FIRMWARE
        self.s['outbox'] = list(self.s.get('outbox') or [])
        if self.s['lock_state'] == 'unlocked':       # mất điện khi đang mở -> khởi động lại thì chốt khoá
            self.s['lock_state'] = 'locked'

        self._mu = threading.RLock()
        self._stop = threading.Event()
        self.connected = threading.Event()
        self.network_up = True               # "Wi-Fi" mô phỏng; False = cố tình ngắt mạng
        self.dead = False
        self.client = None
        self._seen = deque(maxlen=300)       # command_id đã xử lý (broker QoS1 có thể giao trùng)
        self._cmd_q = queue.Queue()
        self._relock_timer = None
        self._last_status = 0.0
        self._started = time.time()
        self._last_error = None
        self._threads = []

    # ------------------------------------------------------------------ vòng đời
    def start(self):
        self.s['boot_count'] += 1
        self._save()
        for fn in (self._command_worker, self._tick_loop):
            t = threading.Thread(target=fn, daemon=True)
            t.start()
            self._threads.append(t)
        self.log.info('KHỞI ĐỘNG khoá ảo %s (firmware %s, pin %s%%, trạng thái %s, boot #%s)',
                      self.code, self.s['firmware_version'], self.s['battery_level'],
                      self.s['lock_state'], self.s['boot_count'])
        self._connect()

    def stop(self):
        """Rút điện: không gửi lời chào cuối (khoá thật cũng vậy) -> server sẽ tự đánh offline sau 180s."""
        self._stop.set()
        self._cancel_relock()
        self._disconnect()
        self._save()
        self.log.info('ĐÃ TẮT NGUỒN.')

    def wait(self):
        self._stop.wait()

    # ------------------------------------------------------------------ MQTT
    def _connect(self):
        if not self.network_up or self.dead or self._stop.is_set():
            return
        c = new_paho_client(self.code, config.MQTT_CLEAN_SESSION)
        c.username_pw_set(self.code, self.secret)
        if config.MQTT_TLS:
            c.tls_set()
        c.reconnect_delay_set(min_delay=1, max_delay=60)
        c.on_connect = self._on_connect
        c.on_disconnect = self._on_disconnect
        c.on_message = self._on_message
        self.client = c
        self.log.info('Đang nối broker %s:%s ...', config.MQTT_HOST, config.MQTT_PORT)
        try:
            c.connect_async(config.MQTT_HOST, config.MQTT_PORT, keepalive=config.MQTT_KEEPALIVE)
            c.loop_start()      # tự retry nối lần đầu + tự reconnect khi rớt
        except Exception as e:
            self.log.error('Không khởi động được MQTT: %s', e)

    def _disconnect(self):
        c, self.client = self.client, None
        self.connected.clear()
        if c is not None:
            try:
                c.disconnect()
                c.loop_stop()
            except Exception:
                pass

    def _on_connect(self, client, userdata, flags, rc):
        if rc != 0:
            self._last_error = CONNACK_TEXT.get(rc, f'rc={rc}')
            self.log.error('Broker từ chối kết nối: %s', self._last_error)
            return
        self._last_error = None
        client.subscribe(config.topic_cmd(self.code), qos=1)
        self.connected.set()
        self.log.info('ONLINE - đã nối broker, nghe lệnh tại %s', config.topic_cmd(self.code))
        self.publish_status('boot' if time.time() - self._started < 5 else 'reconnected')
        threading.Thread(target=self._flush_outbox, daemon=True).start()

    def _on_disconnect(self, client, userdata, rc):
        was = self.connected.is_set()
        self.connected.clear()
        if was:
            self.log.warning('OFFLINE - mất kết nối broker (rc=%s). Tự nối lại; RFID/PIN/mặt tạm không dùng '
                             'được, BLE/NFC điện thoại vẫn mở cửa tại chỗ.', rc)

    def _on_message(self, client, userdata, msg):
        try:
            data = json.loads(msg.payload.decode('utf-8'))
            if not isinstance(data, dict):
                raise ValueError('payload không phải object')
        except (ValueError, UnicodeDecodeError) as e:
            self.log.warning('Bỏ qua lệnh lỗi định dạng: %s', e)
            return
        self._cmd_q.put(data)

    def _publish(self, topic, payload, qos=1):
        """Trả MQTTMessageInfo nếu đã đưa vào hàng gửi, None nếu đang offline."""
        c = self.client
        if not (c and self.connected.is_set()):
            return None
        try:
            info = c.publish(topic, json.dumps(payload, ensure_ascii=False), qos=qos)
        except Exception as e:
            self.log.warning('Publish lỗi: %s', e)
            return None
        return info if info.rc == mqtt.MQTT_ERR_SUCCESS else None

    # ------------------------------------------------------------------ status / hàng đợi offline
    def status_payload(self, reason='heartbeat'):
        with self._mu:
            s = self.s
            return {
                'device_code': self.code,
                'lock_state': s['lock_state'],
                'battery_level': s['battery_level'],
                'battery': s['battery_level'],
                'signal_strength': random.randint(-70, -45),
                'tamper_detected': bool(s['tamper_detected']),
                'temperature': round(float(s['temperature']) + random.uniform(-0.3, 0.3), 1),
                'firmware_version': s['firmware_version'],
                'firmware': s['firmware_version'],
                'mac_address': self.ident.get('mac_address'),
                'uptime': int(time.time() - self._started),
                'reason': reason,
                'ts': int(time.time()),
            }

    def publish_status(self, reason='heartbeat') -> bool:
        if self.dead:
            return False
        ok = self._publish(config.topic_status(self.code), self.status_payload(reason)) is not None
        if ok:
            self._last_status = time.time()
            self.log.debug('status (%s) đã gửi', reason)
        return ok

    def _queue_out(self, kind, payload):
        with self._mu:
            ob = self.s['outbox']
            ob.append({'kind': kind, 'payload': payload, 'queued_at': int(time.time())})
            del ob[:-config.OUTBOX_MAX]
            self._save()
        self.log.info('Đã xếp hàng chờ gửi (%s) - đang offline. Hàng đợi: %d', kind, len(self.s['outbox']))

    def send(self, kind, payload, *, queue_if_offline=False) -> bool:
        """kind: 'event' | 'ack'. Offline: xếp hàng nếu queue_if_offline, ngược lại bỏ."""
        topic = config.topic_event(self.code) if kind == 'event' else config.topic_ack(self.code)
        if self._publish(topic, payload) is not None:
            return True
        if queue_if_offline:
            self._queue_out(kind, payload)
        return False

    def _flush_outbox(self):
        with self._mu:
            pending = list(self.s['outbox'])
        if not pending:
            return
        self.log.info('Đồng bộ %d bản ghi offline lên server ...', len(pending))
        sent = 0
        for item in pending:
            topic = config.topic_event(self.code) if item['kind'] == 'event' else config.topic_ack(self.code)
            info = self._publish(topic, item['payload'])
            if info is None:
                break
            info.wait_for_publish(timeout=5)
            if not info.is_published():
                break
            with self._mu:
                try:
                    self.s['outbox'].remove(item)
                except ValueError:
                    pass
                self._save()
            sent += 1
        self.log.info('Đã đồng bộ %d/%d bản ghi offline.', sent, len(pending))

    # ------------------------------------------------------------------ khoá cơ khí
    def _save(self):
        with self._mu:
            self.store.save_state(self.s)

    def set_lock(self, target, source) -> tuple:
        """Trả (ok, reason). 'jammed' thì không thao tác được."""
        with self._mu:
            if self.dead:
                return False, 'DEAD_BATTERY'
            if self.s['lock_state'] == 'jammed':
                return False, 'JAMMED'
            changed = self.s['lock_state'] != target
            self.s['lock_state'] = target
            self._save()
        self._cancel_relock()
        if target == 'unlocked' and self.auto_lock > 0:
            self._relock_timer = threading.Timer(self.auto_lock, self._auto_relock)
            self._relock_timer.daemon = True
            self._relock_timer.start()
        if changed:
            self.log.info('🔓 ĐÃ MỞ KHOÁ (%s)' if target == 'unlocked' else '🔒 ĐÃ KHOÁ (%s)', source)
        self.publish_status(f'{target}:{source}')
        return True, None

    def _auto_relock(self):
        if self.s['lock_state'] == 'unlocked':
            self.set_lock('locked', 'auto_relock')

    def _cancel_relock(self):
        t, self._relock_timer = self._relock_timer, None
        if t:
            t.cancel()

    # ------------------------------------------------------------------ xử lý lệnh từ server
    def _command_worker(self):
        while not self._stop.is_set():
            try:
                data = self._cmd_q.get(timeout=0.5)
            except queue.Empty:
                continue
            try:
                self._handle_command(data)
            except Exception:
                self.log.exception('Lỗi khi xử lý lệnh %r', data)

    def _ack(self, data, ok, reason=None, **extra):
        if not data.get('command_id'):
            return
        payload = {
            'command_id': data['command_id'], 'token': data.get('token'), 'command': data.get('command'),
            'status': config.ACK_OK if ok else config.ACK_FAIL, 'success': ok,
            'reason': reason, 'lock_state': self.s['lock_state'],
            'battery_level': self.s['battery_level'], 'ts': int(time.time()), **extra,
        }
        self.send('ack', payload, queue_if_offline=True)

    def _handle_command(self, data):
        cmd = str(data.get('command') or '').upper()
        cid = data.get('command_id')
        self.log.info('⇐ LỆNH %s từ %s (id=%s)', cmd, data.get('source', '?'), (cid or '-')[:8])
        if cid:
            if cid in self._seen:
                self.log.info('Lệnh %s đã xử lý rồi, chỉ ack lại.', cid[:8])
                return self._ack(data, True, 'DUPLICATE')
            self._seen.append(cid)

        if self.dead:
            return self._ack(data, False, 'DEAD_BATTERY')

        if cmd in ('UNLOCK', 'LOCK'):
            ok, reason = self.set_lock('unlocked' if cmd == 'UNLOCK' else 'locked', data.get('source') or 'remote')
            return self._ack(data, ok, reason)
        if cmd == 'PING':
            return self._ack(data, True, None, uptime=int(time.time() - self._started),
                             firmware_version=self.s['firmware_version'])
        if cmd == 'BUZZER_ALERT':         # server phát khi khoá tạm do sai liên tiếp - không có command_id
            self.log.warning('🚨 CÒI HÚ: %s', data.get('reason', ''))
            return
        if cmd == 'REBOOT':
            self._ack(data, True)
            return self.reboot('remote_reboot')
        if cmd == 'OTA_UPDATE':
            self._ack(data, True)
            return self.ota(data.get('version') or (data.get('payload') or {}).get('version'))
        if cmd == 'RESET':
            self._ack(data, True)
            return self.factory_reset()
        if cmd in ('ADD_CARD', 'REMOVE_CARD'):
            uid = str(data.get('uid') or data.get('card_uid') or (data.get('payload') or {}).get('uid') or '')
            with self._mu:
                cards = self.s['cards']
                if cmd == 'ADD_CARD' and uid and uid not in cards:
                    cards.append(uid)
                if cmd == 'REMOVE_CARD' and uid in cards:
                    cards.remove(uid)
                self._save()
            return self._ack(data, True)
        self.log.warning('Lệnh không hỗ trợ: %s', cmd)
        self._ack(data, False, 'UNSUPPORTED_COMMAND')

    # ------------------------------------------------------------------ reboot / OTA / reset
    def reboot(self, why='manual'):
        def run():
            self.log.warning('♻ KHỞI ĐỘNG LẠI (%s) ...', why)
            self._disconnect()
            time.sleep(config.REBOOT_SECONDS)
            with self._mu:
                self.s['boot_count'] += 1
                if self.s['lock_state'] == 'unlocked':
                    self.s['lock_state'] = 'locked'
                self._save()
            self._started = time.time()
            self._connect()
        threading.Thread(target=run, daemon=True).start()

    def ota(self, version=None):
        def run():
            ver = version or f'1.{random.randint(1, 9)}.{random.randint(0, 9)}-virtual'
            self.log.warning('⬇ OTA: đang cập nhật firmware -> %s', ver)
            time.sleep(config.OTA_SECONDS)
            with self._mu:
                self.s['firmware_version'] = ver
                self._save()
            self.log.warning('✔ OTA xong, firmware = %s', ver)
            self.reboot('ota')
        threading.Thread(target=run, daemon=True).start()

    def factory_reset(self):
        """Xoá bộ nhớ cục bộ (thẻ, hàng đợi, tamper). Identity/secret giữ nguyên để còn nối được broker."""
        self.log.warning('⚠ FACTORY RESET - xoá thẻ & hàng đợi cục bộ')
        with self._mu:
            self.s.update(cards=[], outbox=[], tamper_detected=False, lock_state='locked')
            self._save()
        self.reboot('factory_reset')

    # ------------------------------------------------------------------ hành động tại chỗ (REPL gọi)
    def tap_rfid(self, uid):
        """Server xác thực UID rồi gửi lệnh UNLOCK về - khoá KHÔNG tự mở."""
        if not self.connected.is_set():
            self.log.warning('RFID bị từ chối: khoá offline, không xác thực được thẻ.')
            return False
        self.log.info('⇒ Quẹt thẻ %s, chờ server xác thực ...', uid)
        return self.send('event', {'type': config.EVENT_TYPE['rfid'], 'uid': uid, 'ts': int(time.time())})

    def enter_pin(self, pin):
        if not self.connected.is_set():
            self.log.warning('PIN bị từ chối: khoá offline, không xác thực được mã.')
            return False
        self.log.info('⇒ Nhập PIN ****, chờ server xác thực ...')
        return self.send('event', {'type': config.EVENT_TYPE['pin'], 'pin': pin, 'ts': int(time.time())})

    def scan_face(self, embedding, snapshot_url=''):
        if not self.connected.is_set():
            self.log.warning('Khuôn mặt bị từ chối: khoá offline.')
            return False
        self.log.info('⇒ Gửi embedding khuôn mặt (%d chiều), chờ server so khớp ...', len(embedding))
        return self.send('event', {'type': config.EVENT_TYPE['face'], 'embedding': list(embedding),
                                   'snapshot_url': snapshot_url, 'ts': int(time.time())})

    def phone_unlock(self, kind, ticket):
        """kind: 'ble' | 'nfc'. Khoá TỰ kiểm tra vé; OFFLINE vẫn mở được, sự kiện xếp hàng gửi sau."""
        label, ev_key, prefix = (('Bluetooth', 'ble', 'BLE') if kind == 'ble'
                                 else ('NFC điện thoại', 'nfc_phone', 'NFC_PHONE'))
        radio = 'ble_on' if kind == 'ble' else 'nfc_on'
        at = int(time.time())
        if not self.s[radio]:
            self.log.warning('%s đang tắt trên khoá, bỏ qua.', label)
            return False
        ok, reason, _uhex, exp = tickets.verify(self.sec_hash, self.code, kind, ticket)
        fail_reason = f'{prefix}_{reason}' if reason else None
        if ok:
            opened, why = self.set_lock('unlocked', ev_key)
            if not opened:
                ok, fail_reason = False, f'{prefix}_{why}'
        event = {'type': config.EVENT_TYPE[ev_key], 'ticket': ticket, 'ok': ok,
                 'reason': fail_reason, 'at': at}
        self.log.info('%s vé %s (%s)', '✔ Chấp nhận' if ok else '✘ Từ chối', label,
                      'offline - sẽ đồng bộ sau' if not self.connected.is_set() else 'online')
        self.send('event', event, queue_if_offline=True)
        return ok

    # ------------------------------------------------------------------ mô phỏng môi trường
    def go_offline(self):
        self.network_up = False
        self._disconnect()
        self.log.warning('📴 ĐÃ NGẮT MẠNG (mô phỏng). Khoá hoạt động độc lập.')

    def go_online(self):
        self.network_up = True
        self.log.info('📶 BẬT LẠI MẠNG ...')
        self._connect()

    def set_battery(self, pct):
        with self._mu:
            self.s['battery_level'] = max(0, min(100, int(pct)))
            self._save()
        self._check_battery()
        self.publish_status('battery')

    def set_tamper(self, on):
        with self._mu:
            self.s['tamper_detected'] = bool(on)
            self._save()
        self.log.warning('🛡 TAMPER = %s', 'PHÁT HIỆN CẠY PHÁ' if on else 'bình thường')
        self.publish_status('tamper')

    def set_jam(self, on):
        with self._mu:
            self.s['lock_state'] = 'jammed' if on else 'locked'
            self._save()
        self.log.warning('⚙ %s', 'KẸT CHỐT KHOÁ' if on else 'đã gỡ kẹt, chốt về trạng thái khoá')
        self.publish_status('jam')

    def toggle_radio(self, which, on):
        key = 'ble_on' if which == 'ble' else 'nfc_on'
        with self._mu:
            self.s[key] = bool(on)
            self._save()
        self.log.info('%s = %s', which.upper(), 'BẬT' if on else 'TẮT')

    def _check_battery(self):
        if self.s['battery_level'] <= 0 and not self.dead:
            self.dead = True
            self.log.error('🪫 HẾT PIN - khoá ngừng hoạt động (server sẽ đánh offline sau 180s).')
            self._cancel_relock()
            self._disconnect()
        elif self.s['battery_level'] > 0 and self.dead:
            self.dead = False
            self.log.info('🔋 Có pin trở lại, khởi động ...')
            self._connect()

    def _tick_loop(self):
        last_drain = time.time()
        while not self._stop.wait(1):
            now = time.time()
            if self.battery_every and not self.dead and now - last_drain >= self.battery_every:
                last_drain = now
                with self._mu:
                    self.s['battery_level'] = max(0, self.s['battery_level'] - 1)
                    self._save()
                self._check_battery()
            if self.connected.is_set() and now - self._last_status >= self.status_interval:
                self.publish_status('heartbeat')

    # ------------------------------------------------------------------ báo cáo cho REPL
    def summary(self) -> str:
        s = self.s
        net = ('ONLINE' if self.connected.is_set()
               else ('OFFLINE (đang nối lại...)' if self.network_up else 'OFFLINE (đã ngắt mạng)'))
        err = f'\n  lỗi nối  : {self._last_error}' if self._last_error else ''
        return (f'  mã       : {self.code}\n  mạng      : {net}{err}\n'
                f'  khoá      : {s["lock_state"]}\n  pin       : {s["battery_level"]}%\n'
                f'  tamper    : {s["tamper_detected"]}\n  firmware  : {s["firmware_version"]}\n'
                f'  BLE/NFC   : {"bật" if s["ble_on"] else "tắt"}/{"bật" if s["nfc_on"] else "tắt"}\n'
                f'  thẻ cục bộ: {len(s["cards"])}\n  hàng đợi  : {len(s["outbox"])} bản ghi chờ gửi\n'
                f'  boot      : #{s["boot_count"]}')
