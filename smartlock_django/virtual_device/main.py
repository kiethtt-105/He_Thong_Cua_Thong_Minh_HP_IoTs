# firmware/esp32/main.py  -  MicroPython cho ESP32. CÙNG giao thức với virtual_device/device.py
#
# Cài:   mpremote mip install umqtt.simple hmac     (hoặc upload thủ công)
# Nạp:   mpremote cp main.py config.json :   (config.json lấy từ virtual_device/data/<profile>/identity.json
#        + thêm wifi_ssid, wifi_pass, mqtt_host, mqtt_port)
#
# Phần cứng chỉ nằm trong class Hal (đổi chân ở PIN). Phần còn lại giữ nguyên so với khoá ảo.
import json, time, machine, network, ntptime, ubinascii, hashlib, hmac
from umqtt.simple import MQTTClient

CFG = json.load(open('config.json'))
CODE, SECRET = CFG['device_code'], CFG['secret']
T_CMD, T_STATUS, T_ACK, T_EVENT = ('smartlock/%s/%s' % (CODE, x) for x in ('cmd', 'status', 'ack', 'event'))
PIN = dict(relay=26, led=2, buzzer=25, tamper=27, battery=34)
AUTO_LOCK_S, STATUS_S, UNIX_OFFSET = 10, 30, 946684800     # MicroPython epoch = 2000-01-01


class Hal:
    """Lớp phần cứng. Khoá ảo thay bằng SimHal; thiết bị thật: relay/servo + công tắc cạy + ADC pin."""
    def __init__(self):
        self.relay = machine.Pin(PIN['relay'], machine.Pin.OUT, value=0)
        self.led = machine.Pin(PIN['led'], machine.Pin.OUT, value=0)
        self.buz = machine.Pin(PIN['buzzer'], machine.Pin.OUT, value=0)
        self.tamper_sw = machine.Pin(PIN['tamper'], machine.Pin.IN, machine.Pin.PULL_UP)
        self.adc = machine.ADC(machine.Pin(PIN['battery'])); self.adc.atten(machine.ADC.ATTN_11DB)

    def actuate(self, unlocked):            # 1 = rút chốt (relay hút / servo quay)
        self.relay.value(1 if unlocked else 0); self.led.value(1 if unlocked else 0)

    def tamper(self):                       # công tắc cạy phá: kéo xuống GND khi bị mở nắp
        return self.tamper_sw.value() == 0

    def battery_pct(self):                  # chia áp 2:1 từ pin Li-ion 3.3-4.2V -> 0..100%
        v = self.adc.read_uv() * 2 / 1e6
        return max(0, min(100, int((v - 3.3) / 0.9 * 100)))

    def beep(self, ms=500):
        self.buz.value(1); time.sleep_ms(ms); self.buz.value(0)

    def read_rfid(self):                    # TODO: gắn MFRC522 -> trả UID hex hoa hoặc None
        return None

    def read_keypad_pin(self):              # TODO: gắn bàn phím -> trả chuỗi PIN hoặc None
        return None


# ---- vé điện thoại: y hệt tickets.py ----------------------------------------------------------
LABELS = {'ble': b'ble-ticket-v1', 'nfc': b'nfc-phone-ticket-v1'}
SEC_HASH = ubinascii.hexlify(hashlib.sha256(SECRET.encode()).digest()).decode()

def _sig(kind, user_hex, exp):
    key = hmac.new(SEC_HASH.encode(), LABELS[kind], hashlib.sha256).digest()
    msg = ('%s|%s|%d' % (CODE, user_hex, exp)).encode()
    return ubinascii.hexlify(hmac.new(key, msg, hashlib.sha256).digest()).decode()[:32]

def verify_ticket(kind, ticket):
    try:
        user_hex, exp_s, sig = ticket.strip().split('.'); exp = int(exp_s)
    except ValueError:
        return False, 'INVALID_TICKET'
    good = _sig(kind, user_hex, exp)
    if sum(a != b for a, b in zip(sig, good)) or len(sig) != len(good):     # so sánh không dừng sớm
        return False, 'INVALID_TICKET'
    return (False, 'TICKET_EXPIRED') if exp < time.time() + UNIX_OFFSET else (True, None)


# ---- khoá ----------------------------------------------------------------------------------
hal, state = Hal(), {'lock': 'locked', 'relock_at': 0, 'seen': [], 'outbox': [], 'started': time.time(), 'last_status': 0}
mq = None

def wifi():
    w = network.WLAN(network.STA_IF); w.active(True)
    if not w.isconnected():
        w.connect(CFG['wifi_ssid'], CFG['wifi_pass'])
        for _ in range(40):
            if w.isconnected(): break
            time.sleep(0.5)
    try: ntptime.settime()
    except Exception: pass
    return w.isconnected()

def pub(topic, payload, queue=False):
    try:
        mq.publish(topic, json.dumps(payload), qos=1); return True
    except Exception:
        if queue: state['outbox'] = (state['outbox'] + [(topic, payload)])[-50:]
        return False

def status(reason='heartbeat'):
    pub(T_STATUS, {'device_code': CODE, 'lock_state': state['lock'], 'battery_level': hal.battery_pct(),
                   'tamper_detected': hal.tamper(), 'firmware_version': CFG.get('firmware', '1.0.0-esp32'),
                   'uptime': int(time.time() - state['started']), 'reason': reason, 'ts': time.time() + UNIX_OFFSET})
    state['last_status'] = time.time()

def set_lock(target, source):
    hal.actuate(target == 'unlocked'); state['lock'] = target
    state['relock_at'] = time.time() + AUTO_LOCK_S if target == 'unlocked' and AUTO_LOCK_S else 0
    status('%s:%s' % (target, source))

def ack(d, ok, reason=None):
    if d.get('command_id'):
        pub(T_ACK, {'command_id': d['command_id'], 'token': d.get('token'), 'command': d.get('command'),
                    'status': 'acknowledged' if ok else 'failed', 'success': ok, 'reason': reason,
                    'lock_state': state['lock'], 'ts': time.time() + UNIX_OFFSET}, queue=True)

def on_cmd(topic, raw):
    try: d = json.loads(raw)
    except ValueError: return
    cmd, cid = str(d.get('command', '')).upper(), d.get('command_id')
    if cid:
        if cid in state['seen']: return ack(d, True, 'DUPLICATE')
        state['seen'] = (state['seen'] + [cid])[-50:]
    if cmd in ('UNLOCK', 'LOCK'):
        set_lock('unlocked' if cmd == 'UNLOCK' else 'locked', d.get('source') or 'remote'); ack(d, True)
    elif cmd == 'PING': ack(d, True)
    elif cmd == 'BUZZER_ALERT': hal.beep(1500)
    elif cmd == 'REBOOT': ack(d, True); time.sleep(1); machine.reset()
    else: ack(d, False, 'UNSUPPORTED_COMMAND')

def phone_unlock(kind, ticket):             # BLE/NFC: tự kiểm tra, offline vẫn mở được
    at = int(time.time() + UNIX_OFFSET)
    ok, reason = verify_ticket(kind, ticket)
    if ok: set_lock('unlocked', kind)
    pub(T_EVENT, {'type': 'ble' if kind == 'ble' else 'nfc_phone', 'ticket': ticket, 'ok': ok,
                  'reason': None if ok else ('BLE_' if kind == 'ble' else 'NFC_PHONE_') + reason, 'at': at}, queue=True)
    return ok

def connect():
    global mq
    mq = MQTTClient(CODE, CFG['mqtt_host'], CFG.get('mqtt_port', 1883), CODE, SECRET, keepalive=30)
    mq.set_callback(on_cmd); mq.connect(clean_session=True); mq.subscribe(T_CMD, qos=1)
    status('boot')
    for item in state['outbox'][:]:                         # đẩy hàng đợi offline
        if pub(item[0], item[1]): state['outbox'].remove(item)

def main():
    backoff = 1
    while True:
        try:
            if not wifi(): raise OSError('wifi')
            connect(); backoff = 1
            while True:
                mq.check_msg()
                now = time.time()
                if state['relock_at'] and now >= state['relock_at']: set_lock('locked', 'auto_relock')
                if now - state['last_status'] >= STATUS_S: status()
                uid = hal.read_rfid()
                if uid: pub(T_EVENT, {'type': 'rfid', 'uid': uid, 'ts': int(now + UNIX_OFFSET)})
                pin = hal.read_keypad_pin()
                if pin: pub(T_EVENT, {'type': 'pin', 'pin': pin, 'ts': int(now + UNIX_OFFSET)})
                time.sleep_ms(100)
        except Exception as e:                              # mất mạng/broker: RFID/PIN từ chối, BLE/NFC vẫn dùng được
            print('offline:', e); time.sleep(backoff); backoff = min(60, backoff * 2)

main()
