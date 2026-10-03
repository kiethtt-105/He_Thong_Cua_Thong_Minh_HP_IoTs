#!/usr/bin/env python3
"""Khoá ảo: kết nối MQTT giống hệt khoá thật (ESP32) để test toàn hệ thống.

    pip install "paho-mqtt<2"
    python virtual_lock.py --host localhost --code LOCK-0001 --secret <provisioning_secret>

Tạo thiết bị trước trong Django admin (device_mode = simulated), lấy device_code + secret gốc.
Lệnh gõ trong lúc chạy:
    rfid <UID>      quẹt thẻ         pin <mã>       nhập PIN        face     gửi vector mặt ngẫu nhiên
    ble <ticket>    mở bằng BLE      nfc <ticket>   mở bằng NFC điện thoại
    tamper          bật/tắt cảnh báo phá khoá       battery <0-100>
    lock / unlock   đổi trạng thái tại chỗ          quit
"""
import argparse
import json
import random
import sys
import threading
import time

import paho.mqtt.client as mqtt


class VirtualLock:
    def __init__(self, a):
        self.code, self.a = a.code, a
        self.lock_state, self.tamper, self.battery = 'locked', False, a.battery
        self.t_status = f'smartlock/{self.code}/status'
        self.t_ack = f'smartlock/{self.code}/ack'
        self.t_event = f'smartlock/{self.code}/event'
        self.t_cmd = f'smartlock/{self.code}/cmd'
        self._relock = None

        self.c = mqtt.Client(client_id=f'vlock-{self.code}', clean_session=True)
        self.c.username_pw_set(self.code, a.secret)
        if a.tls:
            self.c.tls_set()
        # LWT: broker tự báo offline nếu khoá mất kết nối đột ngột
        self.c.will_set(self.t_status, json.dumps({'state': 'offline'}), qos=1)
        self.c.on_connect, self.c.on_message = self.on_connect, self.on_message
        self.c.reconnect_delay_set(1, 30)

    def pub(self, topic, obj):
        self.c.publish(topic, json.dumps(obj), qos=1)

    def status(self):
        self.pub(self.t_status, {'lock_state': self.lock_state, 'battery': self.battery, 'tamper': self.tamper,
                                 'rssi': random.randint(-70, -45), 'temperature': round(random.uniform(24, 30), 1),
                                 'firmware': self.a.firmware})

    # ---- MQTT callbacks
    def on_connect(self, c, u, flags, rc):
        if rc != 0:
            print(f'[!] connect thất bại rc={rc} (rc=4/5: sai code/secret hoặc webhook từ chối)')
            return
        c.subscribe(self.t_cmd, qos=1)
        self.pub(self.t_event, {'type': 'boot', 'firmware': self.a.firmware})
        self.status()
        print(f'[+] {self.code} đã kết nối {self.a.host}:{self.a.port}')

    def on_message(self, c, u, msg):
        try:
            cmd = json.loads(msg.payload)
        except ValueError:
            return
        kind, ok = cmd.get('command'), True
        print(f'[cmd] {kind} (source={cmd.get("source")})')
        if kind == 'UNLOCK':
            self.set_state('unlocked')
            self._schedule_relock()
        elif kind == 'LOCK':
            self.set_state('locked')
        elif kind in ('PING', 'REBOOT'):
            pass
        else:
            ok = False
        # ack: gửi lại command_id + token đã nhận
        self.pub(self.t_ack, {'command_id': cmd.get('command_id'), 'token': cmd.get('token'), 'ok': ok})
        self.status()

    # ---- hành vi khoá
    def set_state(self, s):
        self.lock_state = s
        print(f'[state] {s}')

    def _schedule_relock(self):
        if self._relock:
            self._relock.cancel()
        self._relock = threading.Timer(self.a.relock, lambda: (self.set_state('locked'), self.status()))
        self._relock.daemon = True
        self._relock.start()

    # ---- vòng đời
    def run(self):
        self.c.connect_async(self.a.host, self.a.port, keepalive=30)
        self.c.loop_start()
        threading.Thread(target=self._heartbeat, daemon=True).start()
        self._repl()

    def _heartbeat(self):
        while True:
            time.sleep(self.a.interval)
            self.status()

    def _repl(self):
        for line in sys.stdin:
            p = line.strip().split(maxsplit=1)
            if not p:
                continue
            op, arg = p[0].lower(), (p[1] if len(p) > 1 else '')
            if op == 'quit':
                break
            elif op == 'rfid':
                self.pub(self.t_event, {'type': 'rfid', 'uid': arg})
            elif op == 'pin':
                self.pub(self.t_event, {'type': 'pin', 'pin': arg})
            elif op == 'face':
                self.pub(self.t_event, {'type': 'face', 'embedding': [round(random.gauss(0, .2), 4) for _ in range(128)]})
            elif op in ('ble', 'nfc'):
                self.pub(self.t_event, {'type': 'ble' if op == 'ble' else 'nfc_phone', 'ticket': arg,
                                        'ok': True, 'at': time.time()})
            elif op == 'tamper':
                self.tamper = not self.tamper
                self.status()
            elif op == 'battery' and arg.isdigit():
                self.battery = max(0, min(100, int(arg)))
                self.status()
            elif op in ('lock', 'unlock'):
                self.set_state('locked' if op == 'lock' else 'unlocked')
                self.status()
            else:
                print('lệnh không hợp lệ')
        self.pub(self.t_status, {'state': 'offline'})
        time.sleep(0.3)
        self.c.loop_stop()
        self.c.disconnect()


if __name__ == '__main__':
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--host', default='localhost')
    ap.add_argument('--port', type=int, default=1883)
    ap.add_argument('--code', required=True, help='device_code (username MQTT)')
    ap.add_argument('--secret', required=True, help='provisioning secret gốc (password MQTT)')
    ap.add_argument('--tls', action='store_true')
    ap.add_argument('--interval', type=int, default=30, help='giây giữa các status')
    ap.add_argument('--relock', type=int, default=5, help='tự khoá lại sau N giây khi mở')
    ap.add_argument('--battery', type=int, default=100)
    ap.add_argument('--firmware', default='sim-1.0.0')
    VirtualLock(ap.parse_args()).run()
