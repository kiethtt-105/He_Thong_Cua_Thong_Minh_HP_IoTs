#!/usr/bin/env python3
"""Chẩn đoán đường MQTT (đọc config.json): python tools/mqtt_probe.py [--config file] [--listen 20]

Bước 1 (chỉ thư viện chuẩn): DNS -> TCP -> TLS -> WebSocket upgrade tới broker. Mong đợi "101 Switching Protocols".
Bước 2 (cần paho-mqtt):      đăng nhập bằng mã thiết bị + secret, subscribe smartlock/<code>/cmd, in lệnh nhận được.
"""
import argparse
import base64
import os
import socket
import ssl
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from lockcore import store                                   # noqa: E402
from lockcore.mqttlink import TUNNEL_HEADERS, resolve        # noqa: E402


def ws_handshake(r, timeout=8):
    host, port, path = r['host'], r['port'], r['path']
    print(f'1) DNS {host} ...', end=' ', flush=True)
    ip = socket.gethostbyname(host)
    print(ip)
    print(f'2) TCP {ip}:{port} ...', end=' ', flush=True)
    s = socket.create_connection((host, port), timeout=timeout)
    print('OK')
    if r['tls']:
        print('3) TLS ...', end=' ', flush=True)
        s = ssl.create_default_context().wrap_socket(s, server_hostname=host)
        print('OK', s.version())
    key = base64.b64encode(os.urandom(16)).decode()
    hdr = {'Host': host, 'Upgrade': 'websocket', 'Connection': 'Upgrade', 'Sec-WebSocket-Key': key,
           'Sec-WebSocket-Version': '13', 'Sec-WebSocket-Protocol': 'mqtt', **TUNNEL_HEADERS}
    s.sendall((f'GET {path} HTTP/1.1\r\n' + ''.join(f'{k}: {v}\r\n' for k, v in hdr.items()) + '\r\n').encode())
    first = s.recv(1024).decode('latin1').split('\r\n')[0]
    s.close()
    print('4) WebSocket upgrade ->', first)
    return ' 101 ' in first + ' ', first


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--config')
    ap.add_argument('--listen', type=int, default=15, help='giây chờ lệnh sau khi nối (0 = bỏ bước 2)')
    a = ap.parse_args()
    if a.config:
        store.USER_CONFIG_PATH = os.path.abspath(a.config)
    cfg = store.load_config()
    m = cfg['mqtt']
    r = resolve(m)
    print('Broker:', r, '| user =', cfg['device_code'], '| enabled =', m.get('enabled'))
    if r['transport'] == 'websockets':
        try:
            ok, first = ws_handshake(r)
        except (OSError, ssl.SSLError) as e:
            print('   LỖI:', e)
            return 1
        if not ok:
            print('   => KHÔNG phải 101. Gợi ý: 404/502 = chưa forward cổng / listener chưa "protocol websockets"; '
                  '302/401/403 = tunnel đang Private (phải Public); trả HTML = sai path.')
            return 1
    if not a.listen:
        return 0
    try:
        import paho.mqtt.client as mqtt
    except ImportError:
        print('Bước 2 bỏ qua: chưa cài paho-mqtt (pip install paho-mqtt)')
        return 0
    from lockcore.mqttlink import MqttLink

    class Ctl:                                   # giả controller tối thiểu
        def log(self, msg, lvl='info'): print(f'   [{lvl}] {msg}')
        def handle_command(self, c, via): print(f'   LỆNH nhận qua {via}: {c}')
    link = MqttLink(Ctl())
    link.start({**m, 'enabled': True}, cfg['device_code'], cfg['secret'])
    t0 = time.time()
    while time.time() - t0 < a.listen:
        time.sleep(0.5)
    print('Kết quả:', 'ĐÃ KẾT NỐI' if link.connected else 'CHƯA nối được: ' + (link.error or 'timeout'))
    link.stop()
    return 0 if link.connected else 1


if __name__ == '__main__':
    sys.exit(main())
