#!/usr/bin/env python3
"""Khoá giả lập SmartLock (ESP32 simulator).

  python run.py                       # chạy + mở UI http://127.0.0.1:8080
  python run.py --config my.json                      # dùng file cấu hình khác (mặc định ./config.json)
  python run.py --server https://xxx-8000.asse.devtunnels.ms   # ép dùng server khác (không sửa config)
  python run.py --heartbeat 10 --poll 2               # chu kỳ nhanh để demo
"""
import argparse
import os
import threading
import time
import webbrowser

from lockcore import store
from lockcore.controller import Controller
from webui import make_server


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--host', default='127.0.0.1')
    ap.add_argument('--port', type=int, default=8080)
    ap.add_argument('--config', help='đường dẫn file config.json (mặc định ./config.json)')
    ap.add_argument('--server', help='ghi đè URL server (vd https://xxx-8000.asse.devtunnels.ms)')
    ap.add_argument('--heartbeat', type=float, help='ghi đè chu kỳ heartbeat (giây)')
    ap.add_argument('--poll', type=float, help='ghi đè chu kỳ kéo lệnh (giây)')
    ap.add_argument('--no-browser', action='store_true')
    a = ap.parse_args()
    if a.config:
        store.USER_CONFIG_PATH = os.path.abspath(a.config)

    ctl = Controller({k: v for k, v in (('server', a.server), ('heartbeat', a.heartbeat), ('poll', a.poll)) if v})
    srv = make_server(ctl, a.host, a.port)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    url = f'http://{a.host}:{a.port}'
    print(f'== SmartLock device simulator ==  UI: {url}')
    ctl.start()
    if not a.no_browser:
        threading.Timer(0.8, lambda: webbrowser.open(url)).start()
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print('\nTắt khoá...')
        ctl.shutdown()


if __name__ == '__main__':
    main()
