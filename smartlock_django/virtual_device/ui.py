# virtual_device/ui.py
"""
Giao diện mô phỏng khoá (web cục bộ) cho VirtualLock. Chỉ dùng thư viện chuẩn, bind 127.0.0.1.

    python -m virtual_device ui --profile default          # rồi mở http://127.0.0.1:8765
    (VS Code: Ctrl+Shift+P -> "Simple Browser: Show" -> dán URL, hoặc chạy task "Khoá ảo: giao diện")

UI KHÔNG chứa logic khoá: mọi thao tác đều gọi đúng các hàm của VirtualLock (device.py), nên hành vi
giống hệt chế độ dòng lệnh. Lệnh từ server (UNLOCK/LOCK/...) làm UI đổi trạng thái theo.
"""
import json
import logging
import random
import threading
import time
import webbrowser
from collections import deque
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from . import tickets

PAGE = Path(__file__).parent / 'web' / 'index.html'


class _Ring(logging.Handler):
    """Gom log của khoá vào bộ đệm vòng để UI đọc theo id."""

    def __init__(self):
        super().__init__()
        self.buf, self.n, self._l = deque(maxlen=400), 0, threading.Lock()

    def emit(self, r):
        try:
            msg = r.getMessage()
        except Exception:
            return
        with self._l:
            self.n += 1
            self.buf.append({'id': self.n, 't': time.strftime('%H:%M:%S', time.localtime(r.created)),
                             'lvl': r.levelname, 'msg': msg})

    def since(self, after):
        with self._l:
            return [x for x in self.buf if x['id'] > after]


class LockUI:
    def __init__(self, lock):
        self.lock = lock
        self.ring = _Ring()
        lock.log.addHandler(self.ring)          # tạo TRƯỚC lock.start() để bắt log khởi động
        lock.log.setLevel(logging.DEBUG)

    # ---------------------------------------------------------------- trạng thái
    def snapshot(self, after=0):
        L, s = self.lock, self.lock.s
        return {
            'code': L.code, 'name': L.ident.get('name'), 'connected': L.connected.is_set(),
            'network_up': L.network_up, 'dead': L.dead, 'error': L._last_error,
            'lock_state': s['lock_state'], 'battery': s['battery_level'], 'tamper': s['tamper_detected'],
            'temperature': s['temperature'], 'firmware': s['firmware_version'], 'ble_on': s['ble_on'],
            'nfc_on': s['nfc_on'], 'cards': list(s['cards']), 'outbox': len(s['outbox']),
            'boot': s['boot_count'], 'uptime': int(time.time() - L._started), 'auto_lock': L.auto_lock,
            'logs': self.ring.since(after),
        }

    # ---------------------------------------------------------------- thao tác
    def act(self, b):
        L, a = self.lock, b.get('action')
        try:
            if a in ('lock', 'unlock'):
                ok, why = L.set_lock('locked' if a == 'lock' else 'unlocked', 'manual')
                return {'ok': ok, 'reason': why}
            if a == 'rfid':
                return {'ok': bool(L.tap_rfid(str(b.get('uid') or '').strip().upper()))}
            if a == 'pin':
                return {'ok': bool(L.enter_pin(str(b.get('pin') or '')))}
            if a == 'face':
                return {'ok': bool(L.scan_face([round(random.uniform(-1, 1), 4) for _ in range(128)]))}
            if a == 'mint':
                t, exp = tickets.mint(L.sec_hash, L.code, b['kind'], str(b['user']).replace('-', ''))
                return {'ok': True, 'ticket': t, 'exp': exp}
            if a == 'phone':
                return {'ok': bool(L.phone_unlock(b['kind'], str(b.get('ticket') or '').strip()))}
            if a == 'network':
                (L.go_online if b.get('on') else L.go_offline)()
            elif a == 'battery':
                L.set_battery(int(b['value']))
            elif a == 'tamper':
                L.set_tamper(bool(b.get('on')))
            elif a == 'jam':
                L.set_jam(bool(b.get('on')))
            elif a == 'radio':
                L.toggle_radio(b['which'], bool(b.get('on')))
            elif a == 'reboot':
                L.reboot('manual')
            else:
                return {'ok': False, 'error': f'thao tác không hỗ trợ: {a}'}
            return {'ok': True}
        except (KeyError, ValueError) as e:
            return {'ok': False, 'error': f'tham số không hợp lệ: {e}'}

    # ---------------------------------------------------------------- HTTP
    def _handler(app):
        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def _send(self, code, body, ctype='application/json; charset=utf-8'):
                raw = (json.dumps(body, ensure_ascii=False) if isinstance(body, (dict, list)) else body).encode()
                self.send_response(code)
                self.send_header('Content-Type', ctype)
                self.send_header('Content-Length', str(len(raw)))
                self.send_header('Cache-Control', 'no-store')
                self.end_headers()
                self.wfile.write(raw)

            def do_GET(self):
                u = urlparse(self.path)
                if u.path == '/':
                    self._send(200, PAGE.read_text(encoding='utf-8'), 'text/html; charset=utf-8')
                elif u.path == '/api/state':
                    after = int(parse_qs(u.query).get('after', ['0'])[0] or 0)
                    self._send(200, app.snapshot(after))
                else:
                    self._send(404, {'error': 'not found'})

            def do_POST(self):
                if urlparse(self.path).path != '/api/do' or self.headers.get('X-VD') != '1':
                    return self._send(403, {'error': 'forbidden'})      # chặn trang web lạ gọi chéo vào khoá
                try:
                    body = json.loads(self.rfile.read(int(self.headers.get('Content-Length') or 0)) or b'{}')
                except ValueError:
                    return self._send(400, {'error': 'JSON lỗi'})
                self._send(200, app.act(body if isinstance(body, dict) else {}))
        return H

    def serve(self, port=8765, open_browser=False):
        srv = ThreadingHTTPServer(('127.0.0.1', port), self._handler())
        url = f'http://127.0.0.1:{port}'
        print(f'\n  Giao diện khoá ảo: {url}   (Ctrl+Click để mở; Ctrl+C để rút điện)\n')
        if open_browser:
            webbrowser.open(url)
        try:
            srv.serve_forever()
        except KeyboardInterrupt:
            pass
        finally:
            srv.server_close()
