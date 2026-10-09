"""Web UI của khoá giả lập (stdlib, không cần Flask). Mở http://127.0.0.1:8080"""
import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from lockcore.controller import SCAN

STATIC = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'static')


def make_server(ctl, host, port):
    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def _json(self, obj, status=200):
            b = json.dumps(obj, ensure_ascii=False).encode()
            self.send_response(status)
            self.send_header('Content-Type', 'application/json; charset=utf-8')
            self.send_header('Content-Length', str(len(b)))
            self.send_header('Cache-Control', 'no-store')
            self.end_headers()
            self.wfile.write(b)

        def do_GET(self):
            path, _, qs = self.path.partition('?')
            if path == '/api/state':
                since = int(qs.split('since=')[1].split('&')[0]) if 'since=' in qs else 0
                return self._json(ctl.snapshot(since))
            if path == '/api/wifi-scan':
                return self._json([{'ssid': s, 'rssi': r, 'secured': sec} for s, r, sec in SCAN])
            if path in ('/', '/index.html'):
                b = open(os.path.join(STATIC, 'index.html'), 'rb').read()
                self.send_response(200)
                self.send_header('Content-Type', 'text/html; charset=utf-8')
                self.send_header('Content-Length', str(len(b)))
                self.end_headers()
                return self.wfile.write(b)
            self.send_error(404)

        def do_POST(self):
            n = int(self.headers.get('Content-Length') or 0)
            try:
                d = json.loads(self.rfile.read(n) or b'{}')
            except ValueError:
                return self._json({'ok': False, 'message': 'JSON lỗi'}, 400)
            if self.path == '/api/setup':
                ok, msg = ctl.provision(d)
                return self._json({'ok': ok, 'message': msg}, 200 if ok else 400)
            if self.path == '/api/action':
                try:
                    return self._json(ctl.action(d))
                except Exception as e:                      # không để UI chết vì 1 thao tác lỗi
                    ctl.log(f'Lỗi thao tác: {e}', 'err')
                    return self._json({'ok': False, 'message': str(e)}, 500)
            self.send_error(404)

    return ThreadingHTTPServer((host, port), H)
