#!/usr/bin/env python3
"""Server giả (chỉ để TEST khoá khi chưa chạy Django): python tools/fake_server.py  -> http://127.0.0.1:8000
Admin giả: POST /_cmd/<UNLOCK|LOCK|REBOOT|PING>   GET /_state"""
import json, sys, time, uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

CODE, SECRET = 'DEV-TEST0001', 'testsecret'
S = {'cmds': [], 'hb': 0, 'acks': [], 'events': [], 'access': [], 'last': {}}


class H(BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def _j(self, o, st=200):
        b = json.dumps(o).encode(); self.send_response(st); self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(b))); self.end_headers(); self.wfile.write(b)
    def _auth(self):
        if self.headers.get('X-Device-Code') != CODE or self.headers.get('X-Device-Secret') != SECRET:
            self._j({'ok': False, 'error': {'code': 'DEVICE_AUTH_FAILED', 'message': 'sai'}}, 401); return False
        return True
    def _cfg(self):
        return {'status': 'online', 'has_owner': True, 'wifi_enabled': True, 'bluetooth_enabled': True, 'nfc_enabled': True,
                'locked_out': False, 'intervals': {'heartbeat_seconds': 60, 'command_poll_seconds': 3}, 'ticket_ttl_seconds': 3600,
                'face': {'dim': 128, 'max_threshold': 0.5}, 'ota': {'available': False}, 'nfc_auto_register': {'active': False, 'seconds_left': 0}}
    def _pending(self):
        now = time.time(); return [{'command_id': c['id'], 'command': c['cmd'], 'token': c['tok'], 'expires_in': max(0, int(c['exp'] - now))}
                                   for c in S['cmds'] if not c['done'] and c['exp'] > now]
    def do_GET(self):
        if self.path == '/_state': return self._j(S)
        if self.path.startswith('/_cmd/'):
            S['cmds'].append({'id': str(uuid.uuid4()), 'cmd': self.path.split('/')[-1].upper(), 'tok': uuid.uuid4().hex, 'exp': time.time() + 30, 'done': False})
            return self._j({'ok': True})
        if not self.path.startswith('/api/device/') or not self._auth(): return
        if self.path.endswith('/config/'): return self._j({'ok': True, 'unix_time': int(time.time()), **self._cfg()})
        if self.path.endswith('/commands/'): return self._j({'ok': True, 'commands': self._pending()})
        self._j({'ok': False}, 404)
    def do_POST(self):
        n = int(self.headers.get('Content-Length') or 0); d = json.loads(self.rfile.read(n) or b'{}')
        if not self._auth(): return
        p = self.path
        if p.endswith('/heartbeat/'): S['hb'] += 1; S['last'] = d; return self._j({'ok': True, 'unix_time': int(time.time()), 'commands': self._pending(), **self._cfg()})
        if p.endswith('/ack/'):
            S['acks'].append(d)
            for c in S['cmds']:
                if c['id'] == d.get('command_id'): c['done'] = True
            return self._j({'ok': True, 'status': 'acknowledged', 'duplicate': False})
        if p.endswith('/events/'): S['events'].append(d); return self._j({'ok': True, 'notified': False, 'count': 1})
        if p.endswith('/access/pin/'): S['access'].append(d); return self._j({'ok': True, 'granted': d.get('pin') == '123456', 'reason': None if d.get('pin') == '123456' else 'INVALID_OR_EXPIRED_PIN', 'locked_out': False})
        if p.endswith('/access/rfid/'): S['access'].append(d); return self._j({'ok': True, 'granted': True, 'reason': None, 'locked_out': False})
        if p.endswith('/access/phone/'): S['access'].append(d); return self._j({'ok': True, 'results': [{'accepted': True} for _ in d.get('events', [])]})
        self._j({'ok': True})


if __name__ == '__main__':
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8000
    print(f'fake server :{port}  code={CODE} secret={SECRET}'); ThreadingHTTPServer(('127.0.0.1', port), H).serve_forever()
