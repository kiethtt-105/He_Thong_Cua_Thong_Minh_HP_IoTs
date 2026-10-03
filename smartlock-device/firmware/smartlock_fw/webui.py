"""Máy chủ HTTP cục bộ của khoá: trang LIVE VIEW + API điều khiển/mô phỏng (dùng chung cho VS Code extension).
Chỉ dùng thư viện chuẩn. Mặc định chỉ lắng nghe 127.0.0.1."""
import json
import queue
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from . import protocol as P

STATIC = Path(__file__).parent / "static"


def make_server(app):
    cfg, core, bus = app.cfg, app.core, app.bus
    token = cfg.s("ui", "token"); sim_ok = cfg.b("ui", "allow_sim_input")

    class H(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"
        def log_message(self, *a): pass

        def _json(self, obj, code=200):
            b = json.dumps(obj, ensure_ascii=False, default=str).encode()
            self.send_response(code); self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(b))); self.send_header("Cache-Control", "no-store"); self.end_headers(); self.wfile.write(b)

        def _authed(self):
            if not token: return True
            q = parse_qs(urlparse(self.path).query)
            return (self.headers.get("X-Token") or (q.get("token") or [""])[0]) == token

        def _body(self):
            try: n = int(self.headers.get("Content-Length") or 0); return json.loads(self.rfile.read(n) or b"{}") if n else {}
            except Exception: return {}

        def do_GET(self):
            path = urlparse(self.path).path
            if path in ("/", "/index.html"):
                b = (STATIC / "index.html").read_bytes()
                self.send_response(200); self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(b))); self.end_headers(); self.wfile.write(b); return
            if not self._authed(): return self._json({"ok": False, "error": "unauthorized"}, 401)
            if path == "/api/state": return self._json(core.snapshot())
            if path == "/api/log": return self._json(bus.history(200))
            if path == "/api/config": return self._json(app.public_config(sim_ok))
            if path == "/api/stream": return self._stream()
            self._json({"ok": False, "error": "not found"}, 404)

        def _stream(self):
            self.send_response(200); self.send_header("Content-Type", "text/event-stream")
            self.send_header("Cache-Control", "no-store"); self.send_header("Connection", "keep-alive"); self.end_headers()
            q = bus.subscribe()
            try:
                hello = json.dumps({"t": "hello", "s": core.snapshot(), "logs": bus.history(100), "cfg": app.public_config(sim_ok)}, ensure_ascii=False, default=str)
                self.wfile.write(f"data: {hello}\n\n".encode()); self.wfile.flush()
                while True:
                    try: self.wfile.write(f"data: {q.get(timeout=15)}\n\n".encode())
                    except queue.Empty: self.wfile.write(b": ka\n\n")
                    self.wfile.flush()
            except (BrokenPipeError, ConnectionResetError, OSError): pass
            finally: bus.unsubscribe(q)

        def do_POST(self):
            if not self._authed(): return self._json({"ok": False, "error": "unauthorized"}, 401)
            path, b = urlparse(self.path).path, self._body()
            try:
                self._json(self._route(path, b))
            except Exception as e:
                bus.log("crit", "sys", f"API lỗi {path}: {e}"); self._json({"ok": False, "error": str(e)}, 500)

        def _route(self, path, b):
            # --- điều khiển cục bộ (như núm xoay/nút trong nhà) - luôn cho phép
            if path == "/api/lock": return {"ok": core.do_lock("núm xoay trong nhà")}
            if path == "/api/unlock": return {"ok": core.grant("núm xoay trong nhà")}
            if path == "/api/reboot": threading.Timer(0.2, core.reboot).start(); return {"ok": True}
            if path == "/api/radio": core.set_radio(b["name"], b["on"]); return {"ok": True}
            # --- mô phỏng đầu vào
            if not sim_ok: return {"ok": False, "error": "[ui] allow_sim_input = false"}
            if path == "/api/sim/rfid": threading.Thread(target=core.on_rfid, args=(b["uid"],), daemon=True).start(); return {"ok": True}
            if path == "/api/sim/key": core.on_key(b["key"]); return {"ok": True}
            if path == "/api/sim/pin": threading.Thread(target=core.type_pin, args=(str(b["pin"]),), daemon=True).start(); return {"ok": True}
            if path == "/api/sim/face": threading.Thread(target=core.request_face, args=(b.get("who"),), daemon=True).start(); return {"ok": True}
            if path == "/api/sim/ble": threading.Thread(target=core.on_ble_ticket, args=(b["ticket"],), daemon=True).start(); return {"ok": True}
            if path == "/api/sim/nfc": threading.Thread(target=core.on_nfc_ticket, args=(b["ticket"],), daemon=True).start(); return {"ok": True}
            if path == "/api/sim/tamper": core.set_tamper(b["on"]); return {"ok": True}
            if path == "/api/sim/jam": core.set_jam(b["on"]); return {"ok": True}
            if path == "/api/sim/battery": core.set_battery(b["level"]); return {"ok": True}
            if path == "/api/ticket":     # cấp vé TEST (khoá có secret nên ký được)
                kind = b.get("kind", "ble")
                uid = b.get("user_id") or cfg.s("standalone", "default_user_id")
                t, exp = P.mint_ticket(cfg.code, cfg.secret, kind, uid, int(b.get("ttl", 3600)))
                return {"ok": True, "ticket": t, "expires_at": exp}
            return {"ok": False, "error": "not found"}

    srv = ThreadingHTTPServer((cfg.s("ui", "host"), cfg.i("ui", "port")), H)
    srv.daemon_threads = True
    return srv
