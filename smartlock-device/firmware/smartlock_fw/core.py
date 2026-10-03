"""LÕI KHOÁ: máy trạng thái locked/unlocked/jammed, xác thực 5 kênh (RFID, PIN, khuôn mặt, BLE, NFC-điện thoại),
khoá tạm khi sai liên tiếp, nhận lệnh MQTT, hàng đợi sự kiện offline, pin/nhiệt độ/chống cạy."""
import json
import math
import os
import threading
import time
from collections import deque

from . import protocol as P
from .drivers.camera import DIM

LOW_BATTERY = (20, 10)


class LockCore:
    def __init__(self, cfg, bus, *, actuator, buzzer, wifi, ble, nfc, keypad, camera, power):
        self.cfg, self.bus = cfg, bus
        self.act, self.buzz, self.wifi, self.ble, self.nfc, self.keypad, self.cam, self.power = actuator, buzzer, wifi, ble, nfc, keypad, camera, power
        self.link = None                       # gắn sau (mqtt)
        self.lk = threading.RLock()
        self.t0 = time.time()
        self.persist = self._load()
        self.fails = deque()
        self.pending = None                    # {'kind','deadline'} chờ server ra lệnh UNLOCK
        self.keybuf, self.key_t = "", 0.0
        self.relock_at = 0.0
        self.lockout_until = 0.0
        self.seen_cmds = deque(self.persist.get("seen_cmds", []), maxlen=100)
        self._drain, self._warned, self._last_save = 0.0, set(), 0.0
        self.st = {
            "code": cfg.code, "name": cfg.s("device", "name"), "mode": cfg.s("device", "mode"),
            "standalone": cfg.standalone, "firmware": cfg.s("device", "firmware"), "mac": cfg.mac,
            "location": cfg.s("device", "location"),
            "lock_state": "locked", "battery": int(self.persist.get("battery", cfg.i("power", "initial_battery"))),
            "temperature": None, "tamper": False, "rssi": None, "uptime": 0, "led": "idle", "busy": False,
            "wifi": {"enabled": cfg.b("wifi", "enabled"), "connected": False, "ssid": "", "driver": wifi.kind},
            "bluetooth": {"enabled": cfg.b("bluetooth", "enabled"), "advertising": False, "driver": ble.kind},
            "nfc": {"enabled": cfg.b("nfc", "enabled"), "driver": nfc.kind},
            "camera": {"enabled": camera is not None, "driver": camera.kind if camera else None},
            "mqtt": {"connected": False}, "keypad_len": 0, "pending": None,
            "lockout_remaining": 0, "relock_in": 0, "jammed": False, "events_queued": len(self.persist.get("queue", [])),
        }

    # ------------------------------------------------------------------ lưu trạng thái
    def _load(self):
        try:
            with open(self.cfg.p("device", "state_file"), encoding="utf-8") as f: return json.load(f)
        except Exception: return {}

    def save(self, force=False):
        if not force and time.time() - self._last_save < 5: return
        self._last_save = time.time()
        self.persist.update(battery=self.st["battery"], seen_cmds=list(self.seen_cmds))
        path = self.cfg.p("device", "state_file"); tmp = f"{path}.tmp"
        try:
            with open(tmp, "w", encoding="utf-8") as f: json.dump(self.persist, f)
            os.replace(tmp, path)
        except OSError: pass

    # ------------------------------------------------------------------ snapshot / phát trạng thái
    def snapshot(self):
        with self.lk:
            now = time.time(); s = json.loads(json.dumps(self.st))
            s["uptime"] = int(now - self.t0)
            s["lockout_remaining"] = max(0, int(math.ceil(self.lockout_until - now)))
            s["relock_in"] = max(0, int(math.ceil(self.relock_at - now))) if self.st["lock_state"] == "unlocked" else 0
            s["pending"] = self.pending["kind"] if self.pending else None
            s["events_queued"] = len(self.persist.get("queue", []))
            return s

    def changed(self): self.bus.push_state(self.snapshot())

    def _set_led(self, led, secs=1.5):
        self.st["led"] = led
        if led != "idle": threading.Timer(secs, lambda: self._led_idle(led)).start()

    def _led_idle(self, led):
        if self.st["led"] == led and not self.pending: self.st["led"] = "idle"; self.changed()

    # ------------------------------------------------------------------ chốt khoá
    def grant(self, source, who=""):
        with self.lk:
            if not self.act.unlock():
                return self._jam()
            self.st["lock_state"], self.st["jammed"] = "unlocked", False
            self.relock_at = time.time() + self.cfg.i("lock", "unlock_seconds")
            self.pending = None; self.fails.clear()
            self._set_led("ok"); self.buzz.beep("ok")
        self.bus.log("ok", "lock", f"MỞ KHOÁ qua {source}" + (f" ({who})" if who else ""), source=source)
        self.send_status(); self.changed(); return True

    def do_lock(self, source="auto"):
        with self.lk:
            if self.st["lock_state"] == "locked" and not self.st["jammed"]: return True
            if not self.act.lock(): return self._jam()
            self.st["lock_state"], self.st["jammed"] = "locked", False
            self.relock_at = 0
        self.bus.log("info", "lock", f"KHOÁ LẠI ({source})", source=source)
        self.send_status(); self.changed(); return True

    def _jam(self):
        self.st["lock_state"], self.st["jammed"] = "jammed", True
        self._set_led("error", 3); self.buzz.beep("error")
        self.bus.log("crit", "lock", "KẸT CHỐT: cơ cấu khoá không phản hồi (jammed)")
        self.send_status(); self.changed(); return False

    def set_jam(self, on):
        self.act.set_jam(on)
        if on: self.bus.log("warn", "lock", "Mô phỏng: kẹt chốt BẬT")
        else:
            self.bus.log("info", "lock", "Mô phỏng: kẹt chốt TẮT")
            if self.st["jammed"]: self.st["lock_state"], self.st["jammed"] = "locked", False; self.act.lock(); self.send_status()
        self.changed()

    # ------------------------------------------------------------------ từ chối + khoá tạm
    def deny(self, kind, reason):
        now = time.time()
        with self.lk:
            self.pending = None
            self._set_led("error", 2); self.buzz.beep("error")
            self.fails.append(now)
            while self.fails and now - self.fails[0] > self.cfg.i("security", "fail_window_seconds"): self.fails.popleft()
            trip = (self.cfg.b("security", "local_lockout") and len(self.fails) >= self.cfg.i("security", "fail_threshold")
                    and now >= self.lockout_until)
            if trip:
                secs = self.cfg.i("security", "lockout_seconds")
                self.lockout_until = now + secs; self.fails.clear()
        self.bus.log("warn", kind, f"TỪ CHỐI ({reason})", reason=reason)
        if trip:
            self.buzz.beep("alarm")
            self.bus.log("crit", "lock", f"Sai liên tiếp: khoá tạm {secs}s, còi báo động", lockout=secs)
        self.changed()

    def blocked(self):
        if time.time() < self.lockout_until:
            self.buzz.beep("error"); self.bus.log("warn", "lock", "Đang khoá tạm do nhập sai nhiều lần"); return True
        return False

    # ------------------------------------------------------------------ luồng chung rfid/pin/face
    def _credential(self, kind, payload, local_check):
        if self.blocked(): return
        if self.cfg.standalone:
            ok, who, reason = local_check()
            return self.grant(kind, who) if ok else self.deny(kind, reason)
        if not (self.link and self.link.ready()):
            return self.deny(kind, "OFFLINE: không có kết nối tới máy chủ (kênh này cần xác thực từ server)")
        with self.lk:
            self.pending = {"kind": kind, "deadline": time.time() + self.cfg.i("security", "verify_timeout_seconds")}
            self.st["led"] = "busy"
        self.link.send_event(kind, **payload); self.changed()

    # ------------------------------------------------------------------ RFID
    def on_rfid(self, raw):
        uid = P.normalize_uid(raw)
        if not self.st["nfc"]["enabled"]: return self.bus.log("warn", "nfc", "NFC đang tắt, bỏ qua thẻ")
        if len(uid) < 4: return self.bus.log("warn", "rfid", "UID thẻ không hợp lệ")
        self.bus.log("info", "rfid", f"Quẹt thẻ …{uid[-4:]}")
        def chk():
            for name, u in self.cfg.section("standalone.cards").items():
                if P.normalize_uid(u) == uid: return True, name, None
            return False, "", "UNKNOWN_CARD"
        self._credential("rfid", {"uid": uid}, chk)

    # ------------------------------------------------------------------ PIN (bàn phím)
    def on_key(self, k):
        k = str(k)[:1].upper()
        with self.lk:
            self.key_t = time.time(); self.buzz.beep("tick")
            if k.isdigit():
                if len(self.keybuf) < self.cfg.i("keypad", "max_digits"): self.keybuf += k
            elif k == "*": self.keybuf = ""
            elif k == "A": threading.Thread(target=self.request_face, daemon=True).start()
            elif k == "#":
                pin, self.keybuf = self.keybuf, ""
                if len(pin) >= 4: threading.Thread(target=self._submit_pin, args=(pin,), daemon=True).start()
                elif pin: self.deny("pin", "PIN quá ngắn")
            self.st["keypad_len"] = len(self.keybuf)
        self.changed()

    def _submit_pin(self, pin):
        self.bus.log("info", "pin", f"Nhập PIN ({len(pin)} số)")
        def chk():
            uses = self.persist.setdefault("pin_uses", {})
            for name, val in self.cfg.section("standalone.pins").items():
                code, _, mx = (x.strip() for x in val.partition(","))
                mx = int(mx) if mx.isdigit() else 0
                if code == pin and (not mx or uses.get(name, 0) < mx):
                    uses[name] = uses.get(name, 0) + 1; self.save(True); return True, name, None
            return False, "", "INVALID_OR_EXPIRED_PIN"
        self._credential("pin", {"pin": pin}, chk)

    def type_pin(self, pin):
        for ch in pin: self.on_key(ch)
        self.on_key("#")

    # ------------------------------------------------------------------ khuôn mặt
    def request_face(self, who=None):
        if not self.cam: return self.bus.log("warn", "face", "Camera đang tắt")
        if self.blocked(): return
        self.bus.log("info", "face", "Đang quét khuôn mặt…" + (f" (giả lập: {who})" if who else ""))
        try: vec = self.cam.scan(who)
        except Exception as e: return self.bus.log("crit", "face", f"Lỗi camera: {e}")
        if not vec: return self.bus.log("warn", "face", "Không phát hiện khuôn mặt rõ ràng")
        def chk():
            best, bd = None, 9e9
            for name, ref in self.cam.profiles().items():
                d = math.sqrt(sum((a - b) ** 2 for a, b in zip(vec, ref))) if len(ref) == len(vec) else 9e9
                if d < bd: best, bd = name, d
            lim = min(self.cfg.f("standalone", "face_threshold"), 0.6)
            return (True, best, None) if best and bd <= lim else (False, "", "NO_MATCH")
        self._credential("face", {"embedding": [round(x, 6) for x in vec], "snapshot_url": ""}, chk)

    # ------------------------------------------------------------------ BLE / NFC điện thoại (vé, kiểm tra OFFLINE)
    def _phone(self, kind, ticket):
        ch = {"ble": ("ble_unlock", "BLE", "bluetooth", "ble"), "nfc": ("nfc_phone_unlock", "NFC_PHONE", "nfc", "nfc")}[kind]
        ev, prefix, radio, logk = ch
        if not self.st[radio]["enabled"]:
            return self.bus.log("warn", logk, f"{'Bluetooth' if kind == 'ble' else 'NFC'} đang tắt, bỏ qua vé")
        at = int(time.time())
        ok, reason, user_hex, exp = P.verify_ticket(self.cfg.code, self.cfg.secret, kind, ticket)
        who = f"user …{user_hex[-6:]}" if user_hex else ""
        if ok:
            self.grant(kind, who)
            if kind == "ble": self.ble.notify("OK")
            self.bus.log("ok", logk, f"Vé hợp lệ, hết hạn sau {exp - at}s")
        else:
            self.deny(logk, f"vé {reason}")
            if kind == "ble": self.ble.notify(f"DENIED:{reason}")
        if not self.cfg.standalone:
            self._send_or_queue(ev, ticket=ticket, ok=ok, reason=None if ok else f"{prefix}_{reason}", at=at)

    def on_ble_ticket(self, t): self._phone("ble", t)
    def on_nfc_ticket(self, t): self._phone("nfc", t)

    # ------------------------------------------------------------------ gửi lên máy chủ (+ hàng đợi offline)
    def _send_or_queue(self, kind, **data):
        if self.link and self.link.ready() and self.link.send_event(kind, **data): return
        with self.lk:
            q = self.persist.setdefault("queue", []); q.append({"kind": kind, "data": data})
            del q[:-200]
        self.save(True)
        self.bus.log("warn", "mqtt", f"Offline: đã xếp hàng sự kiện '{kind}' để gửi khi có mạng ({len(q)} chờ)")
        self.changed()

    def flush_queue(self):
        with self.lk: q, self.persist["queue"] = self.persist.get("queue", []), []
        sent = 0
        for i, it in enumerate(q):
            if not self.link.send_event(it["kind"], **it["data"]):
                with self.lk: self.persist["queue"] = q[i:] + self.persist["queue"]
                break
            sent += 1
        if sent: self.bus.log("ok", "mqtt", f"Đã đồng bộ {sent} sự kiện offline lên máy chủ")
        self.save(True); self.changed()

    def send_status(self):
        if self.link and self.link.ready(): self.link.send_status()

    # ------------------------------------------------------------------ lệnh từ máy chủ
    def handle_command(self, msg):
        cid, cmd, tok, src = msg.get("command_id"), str(msg.get("command", "")).upper(), msg.get("token"), msg.get("source", "remote")
        if cid and cid in self.seen_cmds:
            return self.bus.log("info", "cmd", f"Bỏ qua lệnh trùng {cmd} {str(cid)[:8]}")
        if cid: self.seen_cmds.append(cid)
        self.bus.log("info", "cmd", f"Lệnh {cmd} từ {src}", command=cmd, source=src)
        ok, err = True, None
        if cmd == "UNLOCK":
            ok = self.grant(src)
        elif cmd == "LOCK":
            ok = self.do_lock(src)
        elif cmd == "PING":
            pass
        elif cmd == "REBOOT":
            threading.Timer(0.5, self.reboot).start()
        elif cmd == "BUZZER_ALERT":
            self.buzz.beep("alarm"); self._set_led("error", 5)
            self.bus.log("crit", "lock", f"Còi báo động theo lệnh máy chủ ({msg.get('reason', '')})")
        else:
            ok, err = False, f"unsupported:{cmd}"
            self.bus.log("warn", "cmd", f"Lệnh chưa hỗ trợ: {cmd}")
        if cid and self.link: self.link.send_ack(cid, tok, ok, self.st["lock_state"], err)
        self.changed()

    def reboot(self):
        self.bus.log("warn", "sys", "Khởi động lại thiết bị…")
        self.do_lock("reboot"); self.t0 = time.time(); self.pending = None; self.keybuf = ""
        if self.link: self.link.restart()
        self.bus.log("ok", "sys", "Đã khởi động xong"); self.changed()

    # ------------------------------------------------------------------ điều khiển phần cứng/phụ
    def set_radio(self, name, on):
        on = bool(on)
        with self.lk: self.st[name]["enabled"] = on
        self.bus.log("info", {"wifi": "wifi", "bluetooth": "ble", "nfc": "nfc"}[name], f"{name.capitalize()} {'BẬT' if on else 'TẮT'}")
        if name == "bluetooth":
            try:
                (self.ble.start(self.on_ble_ticket) if on else self.ble.stop())
                self.st["bluetooth"]["advertising"] = on and self.ble.advertising
            except Exception as e: self.bus.log("crit", "ble", str(e))
        if name == "wifi" and self.link: self.link.set_network(on and self.st["wifi"]["connected"])
        self.send_status(); self.changed()

    def set_tamper(self, on):
        on = bool(on)
        if on == self.st["tamper"]: return
        self.st["tamper"] = on
        if on:
            self.buzz.beep("alarm"); self._set_led("error", 5)
            self.bus.log("crit", "lock", "PHÁT HIỆN CẠY PHÁ (tamper)")
            if not self.cfg.standalone: self._send_or_queue("tamper", tamper=True)
        else: self.bus.log("info", "lock", "Tamper đã xoá")
        self.send_status(); self.changed()

    def set_battery(self, v):
        self.st["battery"] = max(0, min(100, int(v))); self.send_status(); self.changed()

    # ------------------------------------------------------------------ vòng tick 1 giây
    def tick(self, n):
        now = time.time()
        with self.lk:
            if self.st["lock_state"] == "unlocked" and self.relock_at and now >= self.relock_at: relock = True
            else: relock = False
            if self.pending and now > self.pending["deadline"]: expired = self.pending["kind"]
            else: expired = None
            if self.keybuf and now - self.key_t > self.cfg.i("keypad", "timeout_seconds"):
                self.keybuf = ""; self.st["keypad_len"] = 0
        if relock: self.do_lock("tự khoá lại")
        if expired: self.deny(expired, "server không xác nhận (hết thời gian chờ)")
        # pin: đọc pin hệ thống nếu có, ngược lại giả lập hao pin
        real = self.power.battery()
        if real is not None: self.st["battery"] = real
        else:
            self._drain += 1 / (60.0 * max(1, self.cfg.i("power", "drain_minutes_per_percent")))
            if self._drain >= 1: self._drain -= 1; self.st["battery"] = max(0, self.st["battery"] - 1)
        for lv in LOW_BATTERY:
            if self.st["battery"] <= lv and lv not in self._warned:
                self._warned.add(lv); self.bus.log("warn", "power", f"Pin yếu: {self.st['battery']}%")
                self.send_status()
        if self.st["battery"] > 25: self._warned.clear()
        if n % 5 == 0:
            self.st["temperature"] = self.power.temperature()
            w = self.wifi.probe()
            old = self.st["wifi"]["connected"]
            self.st["wifi"].update(connected=w["connected"], ssid=w["ssid"]); self.st["rssi"] = w["rssi"]
            if w["connected"] != old:
                self.bus.log("info" if w["connected"] else "warn", "wifi",
                             f"Wi-Fi {'đã kết nối ' + w['ssid'] if w['connected'] else 'MẤT KẾT NỐI'}")
            if self.link: self.link.set_network(self.st["wifi"]["enabled"] and w["connected"])
        if self.link:
            self.st["mqtt"]["connected"] = self.link.connected
            if self.link.connected and n % max(5, self.cfg.i("server", "heartbeat_seconds")) == 0: self.link.send_status()
        self.save()
        if n % 2 == 0 or relock: self.changed()
