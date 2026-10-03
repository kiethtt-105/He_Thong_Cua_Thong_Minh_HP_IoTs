"""Lắp ráp khoá: driver + lõi + MQTT + web UI, và vòng tick."""
import logging
import signal
import threading
import time

from .bus import EventBus
from .config import Config
from .core import LockCore
from .drivers.ble import make_ble
from .drivers.camera import make_camera
from .drivers.keypad import make_keypad
from .drivers.lock import make_buzzer, make_lock
from .drivers.nfc import make_nfc
from .drivers.power import make_power
from .drivers.wifi import make_wifi
from .link import MqttLink
from .webui import make_server

log = logging.getLogger("smartlock")


class App:
    def __init__(self, cfg: Config):
        self.cfg, self.bus, self.stop_ev = cfg, EventBus(), threading.Event()
        self.core = LockCore(cfg, self.bus, actuator=make_lock(cfg), buzzer=make_buzzer(cfg), wifi=make_wifi(cfg),
                             ble=make_ble(cfg), nfc=make_nfc(cfg), keypad=make_keypad(cfg),
                             camera=make_camera(cfg), power=make_power(cfg))
        self.link = MqttLink(cfg, self.core, self.bus)
        self.core.link = self.link
        self.srv = None

    def public_config(self, sim_ok):
        c, cam = self.cfg, self.core.cam
        return {"sim_input": sim_ok, "standalone": c.standalone, "device_mode": c.s("device", "mode"),
                "cards": {k: v for k, v in c.section("standalone.cards").items()},
                "faces": sorted(cam.profiles().keys()) if cam else [],
                "unlock_seconds": c.i("lock", "unlock_seconds"), "adv_name": c.s("bluetooth", "adv_name") or "SmartLock-" + "".join(ch for ch in c.code if ch.isalnum())[-6:],
                "drivers": {"wifi": c.s("wifi", "driver"), "bluetooth": c.s("bluetooth", "driver"), "nfc": c.s("nfc", "driver"),
                            "keypad": c.s("keypad", "driver"), "camera": c.s("camera", "driver"), "lock": c.s("lock", "driver")}}

    def run(self):
        cfg, core, bus = self.cfg, self.core, self.bus
        bus.log("ok", "sys", f"Khởi động {cfg.s('device', 'name')} [{cfg.code}] fw {cfg.s('device', 'firmware')} - "
                              f"{'ĐỘC LẬP (standalone)' if cfg.standalone else 'ONLINE (MQTT)'}, mode {cfg.s('device', 'mode')}")
        if not cfg.found: bus.log("warn", "sys", f"Không thấy {cfg.path} - dùng mặc định. Chạy `python -m smartlock_fw init`.")
        # khởi tạo khoá ở trạng thái khoá chặt
        core.act.lock()
        # Wi-Fi
        w = core.wifi.probe(); core.st["wifi"].update(connected=w["connected"], ssid=w["ssid"]); core.st["rssi"] = w["rssi"]
        if cfg.b("wifi", "connect") and core.st["wifi"]["enabled"] and not w["connected"]:
            bus.log("info", "wifi", f"Đang kết nối Wi-Fi '{cfg.s('wifi', 'ssid')}' …"); core.wifi.connect()
        bus.log("info" if w["connected"] else "warn", "wifi", f"Wi-Fi: {'kết nối ' + w['ssid'] if w['connected'] else 'chưa kết nối'}"
                + (f" ({w['rssi']} dBm)" if w["rssi"] is not None else ""))
        # BLE / NFC / bàn phím
        for name, fn in (("ble", self._start_ble), ("nfc", self._start_nfc), ("keypad", self._start_keypad)):
            try: fn()
            except Exception as e: bus.log("crit", name, f"Không khởi động được {name}: {e}")
        # MQTT
        self.link.start(core.st["wifi"]["enabled"] and w["connected"])
        # web UI
        self.srv = make_server(self)
        threading.Thread(target=self.srv.serve_forever, daemon=True, name="web").start()
        host, port = cfg.s("ui", "host"), cfg.i("ui", "port")
        bus.log("ok", "sys", f"Live view: http://{'127.0.0.1' if host in ('0.0.0.0', '') else host}:{port}/" + ("?token=…" if cfg.s("ui", "token") else ""))
        for sig in (signal.SIGINT, signal.SIGTERM):
            try: signal.signal(sig, lambda *a: self.stop_ev.set())
            except ValueError: pass
        n = 0
        while not self.stop_ev.wait(1.0):
            n += 1
            try: core.tick(n)
            except Exception: log.exception("tick lỗi")
        self.shutdown()

    def _start_ble(self):
        c = self.core
        if c.st["bluetooth"]["enabled"]:
            c.ble.start(c.on_ble_ticket); c.st["bluetooth"]["advertising"] = c.ble.advertising
            self.bus.log("info", "ble", f"Bluetooth quảng bá ({c.ble.kind}) tên '{self.public_config(True)['adv_name']}'")

    def _start_nfc(self):
        c = self.core
        c.nfc.start(c.on_rfid, c.on_nfc_ticket)
        self.bus.log("info", "nfc", f"Đầu đọc NFC: driver {c.nfc.kind}")

    def _start_keypad(self):
        c = self.core
        c.keypad.start(c.on_key)
        self.bus.log("info", "pin", f"Bàn phím: driver {c.keypad.kind}")

    def shutdown(self):
        self.bus.log("warn", "sys", "Tắt thiết bị…")
        try: self.core.do_lock("tắt máy"); self.core.save(True)
        except Exception: pass
        for obj in (self.link, self.core.ble, self.core.nfc, self.core.keypad):
            try: obj.stop()
            except Exception: pass
        if self.srv: self.srv.shutdown()
