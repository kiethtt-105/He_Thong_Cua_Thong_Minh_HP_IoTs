"""Đọc device.conf (INI). Mọi thứ cấu hình Wi-Fi / Bluetooth / NFC / bàn phím / camera / khoá / pin nằm ở đây,
giống 1 khoá thật có file cấu hình trong flash."""
import configparser
import os
import uuid
from pathlib import Path

DEFAULTS = {
    "device": {"code": "LOCK-0001", "secret": "", "name": "SmartLock giả lập", "mode": "simulated",
               "firmware": "1.0.0", "mac": "", "location": "", "state_file": "state.json"},
    "server": {"mode": "online", "mqtt_host": "localhost", "mqtt_port": "1883", "mqtt_tls": "false",
               "mqtt_ca": "", "keepalive": "30", "heartbeat_seconds": "30", "client_id": ""},
    "wifi": {"enabled": "true", "driver": "sim", "ssid": "", "password": "", "connect": "false",
             "allow_ethernet": "true", "sim_rssi": "-52"},
    "bluetooth": {"enabled": "true", "driver": "sim", "adv_name": "", "service_uuid": "5a110c00-0000-4c0c-9e00-534d4c4f434b",
                  "ticket_char_uuid": "5a110c01-0000-4c0c-9e00-534d4c4f434b",
                  "result_char_uuid": "5a110c02-0000-4c0c-9e00-534d4c4f434b"},
    "nfc": {"enabled": "true", "driver": "sim", "reader": "", "hce_aid": "F0534D4C4F434B01"},
    "keypad": {"driver": "sim", "rows": "5,6,13,19", "cols": "26,20,21,16",
               "layout": "123A,456B,789C,*0#D", "timeout_seconds": "10", "max_digits": "8"},
    "camera": {"enabled": "true", "driver": "sim", "index": "0", "faces_dir": "faces", "frames": "3"},
    "lock": {"driver": "sim", "pin": "17", "servo_pin": "18", "active_high": "true",
             "unlock_seconds": "5", "servo_locked_deg": "0", "servo_unlocked_deg": "90"},
    "buzzer": {"driver": "sim", "pin": "27"},
    "power": {"source": "sim", "initial_battery": "100", "drain_minutes_per_percent": "20"},
    "security": {"local_lockout": "true", "fail_threshold": "3", "fail_window_seconds": "60",
                 "lockout_seconds": "60", "verify_timeout_seconds": "6"},
    "ui": {"host": "127.0.0.1", "port": "8765", "token": "", "allow_sim_input": "true"},
    "standalone": {"default_user_id": "00000000-0000-0000-0000-000000000001", "face_threshold": "0.5"},
    "standalone.cards": {}, "standalone.pins": {},
}


def _b(v): return str(v).strip().lower() in ("1", "true", "yes", "on")


class Config:
    def __init__(self, path=None):
        self.path = Path(path or os.environ.get("SMARTLOCK_CONF") or "device.conf").resolve()
        self.base = self.path.parent
        cp = configparser.ConfigParser(inline_comment_prefixes=(";",), interpolation=None)
        for sec, vals in DEFAULTS.items():
            cp[sec] = dict(vals)
        self.found = self.path.exists()
        if self.found:
            cp.read(self.path, encoding="utf-8")
        self.cp = cp
        # biến môi trường ghi đè nhanh: SMARTLOCK_<SECTION>_<KEY>
        for sec in cp.sections():
            for key in list(cp[sec].keys()):
                env = os.environ.get(f"SMARTLOCK_{sec.upper().replace('.', '_')}_{key.upper()}")
                if env is not None:
                    cp[sec][key] = env

    # --- truy cập
    def s(self, sec, key): return self.cp[sec][key].strip()
    def b(self, sec, key): return _b(self.cp[sec][key])
    def i(self, sec, key): return int(float(self.cp[sec][key]))
    def f(self, sec, key): return float(self.cp[sec][key])
    def l(self, sec, key): return [x.strip() for x in self.cp[sec][key].split(",") if x.strip()]
    def section(self, sec): return dict(self.cp[sec]) if self.cp.has_section(sec) else {}
    def p(self, sec, key): return (self.base / self.s(sec, key)).resolve() if not os.path.isabs(self.s(sec, key)) else Path(self.s(sec, key))

    @property
    def code(self): return self.s("device", "code")
    @property
    def secret(self): return self.cp["device"]["secret"].strip()
    @property
    def standalone(self): return self.s("server", "mode").lower() == "standalone"

    @property
    def mac(self):
        m = self.s("device", "mac").upper()
        if m: return m
        n = uuid.getnode()
        return ":".join(f"{(n >> s) & 0xFF:02X}" for s in range(40, -8, -8))

    def validate(self):
        errs = []
        if not self.secret: errs.append("[device] secret trống - chạy `python -m smartlock_fw init` để sinh secret.")
        if not self.code: errs.append("[device] code trống.")
        return errs
