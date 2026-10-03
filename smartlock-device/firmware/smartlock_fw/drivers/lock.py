"""Cơ cấu chấp hành (chốt khoá): sim | relay (rơ-le/khoá điện từ) | servo."""
import time
from . import optional_import


class SimLock:
    kind = "sim"
    def __init__(self, cfg): self.jam = False
    def unlock(self): return not self.jam
    def lock(self): return not self.jam
    def set_jam(self, on): self.jam = bool(on)


class RelayLock:
    """Chân GPIO điều khiển rơ-le/khoá chốt điện từ. active_high=true: mức cao = MỞ."""
    kind = "relay"
    def __init__(self, cfg):
        self.GPIO = optional_import("RPi.GPIO", "pip install RPi.GPIO (chạy trên Raspberry Pi)")
        self.pin, self.hi = cfg.i("lock", "pin"), cfg.b("lock", "active_high")
        self.GPIO.setmode(self.GPIO.BCM); self.GPIO.setup(self.pin, self.GPIO.OUT)
        self._w(False)
    def _w(self, unlocked): self.GPIO.output(self.pin, (self.GPIO.HIGH if unlocked == self.hi else self.GPIO.LOW))
    def unlock(self): self._w(True); return True
    def lock(self): self._w(False); return True
    def set_jam(self, on): pass


class ServoLock:
    kind = "servo"
    def __init__(self, cfg):
        self.GPIO = optional_import("RPi.GPIO", "pip install RPi.GPIO")
        self.GPIO.setmode(self.GPIO.BCM); self.GPIO.setup(cfg.i("lock", "servo_pin"), self.GPIO.OUT)
        self.pwm = self.GPIO.PWM(cfg.i("lock", "servo_pin"), 50); self.pwm.start(0)
        self.a_lock, self.a_open = cfg.f("lock", "servo_locked_deg"), cfg.f("lock", "servo_unlocked_deg")
    def _go(self, deg):
        self.pwm.ChangeDutyCycle(2.5 + deg / 18.0); time.sleep(0.5); self.pwm.ChangeDutyCycle(0)
    def unlock(self): self._go(self.a_open); return True
    def lock(self): self._go(self.a_lock); return True
    def set_jam(self, on): pass


def make_lock(cfg):
    d = cfg.s("lock", "driver").lower()
    return {"sim": SimLock, "relay": RelayLock, "servo": ServoLock}[d](cfg)


class SimBuzzer:
    kind = "sim"
    def __init__(self, cfg): pass
    def beep(self, pattern="ok"): pass


class GpioBuzzer:
    kind = "gpio"
    PATTERNS = {"ok": [(0.08, 0.05)], "error": [(0.25, 0.1)] * 2, "alarm": [(0.2, 0.1)] * 15, "tick": [(0.02, 0)]}
    def __init__(self, cfg):
        self.GPIO = optional_import("RPi.GPIO", "pip install RPi.GPIO"); self.pin = cfg.i("buzzer", "pin")
        self.GPIO.setmode(self.GPIO.BCM); self.GPIO.setup(self.pin, self.GPIO.OUT)
    def beep(self, pattern="ok"):
        import threading
        def run():
            for on, off in self.PATTERNS.get(pattern, self.PATTERNS["ok"]):
                self.GPIO.output(self.pin, 1); time.sleep(on); self.GPIO.output(self.pin, 0); time.sleep(off)
        threading.Thread(target=run, daemon=True).start()


def make_buzzer(cfg):
    return GpioBuzzer(cfg) if cfg.s("buzzer", "driver").lower() == "gpio" else SimBuzzer(cfg)
