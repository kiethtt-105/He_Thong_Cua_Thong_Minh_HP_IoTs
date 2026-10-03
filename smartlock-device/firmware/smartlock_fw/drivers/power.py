"""Nguồn/pin + cảm biến nhiệt: sim | system (pin laptop thật qua psutil)."""
import random


class SimPower:
    kind = "sim"
    def __init__(self, cfg): self.temp = 28.0
    def battery(self): return None            # None = để core tự giả lập hao pin
    def temperature(self):
        self.temp = max(18.0, min(45.0, self.temp + random.uniform(-0.2, 0.2))); return round(self.temp, 1)


class SystemPower:
    kind = "system"
    def __init__(self, cfg):
        try: import psutil; self.ps = psutil
        except ImportError: raise RuntimeError("Cài psutil: pip install psutil")
    def battery(self):
        b = self.ps.sensors_battery(); return int(b.percent) if b else None
    def temperature(self):
        try:
            t = self.ps.sensors_temperatures()
            for arr in t.values():
                if arr: return round(arr[0].current, 1)
        except Exception: pass
        return None


def make_power(cfg):
    return SystemPower(cfg) if cfg.s("power", "source").lower() == "system" else SimPower(cfg)
