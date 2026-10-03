"""Bàn phím ma trận 4x4: sim (bấm ở web/VS Code) | gpio (Raspberry Pi, quét hàng/cột)."""
import threading
import time
from . import optional_import


class SimKeypad:
    kind = "sim"
    def __init__(self, cfg): pass
    def start(self, on_key): self.on_key = on_key
    def stop(self): pass


class GpioKeypad:
    kind = "gpio"
    def __init__(self, cfg):
        self.GPIO = optional_import("RPi.GPIO", "pip install RPi.GPIO")
        self.rows = [int(x) for x in cfg.l("keypad", "rows")]
        self.cols = [int(x) for x in cfg.l("keypad", "cols")]
        self.layout = cfg.s("keypad", "layout").split(",")
        self.running = False

    def start(self, on_key):
        G = self.GPIO; self.on_key, self.running = on_key, True
        G.setmode(G.BCM)
        for r in self.rows: G.setup(r, G.OUT, initial=G.HIGH)
        for c in self.cols: G.setup(c, G.IN, pull_up_down=G.PUD_UP)
        threading.Thread(target=self._loop, daemon=True, name="keypad").start()

    def stop(self): self.running = False

    def _loop(self):
        G, held = self.GPIO, None
        while self.running:
            hit = None
            for ri, r in enumerate(self.rows):
                G.output(r, G.LOW)
                for ci, c in enumerate(self.cols):
                    if G.input(c) == G.LOW: hit = self.layout[ri][ci]
                G.output(r, G.HIGH)
            if hit and hit != held: self.on_key(hit)
            held = hit; time.sleep(0.03)


def make_keypad(cfg):
    return GpioKeypad(cfg) if cfg.s("keypad", "driver").lower() == "gpio" else SimKeypad(cfg)
