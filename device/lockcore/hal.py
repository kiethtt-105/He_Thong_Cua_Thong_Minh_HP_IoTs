"""HAL giả lập phần cứng: chốt servo, cảm biến cửa, rung/va đập, pin, RSSI, nhiệt độ, còi/LED.
Khi lên ESP32 thật: viết hal_esp32.py có CÙNG các hàm/thuộc tính này (machine.Pin, PWM, ADC...) - controller không đổi."""
import random
import threading
import time


class SimHAL:
    def __init__(self, hw):
        self.hw = hw
        self._mtx = threading.Lock()
        self.lock_state = 'locked'      # locked | unlocked | jammed
        self.door_open = False
        self.tamper = False
        self.battery = float(hw.get('battery', 100))
        self.signal = int(hw.get('signal', -55))
        self.base_temp = float(hw.get('temperature', 27.0))
        self.led = 'idle'
        self.on_door_change = None      # callback(open: bool)

    @property
    def temperature(self):
        return round(self.base_temp + random.uniform(-0.4, 0.4), 1)

    def set_door(self, is_open):
        with self._mtx:
            changed = self.door_open != bool(is_open)
            self.door_open = bool(is_open)
        if changed and self.on_door_change:
            self.on_door_change(self.door_open)

    def shock(self, on=True):
        self.tamper = bool(on)

    def _move(self, target):
        with self._mtx:
            time.sleep(float(self.hw.get('servo_seconds', 0.6)))
            if random.random() < float(self.hw.get('jam_chance', 0)):
                self.lock_state = 'jammed'
                return False
            self.lock_state = target
            return True

    def unlock(self):
        return self._move('unlocked')

    def lock(self):
        return self._move('locked')

    def beep(self, kind):          # ok | deny | alarm
        self.led = {'ok': 'green', 'deny': 'red', 'alarm': 'red'}.get(kind, 'idle')
