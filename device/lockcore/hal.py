"""HAL - lớp phần cứng. Controller KHÔNG BAO GIỜ đụng GPIO/camera/UI: mọi thứ vào/ra đều đi qua đây.

Mục tiêu: SimHAL cư xử như khoá thật (chốt mất thời gian, kẹt, tốn pin, nóng lên, cảm biến rung tự nhả, mất điện
vẫn giữ vị trí chốt/cửa) và MỌI tác động bên ngoài (quẹt thẻ, gõ PIN, bấm quét mặt, điện thoại, núm xoay, mở cửa, va đập)
đều vào controller bằng ĐÚNG đường callback mà phần cứng thật sẽ dùng. Sau này mua linh kiện chỉ viết hal_pi.py (PiHAL)
có cùng hợp đồng; controller, api, mqtt, webui không đổi dòng nào.

HỢP ĐỒNG (BaseHAL)
  trạng thái : lock_state 'locked'|'unlocked'|'jammed' · door_open · tamper · battery(0-100) · signal(dBm) · temperature · led
  chấp hành  : unlock()->bool · lock()->bool · beep('ok'|'deny'|'alarm')
  vòng đời   : on_boot() · tick() (0.5s/lần) · close()
  camera     : capture_embedding() -> list[128 float] | None
  callback (HAL gọi LÊN controller, có thể từ thread khác):
    on_door_change(open) · on_shock() · on_card(uid_hex) · on_pin('123456') · on_face_trigger() · on_phone(kind, ticket) · on_knob()
"""
import json
import os
import random
import threading
import time
from collections import deque


class BaseHAL:
    is_sim = False
    kind = 'base'
    lock_state = 'locked'
    door_open = False
    tamper = False
    battery = 100.0
    signal = -55
    temperature = 0.0
    led = 'idle'

    def __init__(self, hw):
        self.hw = hw
        self.on_door_change = self.on_shock = self.on_card = self.on_pin = None
        self.on_face_trigger = self.on_phone = self.on_knob = None

    def on_boot(self): pass
    def tick(self): pass
    def close(self): pass
    def unlock(self): raise NotImplementedError
    def lock(self): raise NotImplementedError
    def beep(self, kind): pass
    def shock(self, on=True): self.tamper = bool(on)
    def capture_embedding(self): return None
    def describe(self): return {}


# =====================================================================================================
class SimHAL(BaseHAL):
    is_sim = True
    kind = 'sim'

    def __init__(self, hw, state_path=None):
        super().__init__(hw)
        self._mtx = threading.RLock()
        self._path = state_path
        st = self._load()
        # trạng thái VẬT LÝ sống sót qua "mất điện" (tắt/bật lại python): vị trí chốt, cửa, mức pin
        self.lock_state = st.get('lock_state', 'locked')
        self.door_open = bool(st.get('door_open', False))
        self._battery = float(st.get('battery', hw.get('battery', 100)))
        self.tamper = False
        self._tamper_at = None
        self._signal = int(hw.get('signal', -55))
        self.base_temp = float(hw.get('temperature', 27.0))
        self._heat = 0.0
        self._last_tick = time.time()
        self._face_vec = None
        self.led = 'idle'
        self.beeps = deque(maxlen=20)

    # ---------------- lưu / nạp trạng thái vật lý ----------------
    def _load(self):
        try:
            with open(self._path, encoding='utf-8') as f:
                return json.load(f)
        except (OSError, ValueError, TypeError):
            return {}

    def _save(self):
        if not self._path:
            return
        try:
            tmp = self._path + '.tmp'
            with open(tmp, 'w', encoding='utf-8') as f:
                json.dump({'lock_state': self.lock_state, 'door_open': self.door_open,
                           'battery': round(self._battery, 3)}, f)
            os.replace(tmp, self._path)
        except OSError:
            pass

    # ---------------- cảm biến ----------------
    @property
    def battery(self):
        return self._battery

    @battery.setter
    def battery(self, v):
        self._battery = max(0.0, min(100.0, float(v)))
        self._save()

    @property
    def signal(self):                       # RSSI dao động ±1 dBm như thật
        return self._signal + random.randint(-1, 1)

    @signal.setter
    def signal(self, v):
        self._signal = int(v)

    @property
    def temperature(self):                  # nhiệt độ môi trường + nhiệt do servo + nhiễu cảm biến
        return round(self.base_temp + self._heat + random.uniform(-0.3, 0.3), 1)

    # ---------------- vòng đời ----------------
    def on_boot(self):
        """Khởi động = đọc lại vị trí chốt từ cảm biến. Sim: lấy từ state đã lưu (KHÔNG tự ép 'locked')."""
        if self.lock_state not in ('locked', 'unlocked', 'jammed'):
            self.lock_state = 'locked'

    def tick(self):
        now = time.time()
        dt, self._last_tick = now - self._last_tick, now
        mins = float(self.hw.get('battery_drain_minutes') or 0)     # tụt 1% mỗi N phút (tự xả + tiêu thụ nền)
        if mins:
            self._battery = max(0.0, self._battery - dt / (mins * 60))
        self._heat = max(0.0, self._heat - dt * 0.05)                # servo nguội dần
        clear = float(self.hw.get('tamper_clear_seconds', 30))
        if self.tamper and self._tamper_at and now - self._tamper_at >= clear:
            self.tamper = False                                      # cảm biến rung tự nhả như thật

    def close(self):
        self._save()

    # ---------------- chấp hành ----------------
    def _move(self, target):
        with self._mtx:
            if self._battery <= 0:                                   # hết pin: servo không quay
                return False
            for _ in range(2):                                       # firmware thật thử lại 1 lần khi servo kẹt
                time.sleep(float(self.hw.get('servo_seconds', 0.6)))
                self._battery = max(0.0, self._battery - float(self.hw.get('move_cost_pct', 0.02)))
                self._heat = min(8.0, self._heat + 0.4)
                if random.random() >= float(self.hw.get('jam_chance', 0)):
                    self.lock_state = target
                    self._save()
                    return True
            self.lock_state = 'jammed'
            self._save()
            return False

    def unlock(self): return self._move('unlocked')
    def lock(self): return self._move('locked')

    def beep(self, kind):
        self.led = {'ok': 'green', 'deny': 'red', 'alarm': 'red'}.get(kind, 'idle')
        self.beeps.append((time.strftime('%H:%M:%S'), kind))
        t = threading.Timer(2.0, lambda: setattr(self, 'led', 'idle'))
        t.daemon = True
        t.start()

    def shock(self, on=True):
        self.tamper = bool(on)
        self._tamper_at = time.time() if on else None

    def capture_embedding(self):
        """Camera + model: mất ~0.8s. Sim: embedding do trình duyệt (webcam + face-api.js) trích rồi gửi xuống qua sim_set_face()."""
        time.sleep(float(self.hw.get('face_seconds', 0.8)))
        return list(self._face_vec) if self._face_vec else None

    def describe(self):
        return {'battery_pct': round(self._battery, 2), 'servo_heat': round(self._heat, 1), 'beeps': list(self.beeps)[-5:]}

    # ---------------- TÁC ĐỘNG BÊN NGOÀI (thay cho tay người / phần cứng thật) ----------------
    # Mỗi hàm sim_* phát đúng callback mà driver thật sẽ phát, trả về kết quả của controller để UI hiển thị.
    def sim_door(self, is_open):
        with self._mtx:
            changed = self.door_open != bool(is_open)
            self.door_open = bool(is_open)
            self._save()
        if changed and self.on_door_change:
            self.on_door_change(self.door_open)

    set_door = sim_door                                              # tên cũ

    def sim_shock(self, on=True):
        self.shock(on)
        if on and self.on_shock:
            self.on_shock()

    def sim_tap_card(self, uid):
        time.sleep(0.15)                                             # thời gian đầu đọc đọc UID
        uid = ''.join(c for c in str(uid) if c.isalnum()).upper()
        return self.on_card(uid) if self.on_card else None

    def sim_keypad(self, pin):
        return self.on_pin(str(pin)) if self.on_pin else None

    def sim_set_face(self, vec):
        self._face_vec = [float(x) for x in vec] if vec else None

    def sim_press_face(self):                                        # nút/PIR bấm -> camera chụp -> embedding
        return self.on_face_trigger() if self.on_face_trigger else None

    def sim_phone(self, kind, ticket):
        return self.on_phone(kind, ticket) if self.on_phone else None

    def sim_knob(self):
        if self.on_knob:
            self.on_knob()


# =====================================================================================================
def get_hal(hw, state_path=None):
    """hardware.hal: 'sim' (mặc định) | 'real' (bắt buộc phần cứng) | 'auto' (có hal_pi thì dùng, không thì sim)."""
    mode = str(hw.get('hal') or 'sim').lower()
    if mode in ('real', 'auto'):
        try:
            from .hal_pi import PiHAL            # file này sẽ viết SAU khi mua & đấu dây xong linh kiện
            return PiHAL(hw)
        except ImportError as e:
            if mode == 'real':
                raise RuntimeError('hardware.hal="real" nhưng chưa có lockcore/hal_pi.py') from e
        except Exception as e:
            if mode == 'real':
                raise RuntimeError(f'Khởi tạo phần cứng thất bại: {e}') from e
            print(f'[HAL] phần cứng lỗi ({e}) -> dùng SimHAL')
    return SimHAL(hw, state_path)
