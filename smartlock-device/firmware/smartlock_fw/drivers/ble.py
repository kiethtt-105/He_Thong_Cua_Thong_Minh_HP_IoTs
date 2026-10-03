"""Bluetooth LE: khoá là PERIPHERAL (GATT server). Điện thoại ghi VÉ vào characteristic `ticket`,
khoá tự kiểm tra vé (offline được) rồi trả kết quả qua characteristic `result` (read/notify).

  driver = sim   : chỉ giả lập quảng bá; dán vé ở web/VS Code
  driver = bless : GATT server THẬT bằng thư viện `bless` (Windows 10+, Linux/BlueZ, macOS)  -> pip install bless
Quy ước app: quét thiết bị tên `adv_name`, kết nối, ghi vé (UTF-8) vào ticket_char_uuid.
Vé dài ~76 ký tự: nếu MTU nhỏ app có thể ghi nhiều đoạn, firmware tự ghép đến khi đủ dạng a.b.c."""
import asyncio
import re
import threading
import time
from . import log, optional_import

TICKET_RE = re.compile(r"^[0-9a-fA-F]{32}\.\d{9,12}\.[0-9a-fA-F]{32}$")


class SimBle:
    kind = "sim"
    def __init__(self, cfg): self.advertising = False; self.name = cfg.s("bluetooth", "adv_name")
    def start(self, on_ticket): self.on_ticket = on_ticket; self.advertising = True; return True
    def stop(self): self.advertising = False
    def notify(self, text): pass


class BlessBle:
    kind = "bless"
    def __init__(self, cfg):
        self.cfg = cfg
        self.name = cfg.s("bluetooth", "adv_name") or "SmartLock-" + "".join(ch for ch in cfg.code if ch.isalnum())[-6:]
        self.svc, self.c_ticket, self.c_result = (cfg.s("bluetooth", k) for k in ("service_uuid", "ticket_char_uuid", "result_char_uuid"))
        self.advertising, self.server, self.loop, self._buf, self._buf_t = False, None, None, "", 0.0
        self.mod = optional_import("bless", "pip install bless")

    def start(self, on_ticket):
        self.on_ticket = on_ticket
        if self.advertising: return True
        ready = threading.Event(); err = []
        def runner():
            self.loop = asyncio.new_event_loop(); asyncio.set_event_loop(self.loop)
            try: self.loop.run_until_complete(self._serve()); ready.set(); self.loop.run_forever()
            except Exception as e: err.append(e); ready.set()
        threading.Thread(target=runner, daemon=True, name="ble").start()
        ready.wait(15)
        if err: raise RuntimeError(f"Không bật được BLE: {err[0]}")
        self.advertising = True; return True

    async def _serve(self):
        m = self.mod
        self.server = m.BlessServer(name=self.name, loop=self.loop)
        self.server.write_request_func = self._on_write
        self.server.read_request_func = lambda ch, **kw: ch.value
        await self.server.add_new_service(self.svc)
        P, A = m.GATTCharacteristicProperties, m.GATTAttributePermissions
        await self.server.add_new_characteristic(self.svc, self.c_ticket, P.write | P.write_without_response, None, A.writeable)
        await self.server.add_new_characteristic(self.svc, self.c_result, P.read | P.notify, bytearray(b"READY"), A.readable)
        await self.server.start()
        log.info("BLE GATT server '%s' đang quảng bá", self.name)

    def _on_write(self, characteristic, value, **kw):
        chunk = bytes(value).decode("utf-8", "ignore").strip()
        now = time.time()
        if now - self._buf_t > 3: self._buf = ""
        self._buf, self._buf_t = self._buf + chunk, now
        if TICKET_RE.match(self._buf):
            t, self._buf = self._buf, ""
            threading.Thread(target=self.on_ticket, args=(t,), daemon=True).start()
        elif len(self._buf) > 200: self._buf = ""

    def notify(self, text):
        if not (self.server and self.loop): return
        try:
            ch = self.server.get_characteristic(self.c_result)
            ch.value = bytearray(text.encode()[:100])
            self.server.update_value(self.svc, self.c_result)
        except Exception as e: log.debug("notify BLE: %s", e)

    def stop(self):
        if not self.advertising: return
        self.advertising = False
        try: asyncio.run_coroutine_threadsafe(self.server.stop(), self.loop).result(5)
        except Exception: pass


def make_ble(cfg):
    return BlessBle(cfg) if cfg.s("bluetooth", "driver").lower() == "bless" else SimBle(cfg)
