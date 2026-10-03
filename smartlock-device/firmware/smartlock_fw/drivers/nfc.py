"""NFC: sim | pcsc (đầu đọc USB PC/SC như ACR122U/ACR1252, pip install pyscard) | rc522 (RFID-RC522 trên Raspberry Pi).

Một thẻ chạm vào đầu đọc có 2 khả năng:
  1) Điện thoại giả lập thẻ (HCE): đầu đọc gửi SELECT AID -> điện thoại trả VÉ (ASCII) + 90 00  => on_ticket(ticket)
  2) Thẻ vật lý (Mifare...): đọc UID                                                              => on_uid(uid)
"""
import threading
import time
from . import log, optional_import


class SimNfc:
    kind = "sim"
    def __init__(self, cfg): self.running = False
    def start(self, on_uid, on_ticket): self.running = True
    def stop(self): self.running = False


class PcscNfc:
    kind = "pcsc"
    def __init__(self, cfg):
        self.sc = optional_import("smartcard.System", "pip install pyscard")
        self.name_filter = cfg.s("nfc", "reader").lower()
        aid = bytes.fromhex(cfg.s("nfc", "hce_aid"))
        self.select = [0x00, 0xA4, 0x04, 0x00, len(aid)] + list(aid) + [0x00]
        self.running = False

    def start(self, on_uid, on_ticket):
        self.on_uid, self.on_ticket, self.running = on_uid, on_ticket, True
        threading.Thread(target=self._loop, daemon=True, name="nfc").start()

    def stop(self): self.running = False

    def _reader(self):
        for r in self.sc.readers():
            if self.name_filter in str(r).lower(): return r

    def _loop(self):
        present, last = False, 0
        while self.running:
            try:
                r = self._reader()
                if not r: time.sleep(2); continue
                conn = r.createConnection(); conn.connect()
                if present or time.time() - last < 1.5: time.sleep(0.3); continue
                present, last = True, time.time()
                data, s1, s2 = conn.transmit(self.select)
                if (s1, s2) == (0x90, 0x00) and data:
                    self.on_ticket(bytes(data).decode("ascii", "ignore").strip())
                else:
                    uid, s1, s2 = conn.transmit([0xFF, 0xCA, 0x00, 0x00, 0x00])
                    if (s1, s2) == (0x90, 0x00): self.on_uid("".join(f"{b:02X}" for b in uid))
            except Exception as e:
                present = False if "No card" in str(e) or "Card is unresponsive" in str(e) or "Unable to connect" in str(e) else present
                time.sleep(0.4)
                if "No card" not in str(e) and "Unable" not in str(e): log.debug("pcsc: %s", e)


class Rc522Nfc:
    kind = "rc522"
    def __init__(self, cfg):
        self.mod = optional_import("mfrc522", "pip install mfrc522 spidev (bật SPI trên Raspberry Pi)")
        self.running = False

    def start(self, on_uid, on_ticket):
        self.on_uid, self.running = on_uid, True
        threading.Thread(target=self._loop, daemon=True, name="nfc").start()

    def stop(self): self.running = False

    def _loop(self):
        rd, last = self.mod.MFRC522(), (None, 0)
        while self.running:
            st, _ = rd.MFRC522_Request(rd.PICC_REQIDL)
            if st == rd.MI_OK:
                st, uid = rd.MFRC522_Anticoll()
                if st == rd.MI_OK:
                    u = "".join(f"{b:02X}" for b in uid[:4])
                    if u != last[0] or time.time() - last[1] > 2:
                        last = (u, time.time()); self.on_uid(u)
            time.sleep(0.15)


def make_nfc(cfg):
    d = cfg.s("nfc", "driver").lower()
    return {"sim": SimNfc, "pcsc": PcscNfc, "rc522": Rc522Nfc}[d](cfg)
