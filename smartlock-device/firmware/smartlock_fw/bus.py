"""Bus sự kiện: nhật ký trong RAM + phát SSE cho trang live / VS Code."""
import itertools
import json
import logging
import queue
import threading
import time
from collections import deque

console = logging.getLogger("smartlock")


class EventBus:
    def __init__(self, keep=300):
        self.ring, self.subs, self.ids, self.lk = deque(maxlen=keep), set(), itertools.count(1), threading.Lock()

    def log(self, level, kind, text, **data):
        """level: info|ok|warn|crit ; kind: lock|rfid|pin|face|ble|nfc|mqtt|wifi|cmd|power|sys"""
        e = {"id": next(self.ids), "ts": time.time(), "level": level, "kind": kind, "text": text, "data": data}
        with self.lk: self.ring.append(e)
        console.log({"info": 20, "ok": 20, "warn": 30, "crit": 40}.get(level, 20), "[%s] %s", kind, text)
        self._fan({"t": "log", "e": e})
        return e

    def push_state(self, st): self._fan({"t": "state", "s": st})

    def _fan(self, msg):
        s = json.dumps(msg, ensure_ascii=False, default=str)
        with self.lk: subs = list(self.subs)
        for q in subs:
            try: q.put_nowait(s)
            except queue.Full: pass

    def subscribe(self):
        q = queue.Queue(maxsize=500)
        with self.lk: self.subs.add(q)
        return q

    def unsubscribe(self, q):
        with self.lk: self.subs.discard(q)

    def history(self, n=100):
        with self.lk: return list(self.ring)[-n:]
