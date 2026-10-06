"""Chạy:  cd firmware && python -m unittest discover -s ../tests -v"""
import hashlib, hmac, json, os, sys, tempfile, time, types, unittest, uuid
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "firmware"))

from smartlock_fw import protocol as P
from smartlock_fw.app import App
from smartlock_fw.config import Config

SECRET, CODE = "s3cret-" + uuid.uuid4().hex, "LOCK-TEST"


# ---- bản sao NGUYÊN VĂN thuật toán server (services._ticket_sig / parse) để đối chiếu chéo
class FakeDevice:
    device_code = CODE
    provisioning_secret_hash = hashlib.sha256(SECRET.encode()).hexdigest()

def server_sig(device, kind, user_hex, exp):
    label = {'ble': b'ble-ticket-v1', 'nfc': b'nfc-phone-ticket-v1'}[kind]
    key = hmac.new(device.provisioning_secret_hash.encode(), label, hashlib.sha256).digest()
    return hmac.new(key, f'{device.device_code}|{user_hex}|{exp}'.encode(), hashlib.sha256).hexdigest()[:32]


def make_conf(tmp, extra=""):
    p = Path(tmp) / "device.conf"
    p.write_text(f"""[device]
code={CODE}
secret={SECRET}
state_file={Path(tmp)/'state.json'}
[server]
mode=standalone
[lock]
unlock_seconds=1
[ui]
port=0
[camera]
faces_dir={Path(tmp)/'faces'}
[standalone.cards]
chu = 04A1B2C3
[standalone.pins]
chu = 123456
mot lan = 654321, 1
{extra}""", encoding="utf-8")
    (Path(tmp) / "faces").mkdir(exist_ok=True)
    import random; r = random.Random(1)
    (Path(tmp) / "faces" / "alice.json").write_text(json.dumps({"name": "alice", "embedding": [r.gauss(0, .2) for _ in range(128)]}))
    return p


class FakeLink:
    def __init__(self): self.up, self.events, self.acks, self.statuses = True, [], [], 0
    connected = property(lambda s: s.up)
    def ready(self): return self.up
    def send_event(self, k, **d):
        if not self.up: return False
        self.events.append((k, d)); return True
    def send_ack(self, *a): self.acks.append(a)
    def send_status(self): self.statuses += 1
    def set_network(self, on): pass
    def restart(self): pass
    def stop(self): pass


class Base(unittest.TestCase):
    online = False
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        conf = make_conf(self.tmp)
        cfg = Config(conf)
        if self.online: cfg.cp["server"]["mode"] = "online"
        self.app = App(cfg); self.core = self.app.core
        self.link = FakeLink(); self.core.link = self.link
        self.core.act.lock()
    def state(self): return self.core.st["lock_state"]
    def pin(self, v): self.core.type_pin(v); time.sleep(0.2)


class ProtocolTests(unittest.TestCase):
    def test_ticket_matches_server_algorithm(self):
        uid = uuid.uuid4()
        for kind in ("ble", "nfc"):
            t, exp = P.mint_ticket(CODE, SECRET, kind, uid, 600)
            hex_, e, sig = t.split(".")
            self.assertEqual(hex_, uid.hex); self.assertEqual(int(e), exp)
            self.assertEqual(sig, server_sig(FakeDevice, kind, hex_, exp))
            self.assertTrue(P.verify_ticket(CODE, SECRET, kind, t)[0])

    def test_channels_isolated_and_tamper(self):
        t, _ = P.mint_ticket(CODE, SECRET, "ble", uuid.uuid4())
        self.assertEqual(P.verify_ticket(CODE, SECRET, "nfc", t)[1], "INVALID_TICKET")
        bad = t[:-1] + ("0" if t[-1] != "0" else "1")
        self.assertEqual(P.verify_ticket(CODE, SECRET, "ble", bad)[1], "INVALID_TICKET")
        self.assertEqual(P.verify_ticket(CODE, "other", "ble", t)[1], "INVALID_TICKET")
        old, _ = P.mint_ticket(CODE, SECRET, "ble", uuid.uuid4(), -5)
        self.assertEqual(P.verify_ticket(CODE, SECRET, "ble", old)[1], "TICKET_EXPIRED")
        self.assertEqual(P.verify_ticket(CODE, SECRET, "ble", "garbage")[1], "INVALID_TICKET")

    def test_uid_and_hash(self):
        self.assertEqual(P.normalize_uid(" 04:a1-b2 c3 "), "04A1B2C3")
        self.assertEqual(P.hash_token("x"), hashlib.sha256(b"x").hexdigest())


class StandaloneTests(Base):
    def test_card_pin_face(self):
        self.core.on_rfid("04:a1:b2:c3"); self.assertEqual(self.state(), "unlocked")
        self.core.do_lock(); self.core.on_rfid("DEADBEEF"); self.assertEqual(self.state(), "locked")
        self.pin("123456"); self.assertEqual(self.state(), "unlocked")
        self.core.do_lock(); self.pin("654321"); self.assertEqual(self.state(), "unlocked")
        self.core.do_lock(); self.pin("654321"); self.assertEqual(self.state(), "locked")  # PIN dùng 1 lần
        self.core.request_face("alice"); self.assertEqual(self.state(), "unlocked")
        self.core.do_lock(); self.core.request_face("stranger"); self.assertEqual(self.state(), "locked")

    def test_burst_lockout(self):
        for _ in range(3): self.core.on_rfid("BAD00001")
        self.assertGreater(self.core.snapshot()["lockout_remaining"], 0)
        self.core.on_rfid("04A1B2C3"); self.assertEqual(self.state(), "locked")   # đúng thẻ nhưng đang khoá tạm

    def test_phone_tickets_and_expiry(self):
        t, _ = P.mint_ticket(CODE, SECRET, "ble", uuid.uuid4()); self.core.on_ble_ticket(t); self.assertEqual(self.state(), "unlocked")
        self.core.do_lock(); self.core.on_nfc_ticket(t); self.assertEqual(self.state(), "locked")   # vé BLE không dùng ở NFC
        n, _ = P.mint_ticket(CODE, SECRET, "nfc", uuid.uuid4()); self.core.on_nfc_ticket(n); self.assertEqual(self.state(), "unlocked")
        self.core.do_lock(); self.core.set_radio("bluetooth", False); self.core.on_ble_ticket(t); self.assertEqual(self.state(), "locked")

    def test_auto_relock_and_jam(self):
        self.core.grant("test"); time.sleep(1.1); self.core.tick(1); self.assertEqual(self.state(), "locked")
        self.core.set_jam(True); self.core.grant("test"); self.assertEqual(self.state(), "jammed")
        self.core.set_jam(False); self.assertEqual(self.state(), "locked")


class OnlineTests(Base):
    online = True
    def test_credentials_sent_to_server_and_unlocked_by_command(self):
        self.core.on_rfid("04A1B2C3")
        self.assertEqual(self.link.events[-1][0], "rfid"); self.assertEqual(self.link.events[-1][1]["uid"], "04A1B2C3")
        self.assertEqual(self.state(), "locked"); self.assertEqual(self.core.pending["kind"], "rfid")
        self.core.handle_command({"command_id": "c1", "command": "UNLOCK", "token": "tk", "source": "rfid"})
        self.assertEqual(self.state(), "unlocked"); self.assertIsNone(self.core.pending)
        self.assertEqual(self.link.acks[-1][:3], ("c1", "tk", True))

    def test_pin_never_logged_and_sent_plain(self):
        self.core.type_pin("246810"); time.sleep(0.2)
        self.assertEqual(self.link.events[-1], ("pin", {"pin": "246810"}))
        self.assertFalse(any("246810" in e["text"] for e in self.app.bus.history()))

    def test_pending_timeout_counts_as_failure(self):
        self.core.cfg.cp["security"]["verify_timeout_seconds"] = "0"
        self.core.on_rfid("04A1B2C3"); time.sleep(0.05); self.core.tick(1)
        self.assertIsNone(self.core.pending); self.assertEqual(self.state(), "locked")

    def test_offline_blocks_server_channels_but_phone_ticket_works_and_queues(self):
        self.link.up = False
        self.core.on_rfid("04A1B2C3"); self.assertEqual(self.state(), "locked"); self.assertEqual(self.link.events, [])
        t, _ = P.mint_ticket(CODE, SECRET, "ble", uuid.uuid4()); self.core.on_ble_ticket(t)
        self.assertEqual(self.state(), "unlocked"); self.assertEqual(len(self.core.persist["queue"]), 1)
        self.link.up = True; self.core.flush_queue()
        k, d = self.link.events[-1]; self.assertEqual(k, "ble"); self.assertTrue(d["ok"]); self.assertEqual(d["ticket"], t)
        self.assertEqual(self.core.persist["queue"], [])

    def test_bad_ticket_reported_with_reason(self):
        self.core.on_ble_ticket("a" * 32 + ".9999999999." + "b" * 32)
        k, d = self.link.events[-1]; self.assertFalse(d["ok"]); self.assertEqual(d["reason"], "BLE_INVALID_TICKET")

    def test_commands_dedupe_lock_ping_reboot_unknown(self):
        self.core.handle_command({"command_id": "u1", "command": "UNLOCK", "token": "t", "source": "web"})
        self.core.handle_command({"command_id": "u1", "command": "UNLOCK", "token": "t", "source": "web"})
        self.assertEqual(len(self.link.acks), 1)
        self.core.handle_command({"command_id": "l1", "command": "LOCK", "token": "t"}); self.assertEqual(self.state(), "locked")
        self.core.handle_command({"command_id": "p1", "command": "PING", "token": "t"}); self.assertTrue(self.link.acks[-1][2])
        self.core.handle_command({"command_id": "x1", "command": "OTA_UPDATE", "token": "t"}); self.assertFalse(self.link.acks[-1][2])
        self.core.handle_command({"command": "BUZZER_ALERT", "reason": "ACCESS_BURST"})   # không có command_id: không ack

    def test_status_payload(self):
        s = P.build_status(self.core.snapshot())
        for k in ("lock_state", "battery", "signal_strength", "tamper_detected", "temperature", "firmware", "mac"): self.assertIn(k, s)
        self.assertRegex(s["mac"], r"^([0-9A-F]{2}:){5}[0-9A-F]{2}$")   # khớp validator Device.mac_address


class MqttLinkTests(unittest.TestCase):
    """Dùng paho giả để kiểm tra đúng username/password/topic."""
    def test_link_with_fake_paho(self):
        calls = {"pub": [], "sub": []}
        class FakeClient:
            def __init__(self, *a, **k): calls["init"] = k
            def username_pw_set(self, u, p): calls["auth"] = (u, p)
            def will_set(self, t, p, qos=0, retain=False): calls["will"] = (t, json.loads(p))
            def reconnect_delay_set(self, *a): pass
            def connect_async(self, h, p, k): calls["host"] = (h, p)
            def loop_start(self):
                import threading; threading.Timer(0.05, lambda: self.on_connect(self, None, {}, 0)).start()
            def loop_stop(self): pass
            def disconnect(self): pass
            def subscribe(self, t, qos=0): calls["sub"].append((t, qos))
            def publish(self, t, p, qos=0): calls["pub"].append((t, json.loads(p), qos)); return types.SimpleNamespace(rc=0, wait_for_publish=lambda *a: None)
        fake = types.ModuleType("paho.mqtt.client"); fake.Client = FakeClient
        sys.modules.update({"paho": types.ModuleType("paho"), "paho.mqtt": types.ModuleType("paho.mqtt"), "paho.mqtt.client": fake})
        tmp = tempfile.mkdtemp(); cfg = Config(make_conf(tmp)); cfg.cp["server"]["mode"] = "online"
        app = App(cfg); app.link.start(True); time.sleep(0.4)
        self.assertEqual(calls["auth"], (CODE, SECRET))                # đúng quy ước mqtt_auth_webhook
        self.assertIn((f"smartlock/{CODE}/cmd", 1), calls["sub"])
        self.assertEqual(calls["will"], (f"smartlock/{CODE}/status", {"state": "offline", "online": False}))   # LWT khớp on_status
        self.assertIn("boot", [p["type"] for t, p, _ in calls["pub"] if t.endswith("/event")])
        topics = [t for t, _, _ in calls["pub"]]; self.assertIn(f"smartlock/{CODE}/status", topics)
        app.core.on_rfid("04A1B2C3"); time.sleep(0.2)
        ev = [p for t, p, _ in calls["pub"] if t == f"smartlock/{CODE}/event"][-1]; self.assertEqual(ev["type"], "rfid")
        app.link._on_message(app.link.client, None, types.SimpleNamespace(payload=json.dumps(
            {"command_id": "z", "command": "UNLOCK", "token": "tt", "source": "web"}).encode())); time.sleep(0.3)
        self.assertEqual(app.core.st["lock_state"], "unlocked")
        ack = [p for t, p, _ in calls["pub"] if t == f"smartlock/{CODE}/ack"][-1]; self.assertEqual((ack["command_id"], ack["token"]), ("z", "tt"))


class AdminGateTests(unittest.TestCase):
    def _cfg(self, mode, **ui):
        c = Config(make_conf(tempfile.mkdtemp())); c.cp["device"]["mode"] = mode
        for k, v in ui.items(): c.cp["ui"][k] = v
        return c
    def test_admin_auto(self):
        self.assertTrue(self._cfg("simulated").admin_ok)
        self.assertFalse(self._cfg("physical").admin_ok)
        self.assertTrue(self._cfg("physical", allow_admin="true").admin_ok)
    def test_open_host_needs_token(self):
        self.assertTrue(any("token" in e for e in self._cfg("simulated", host="0.0.0.0").validate()))
        self.assertFalse(any("token" in e for e in self._cfg("simulated", host="0.0.0.0", token="x").validate()))


if __name__ == "__main__":
    unittest.main()
