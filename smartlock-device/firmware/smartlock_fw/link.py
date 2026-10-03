"""Kết nối MQTT tới broker của hệ thống (Wi-Fi). Username = device_code, password = secret gốc
(đúng như mqtt_auth_webhook). Mất Wi-Fi/tắt radio => ngắt MQTT; các kênh BLE/NFC-điện thoại vẫn mở cửa offline."""
import json
import threading
import time

from . import protocol as P


class MqttLink:
    def __init__(self, cfg, core, bus):
        self.cfg, self.core, self.bus = cfg, core, bus
        self.client, self.connected, self.net_ok = None, False, False
        self.lk = threading.Lock()
        self.code = cfg.code
        try:
            import paho.mqtt.client as mqtt
            self.mqtt = mqtt
        except ImportError:
            self.mqtt = None

    # ------------------------------------------------------------ vòng đời
    def start(self, net_ok):
        if self.cfg.standalone: return
        if not self.mqtt:
            return self.bus.log("crit", "mqtt", 'Chưa cài paho-mqtt: pip install "paho-mqtt<2"  (hoặc đặt [server] mode = standalone)')
        self.set_network(net_ok)

    def stop(self): self._drop()

    def restart(self):
        self._drop(); time.sleep(1.0)
        if self.net_ok: self._open()

    def set_network(self, online):
        if self.cfg.standalone or not self.mqtt or online == self.net_ok: return
        self.net_ok = online
        if online: self._open()
        else:
            self._drop(); self.bus.log("warn", "mqtt", "Mất mạng: khoá chạy OFFLINE (chỉ còn vé BLE/NFC điện thoại)")

    def ready(self): return self.connected and self.net_ok

    # ------------------------------------------------------------ nội bộ
    def _new_client(self):
        m = self.mqtt
        cid = self.cfg.s("server", "client_id") or self.code
        try: c = m.Client(m.CallbackAPIVersion.VERSION1, client_id=cid, clean_session=False)   # paho 2.x
        except AttributeError: c = m.Client(client_id=cid, clean_session=False)                  # paho 1.x
        c.username_pw_set(self.code, self.cfg.secret)
        if self.cfg.b("server", "mqtt_tls"): c.tls_set(ca_certs=self.cfg.s("server", "mqtt_ca") or None)
        c.reconnect_delay_set(1, 30)
        c.on_connect, c.on_disconnect, c.on_message = self._on_connect, self._on_disconnect, self._on_message
        return c

    def _open(self):
        with self.lk:
            self._drop_locked()
            c = self.client = self._new_client()
            host, port = self.cfg.s("server", "mqtt_host"), self.cfg.i("server", "mqtt_port")
            self.bus.log("info", "mqtt", f"Đang kết nối broker {host}:{port} …")
            try: c.connect_async(host, port, self.cfg.i("server", "keepalive")); c.loop_start()
            except Exception as e: self.bus.log("crit", "mqtt", f"Lỗi MQTT: {e}")

    def _drop(self):
        with self.lk: self._drop_locked()

    def _drop_locked(self):
        c, self.client, self.connected = self.client, None, False
        if c:
            try: c.disconnect(); c.loop_stop()
            except Exception: pass

    def _on_connect(self, c, ud, flags, rc):
        if c is not self.client: return
        if rc != 0:
            why = {4: "sai username/secret", 5: "broker từ chối (thiết bị chưa đăng ký hoặc sai secret)"}.get(rc, f"mã {rc}")
            return self.bus.log("crit", "mqtt", f"Broker từ chối kết nối: {why}")
        self.connected = True
        c.subscribe(P.topic_cmd(self.code), qos=1)
        self.bus.log("ok", "mqtt", f"Đã kết nối broker, nghe {P.topic_cmd(self.code)}")
        self.core.st["mqtt"]["connected"] = True
        self.send_status()
        threading.Thread(target=self.core.flush_queue, daemon=True).start()
        self.core.changed()

    def _on_disconnect(self, c, ud, rc):
        if c is not self.client: return
        self.connected = False; self.core.st["mqtt"]["connected"] = False
        if self.net_ok: self.bus.log("warn", "mqtt", "Mất kết nối broker, đang thử lại…")
        self.core.changed()

    def _on_message(self, c, ud, msg):
        try: data = json.loads(msg.payload.decode("utf-8"))
        except Exception: return self.bus.log("warn", "mqtt", "Gói lệnh không đọc được")
        if isinstance(data, dict): threading.Thread(target=self.core.handle_command, args=(data,), daemon=True).start()

    def _pub(self, topic, obj, qos=1):
        c = self.client
        if not (c and self.connected): return False
        try: return c.publish(topic, P.dumps(obj), qos=qos).rc == 0
        except Exception: return False

    # ------------------------------------------------------------ gửi lên
    def send_status(self): return self._pub(P.topic_status(self.code), P.build_status(self.core.snapshot()), qos=0)
    def send_event(self, kind, **data): return self._pub(P.topic_event(self.code), P.build_event(kind, **data))
    def send_ack(self, cid, tok, ok, state, err=None): return self._pub(P.topic_ack(self.code), P.build_ack(cid, tok, ok, state, err))
