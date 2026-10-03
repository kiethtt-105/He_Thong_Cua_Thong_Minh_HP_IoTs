"""CLI:  python -m smartlock_fw <lệnh>
  init            tạo device.conf mới (sinh secret) + faces/ mẫu + in lệnh đăng ký lên máy chủ
  run             chạy khoá (mặc định)
  ticket          cấp vé BLE/NFC để test:  ticket ble --user <uuid> [--ttl 3600]
  face-capture    chụp webcam -> faces/<tên>.json (cần opencv + face_recognition)
  doctor          kiểm tra cấu hình + thư viện + cổng
"""
import argparse
import json
import logging
import random
import secrets
import sys
from pathlib import Path

from . import __version__, protocol as P
from .config import Config

CONF_TEMPLATE = (Path(__file__).parent / "device.conf.example").read_text(encoding="utf-8") if (Path(__file__).parent / "device.conf.example").exists() else ""


def cmd_init(a):
    path = Path(a.conf)
    if path.exists() and not a.force: sys.exit(f"{path} đã tồn tại (dùng --force để ghi đè).")
    code = (a.code or f"LOCK-{secrets.token_hex(2).upper()}").upper()
    secret = secrets.token_hex(16)
    text = CONF_TEMPLATE.replace("@CODE@", code).replace("@SECRET@", secret).replace("@NAME@", a.name)
    path.write_text(text, encoding="utf-8")
    faces = path.parent / "faces"; faces.mkdir(exist_ok=True)
    demo = faces / "alice.json"
    if not demo.exists():
        rnd = random.Random(42)
        demo.write_text(json.dumps({"name": "alice", "embedding": [round(rnd.gauss(0, 0.2), 6) for _ in range(128)]}))
    cfg = Config(path)
    print(f"\n✔ Đã tạo {path}\n  device_code : {code}\n  secret      : {secret}   (GIỮ BÍ MẬT - dùng để claim khoá trên web)\n  mac         : {cfg.mac}\n")
    print("─── Đăng ký khoá này lên máy chủ Django (python manage.py shell) ───")
    print(f"""from smartlock.models import Device
from smartlock.services import hash_token
Device.objects.create(device_code='{code}', provisioning_secret_hash=hash_token('{secret}'),
                      device_mode='simulated', name='{a.name}', mac_address='{cfg.mac}')""")
    print("\nSau đó chạy khoá, rồi vào web: Thiết bị -> Thêm khoá (claim) bằng device_code + secret ở trên.")


def cmd_run(a):
    from .app import App
    cfg = Config(a.conf)
    errs = cfg.validate()
    for e in errs: print("✘", e)
    if errs: sys.exit(2)
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)-5s %(message)s", datefmt="%H:%M:%S")
    App(cfg).run()


def cmd_ticket(a):
    cfg = Config(a.conf)
    t, exp = P.mint_ticket(cfg.code, cfg.secret, a.kind, a.user, a.ttl)
    print(t)
    print(f"(kênh {a.kind}, hết hạn unix {exp})", file=sys.stderr)


def cmd_face(a):
    from .drivers.camera import OpenCvCamera
    cfg = Config(a.conf); cfg.cp["camera"]["driver"] = "opencv"
    cam = OpenCvCamera(cfg); print("Nhìn thẳng camera…")
    v = cam.scan()
    if not v: sys.exit("Không thấy khuôn mặt.")
    out = cfg.p("camera", "faces_dir") / f"{a.name}.json"; out.parent.mkdir(exist_ok=True)
    out.write_text(json.dumps({"name": a.name, "embedding": v})); print("Đã lưu", out)


def cmd_doctor(a):
    import importlib, socket
    cfg = Config(a.conf)
    print(f"Cấu hình: {cfg.path} ({'có' if cfg.found else 'KHÔNG CÓ'})")
    for e in cfg.validate(): print("  ✘", e)
    need = {"paho.mqtt.client": "bắt buộc nếu mode=online", "bless": "bluetooth driver=bless", "smartcard": "nfc driver=pcsc",
            "mfrc522": "nfc driver=rc522", "RPi.GPIO": "relay/servo/keypad gpio", "cv2": "camera opencv",
            "face_recognition": "camera opencv", "psutil": "power source=system"}
    for m, why in need.items():
        try: importlib.import_module(m); print(f"  ✔ {m}")
        except Exception: print(f"  - {m} chưa có ({why})")
    s = socket.socket(); s.settimeout(1)
    try: s.connect((cfg.s("server", "mqtt_host"), cfg.i("server", "mqtt_port"))); print("  ✔ broker MQTT truy cập được")
    except OSError as e: print(f"  ✘ broker MQTT {cfg.s('server', 'mqtt_host')}:{cfg.i('server', 'mqtt_port')} không kết nối được ({e})")
    finally: s.close()


def main():
    ap = argparse.ArgumentParser(prog="smartlock_fw", description=f"SmartLock firmware {__version__}")
    ap.add_argument("-c", "--conf", default="device.conf")
    sub = ap.add_subparsers(dest="cmd")
    p = sub.add_parser("init"); p.add_argument("--code"); p.add_argument("--name", default="SmartLock giả lập"); p.add_argument("--force", action="store_true"); p.set_defaults(f=cmd_init)
    p = sub.add_parser("run"); p.set_defaults(f=cmd_run)
    p = sub.add_parser("ticket"); p.add_argument("kind", choices=["ble", "nfc"]); p.add_argument("--user", required=True); p.add_argument("--ttl", type=int, default=3600); p.set_defaults(f=cmd_ticket)
    p = sub.add_parser("face-capture"); p.add_argument("name"); p.set_defaults(f=cmd_face)
    p = sub.add_parser("doctor"); p.set_defaults(f=cmd_doctor)
    ap.set_defaults(f=cmd_run)
    a = ap.parse_args()
    a.f(a)


if __name__ == "__main__":
    main()
