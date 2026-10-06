"""Phòng lab: tạo khoá mới + sửa thông tin khoá (ghi lại device.conf, giữ nguyên chú thích)."""
import json
import random
import re
import secrets
from pathlib import Path

from .config import Config

EXAMPLE = Path(__file__).parent / "device.conf.example"
FIELDS = {"name": ("device", "name"), "location": ("device", "location"), "firmware": ("device", "firmware"),
          "unlock_seconds": ("lock", "unlock_seconds")}


def set_conf_value(path, section, key, value):
    """Sửa đúng 1 dòng `key = value` trong [section], giữ chú thích ';' cuối dòng."""
    path = Path(path); lines = path.read_text(encoding="utf-8").splitlines(keepends=True)
    cur, rx = None, re.compile(rf"^(\s*{re.escape(key)}\s*=\s*)([^;\r\n]*?)(\s*(;.*)?)(\r?\n?)$")
    for i, ln in enumerate(lines):
        m = re.match(r"\s*\[([^\]]+)\]", ln)
        if m: cur = m.group(1).strip(); continue
        if cur == section and (mm := rx.match(ln)):
            rest = mm.group(3) or ''; lines[i] = f"{mm.group(1)}{value}{'  ' if rest.lstrip().startswith(';') and not rest[:1].isspace() else ''}{rest}{mm.group(5)}"; break
    else:
        raise KeyError(f"[{section}] {key} không có trong {path.name}")
    path.write_text("".join(lines), encoding="utf-8")


def update_lock(app, data):
    """Đổi thông tin khoá đang chạy: cập nhật cfg + trạng thái + file device.conf."""
    cfg, core = app.cfg, app.core; changed = {}
    for k, (sec, key) in FIELDS.items():
        if k not in data: continue
        v = str(data[k]).strip().replace("\n", " ")
        if k == "unlock_seconds":
            if not v.isdigit() or not 1 <= int(v) <= 600: raise ValueError("unlock_seconds phải từ 1 đến 600")
        elif k == "name" and not v: raise ValueError("Tên khoá không được để trống")
        cfg.cp[sec][key] = v; changed[k] = v
        if cfg.found: set_conf_value(cfg.path, sec, key, v)
    with core.lk:
        core.st["name"], core.st["location"], core.st["firmware"] = cfg.s("device", "name"), cfg.s("device", "location"), cfg.s("device", "firmware")
    app.bus.log("ok", "sys", "Đã đổi thông tin khoá: " + ", ".join(f"{k}={v}" for k, v in changed.items()))
    core.send_status(); core.changed()
    return changed


def create_lock(base, name, location="", code=None):
    """Tạo locks/<CODE>/device.conf (+ faces/alice.json) = 1 khoá mới xuất xưởng. Mỗi khoá chạy cổng UI riêng."""
    base = Path(base); locks = base / "locks"; locks.mkdir(exist_ok=True)
    code = re.sub(r"[^A-Z0-9\-]", "", (code or f"LOCK-{secrets.token_hex(2).upper()}").upper())
    if len(code) < 4: raise ValueError("Mã khoá phải có ít nhất 4 ký tự A-Z, 0-9, '-'")
    d = locks / code
    if d.exists(): raise ValueError(f"Khoá {code} đã tồn tại")
    secret = secrets.token_hex(16)
    port = 8766 + len([x for x in locks.iterdir() if x.is_dir()])
    d.mkdir(); (d / "faces").mkdir()
    text = EXAMPLE.read_text(encoding="utf-8").replace("@CODE@", code).replace("@SECRET@", secret).replace("@NAME@", name or code)
    conf = d / "device.conf"; conf.write_text(text, encoding="utf-8")
    set_conf_value(conf, "device", "location", location); set_conf_value(conf, "ui", "port", str(port))
    rnd = random.Random(42)
    (d / "faces" / "alice.json").write_text(json.dumps({"name": "alice", "embedding": [round(rnd.gauss(0, 0.2), 6) for _ in range(128)]}))
    mac = "02:" + ":".join(secrets.token_hex(1).upper() for _ in range(5))     # MAC riêng cho mỗi khoá (02 = địa chỉ tự đặt)
    set_conf_value(conf, "device", "mac", mac)
    return {"code": code, "secret": secret, "port": port, "conf": str(conf), "mac": mac,
            "run": f'python -m smartlock_fw -c "{conf}" run',
            "django": ("from smartlock.models import Device\nfrom smartlock.services import hash_token\n"
                       f"Device.objects.create(device_code='{code}', provisioning_secret_hash=hash_token('{secret}'),\n"
                       f"    device_mode='simulated', name={name or code!r}, mac_address='{mac}', status='provisioning')")}


def list_locks(base):
    out = []
    for c in sorted((Path(base) / "locks").glob("*/device.conf")):
        cfg = Config(c); out.append({"code": cfg.code, "name": cfg.s("device", "name"), "port": cfg.i("ui", "port"), "conf": str(c)})
    return out
