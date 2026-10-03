"""
GIAO THỨC giữa khoá và máy chủ - MỌI thứ liên quan tới định dạng gói tin nằm trong file này.

Nguồn: smartlock/services.py + views.py (topic, lệnh, vé BLE/NFC, hash secret).
Phần máy chủ -> khoá (topic cmd, payload lệnh, thuật toán vé) lấy NGUYÊN VĂN từ services.py.
Phần khoá -> máy chủ (status / event / ack): services.py chỉ cho biết tên topic và các hàm xử lý
(verify_rfid_tap, verify_door_pin, verify_face, record_ble_unlock, record_nfc_phone_unlock,
touch_device) chứ không kèm file subscriber, nên tên trường bên dưới là quy ước hợp lý nhất.
Nếu subscriber của bạn đặt tên khác, chỉ cần sửa 3 hàm build_* ở cuối file này.
"""
import hashlib
import hmac
import json
import re
import time

# ------------------------------------------------------------------ topic
def topic_cmd(code):    return f"smartlock/{code}/cmd"
def topic_status(code): return f"smartlock/{code}/status"
def topic_event(code):  return f"smartlock/{code}/event"
def topic_ack(code):    return f"smartlock/{code}/ack"

# ------------------------------------------------------------------ hash / uid
def hash_token(token) -> str:
    """Giống services.hash_token. Server lưu Device.provisioning_secret_hash = hash_token(secret)."""
    return hashlib.sha256(str(token).encode()).hexdigest()


def normalize_uid(raw) -> str:
    """Giống services.normalize_uid."""
    return re.sub(r"[\s:\-]", "", raw or "").upper()


# ------------------------------------------------------------------ vé điện thoại (BLE / NFC-HCE)
# key = HMAC_SHA256(key=<provisioning_secret_hash ASCII>, msg=<nhãn kênh>)
# sig = HMAC_SHA256(key, "<device_code>|<user_hex>|<exp>") -> hex, 32 ký tự đầu
# vé  = "<user_hex>.<exp>.<sig>"
CHANNEL_LABEL = {"ble": b"ble-ticket-v1", "nfc": b"nfc-phone-ticket-v1"}


def _sig(code, secret, kind, user_hex, exp):
    key = hmac.new(hash_token(secret).encode(), CHANNEL_LABEL[kind], hashlib.sha256).digest()
    return hmac.new(key, f"{code}|{user_hex}|{exp}".encode(), hashlib.sha256).hexdigest()[:32]


def mint_ticket(code, secret, kind, user_id, ttl=3600, now=None):
    """Tự cấp vé (chỉ để TEST: khoá có secret nên ký được). Server vẫn kiểm user_id có thật + quyền."""
    user_hex = str(user_id).replace("-", "").lower()
    exp = int(now or time.time()) + int(ttl)
    return f"{user_hex}.{exp}.{_sig(code, secret, kind, user_hex, exp)}", exp


def verify_ticket(code, secret, kind, ticket, now=None):
    """Khoá TỰ kiểm tra vé, không cần mạng. Trả (ok, reason, user_hex, exp)."""
    try:
        user_hex, exp_s, sig = (ticket or "").strip().split(".")
        exp = int(exp_s)
    except (ValueError, TypeError):
        return False, "INVALID_TICKET", None, None
    expect = _sig(code, secret, kind, user_hex, exp)
    if not hmac.compare_digest(sig.encode(), expect.encode()):
        return False, "INVALID_TICKET", None, None
    if exp < (now or time.time()):
        return False, "TICKET_EXPIRED", user_hex, exp
    return True, None, user_hex, exp


# ------------------------------------------------------------------ gói khoá -> máy chủ
def build_status(s: dict) -> dict:
    """Gói trạng thái định kỳ. Đặt thừa tên đồng nghĩa để khớp nhiều kiểu subscriber
    (DeviceStatusLog: battery_level, signal_strength, lock_state, tamper_detected, temperature;
    touch_device: firmware, battery)."""
    return {
        "lock_state": s["lock_state"],
        "battery": s["battery"], "battery_level": s["battery"],
        "signal_strength": s.get("rssi"), "rssi": s.get("rssi"),
        "tamper_detected": s["tamper"], "tamper": s["tamper"],
        "temperature": s.get("temperature"),
        "firmware": s["firmware"], "firmware_version": s["firmware"],
        "mac": s["mac"], "mac_address": s["mac"],
        "uptime": s.get("uptime", 0),
        "radios": {"wifi": s["wifi"]["enabled"], "bluetooth": s["bluetooth"]["enabled"],
                   "nfc": s["nfc"]["enabled"]},
        "ts": int(time.time()),
    }


def build_event(kind: str, **data) -> dict:
    """Gói sự kiện. kind: rfid | pin | face | ble_unlock | nfc_phone_unlock | tamper | door | boot
    - rfid: {uid}            -> services.verify_rfid_tap(device, uid)
    - pin:  {pin}            -> services.verify_door_pin(device, pin)
    - face: {embedding, snapshot_url} -> services.verify_face(...)
    - ble_unlock / nfc_phone_unlock: {ticket, ok, reason, at} -> record_ble_unlock / record_nfc_phone_unlock
    """
    return {"type": kind, "event": kind, **data, "ts": int(time.time())}


def build_ack(command_id, token, ok=True, state=None, error=None) -> dict:
    """Thiết bị gửi lại ĐÚNG token của lệnh (xem dispatch_command)."""
    out = {"command_id": command_id, "token": token,
           "status": "acknowledged" if ok else "failed", "ok": bool(ok)}
    if state: out["lock_state"] = state
    if error: out["error"] = error
    return out


def dumps(obj) -> str:
    return json.dumps(obj, ensure_ascii=False, separators=(",", ":"))
