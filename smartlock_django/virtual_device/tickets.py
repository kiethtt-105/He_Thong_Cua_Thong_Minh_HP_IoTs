# virtual_device/tickets.py
"""
Vé điện thoại (Bluetooth / NFC giả lập thẻ) - phản chiếu ĐÚNG services._ticket_sig của server:

    secret_hash = sha256(provisioning_secret).hexdigest()          # = Device.provisioning_secret_hash
    key  = HMAC_SHA256(key=secret_hash (ASCII), msg=<nhãn kênh>)
    sig  = HMAC_SHA256(key, "<device_code>|<user_hex>|<exp>").hexdigest()[:32]
    vé   = "<user_hex>.<exp>.<sig>"

Nhờ vậy khoá ảo tự kiểm tra vé OFFLINE y như khoá thật (không cần gọi server).
"""
import hashlib
import hmac
import time

LABELS = {'ble': b'ble-ticket-v1', 'nfc': b'nfc-phone-ticket-v1'}


def secret_hash(secret: str) -> str:
    return hashlib.sha256(str(secret).encode()).hexdigest()


def _sig(sec_hash: str, kind: str, device_code: str, user_hex: str, exp: int) -> str:
    key = hmac.new(sec_hash.encode(), LABELS[kind], hashlib.sha256).digest()
    return hmac.new(key, f'{device_code}|{user_hex}|{exp}'.encode(), hashlib.sha256).hexdigest()[:32]


def mint(sec_hash: str, device_code: str, kind: str, user_hex: str, ttl: int = 3600):
    """Tạo vé thử (chỉ để test trên khoá ảo; vé thật do server cấp qua /ble-ticket/ và /nfc-ticket/)."""
    exp = int(time.time()) + ttl
    return f'{user_hex}.{exp}.{_sig(sec_hash, kind, device_code, user_hex, exp)}', exp


def verify(sec_hash: str, device_code: str, kind: str, ticket: str, now: float = None):
    """Trả (ok, reason, user_hex, exp). reason ∈ {None, 'INVALID_TICKET', 'TICKET_EXPIRED'}."""
    try:
        user_hex, exp_s, sig = (ticket or '').strip().split('.')
        exp = int(exp_s)
    except ValueError:
        return False, 'INVALID_TICKET', None, None
    if not hmac.compare_digest(sig, _sig(sec_hash, kind, device_code, user_hex, exp)):
        return False, 'INVALID_TICKET', None, None
    if exp < (now if now is not None else time.time()):
        return False, 'TICKET_EXPIRED', user_hex, exp
    return True, None, user_hex, exp
