"""Kiểm vé BLE / NFC-điện-thoại OFFLINE - khớp đúng services._ticket_sig phía server.

vé  = <user_hex>.<exp>.<sig32>
key = HMAC-SHA256( key=sha256(secret).hexdigest().encode(), msg=label )
sig = HMAC-SHA256( key, f'{device_code}|{user_hex}|{exp}' ).hexdigest()[:32]
"""
import hashlib
import hmac

LABELS = {'ble': b'ble-ticket-v1', 'nfc': b'nfc-phone-ticket-v1'}


def _sig(secret, code, kind, user_hex, exp):
    secret_hash = hashlib.sha256(secret.encode()).hexdigest()
    key = hmac.new(secret_hash.encode(), LABELS[kind], hashlib.sha256).digest()
    return hmac.new(key, f'{code}|{user_hex}|{exp}'.encode(), hashlib.sha256).hexdigest()[:32]


def verify(secret, code, kind, ticket, now):
    """-> (ok, reason_suffix). reason_suffix: INVALID_TICKET | TICKET_EXPIRED."""
    try:
        user_hex, exp_s, sig = (ticket or '').strip().split('.')
        exp = int(exp_s)
    except ValueError:
        return False, 'INVALID_TICKET'
    if not hmac.compare_digest(sig.encode(), _sig(secret, code, kind, user_hex, exp).encode()):
        return False, 'INVALID_TICKET'
    if exp < now:
        return False, 'TICKET_EXPIRED'
    return True, None


def make(secret, code, kind, user_hex, exp):      # chỉ để test
    return f'{user_hex}.{exp}.{_sig(secret, code, kind, user_hex, exp)}'
