"""Chuyển model -> dict JSON trả về cho app."""
from smartlock.api.common import iso


def user_json(u) -> dict:
    return {
        'id': str(u.id), 'email': u.email, 'username': u.username, 'full_name': u.full_name or '',
        'phone': u.phone or '', 'avatar_url': u.avatar_url or '', 'email_verified': u.email_verified,
        'two_fa_enabled': u.two_fa_enabled, 'created_at': iso(u.created_at),
    }


def device_json(d, user, perms, lock_state=None) -> dict:
    is_owner = d.owner_id == user.id
    owner = d.owner if d.owner_id else None
    return {
        'id': str(d.id), 'name': d.name, 'device_code': d.device_code, 'device_mode': d.device_mode,
        'status': d.status, 'status_display': d.get_status_display(),
        'battery_level': d.battery_level, 'lock_state': lock_state or 'unknown',
        'location': d.location or '', 'firmware_version': d.firmware_version or '',
        'mac_address': d.mac_address or '', 'last_seen_at': iso(d.last_seen_at),
        'wifi_enabled': d.wifi_enabled, 'bluetooth_enabled': d.bluetooth_enabled, 'nfc_enabled': d.nfc_enabled,
        'is_owner': is_owner,
        'owner_name': (owner.full_name or owner.username) if owner else '',
        'permissions': sorted(perms), 'updated_at': iso(d.updated_at),
    }


def command_json(c) -> dict:
    return {
        'id': str(c.id), 'device_id': str(c.device_id), 'command': c.command_type, 'status': c.status,
        'created_at': iso(c.created_at), 'expires_at': iso(c.expires_at),
        'acknowledged_at': iso(c.acknowledged_at),
    }


def event_json(e) -> dict:
    return {
        'id': str(e.id), 'device_id': str(e.device_id), 'device_name': e.device.name,
        'method': e.method, 'success': e.success, 'reason': e.reason or '',
        'who': (e.user.full_name or e.user.username) if e.user_id else '',
        'confidence': e.confidence, 'snapshot_url': e.snapshot_url or '', 'created_at': iso(e.created_at),
    }


def notification_json(n) -> dict:
    return {
        'id': str(n.id), 'type': n.type, 'title': n.title, 'message': n.message, 'severity': n.severity,
        'is_read': n.is_read, 'device_id': str(n.device_id) if n.device_id else None,
        'created_at': iso(n.created_at), 'read_at': iso(n.read_at),
    }


def session_json(m, current_id) -> dict:
    return {
        'id': str(m.id), 'device_name': m.device_name, 'platform': m.platform, 'app_version': m.app_version,
        'ip_address': m.ip_address, 'created_at': iso(m.created_at), 'last_used_at': iso(m.last_used_at),
        'expires_at': iso(m.expires_at), 'push_enabled': m.push_enabled, 'has_push_token': bool(m.fcm_token),
        'is_current': m.id == current_id,
    }


def announcement_json(a) -> dict:
    return {'id': str(a.id), 'title': a.title, 'body': a.body, 'level': a.level, 'created_at': iso(a.created_at)}
