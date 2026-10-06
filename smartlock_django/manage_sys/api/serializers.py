# manage_sys/api/serializers.py
"""Chuyển model -> dict JSON. KHÔNG bao giờ xuất: mật khẩu, hash PIN / UID thẻ, embedding, secret gốc, ảnh."""


def iso(dt):
    return dt.isoformat() if dt else None


def role_of(user):
    if user.is_superuser:
        return 'superuser'
    return 'admin' if (user.is_admin or user.is_staff) else 'user'


def user_brief(u):
    return {'id': str(u.id), 'email': u.email, 'username': u.username, 'full_name': u.full_name}


def user_item(u, *, locked=None):
    return {**user_brief(u), 'phone': u.phone, 'role': role_of(u), 'is_active': u.is_active,
            'email_verified': u.email_verified, 'two_fa_enabled': u.two_fa_enabled,
            'is_locked': bool(locked), 'device_count': getattr(u, 'device_count', None),
            'created_at': iso(u.created_at)}


def user_full(u, *, is_locked, owned_count):
    return {**user_item(u, locked=is_locked), 'avatar_url': u.avatar_url, 'owned_devices': owned_count,
            'updated_at': iso(u.updated_at),
            'lock': {'failed_attempts': u.login_failed_attempts, 'stage': u.login_lock_stage,
                     'locked_until': iso(u.login_locked_until), 'last_failed_at': iso(u.login_last_failed_at),
                     'last_failed_ip': u.login_last_failed_ip}}


def device_item(d):
    return {'id': str(d.id), 'device_code': d.device_code, 'name': d.name, 'mode': d.device_mode,
            'status': d.status, 'owner': user_brief(d.owner) if d.owner_id else None,
            'mac_address': d.mac_address, 'firmware_version': d.firmware_version,
            'battery_level': d.battery_level, 'location': d.location, 'last_seen_at': iso(d.last_seen_at),
            'is_purchased': d.is_purchased, 'created_at': iso(d.created_at)}


def audit_item(a):
    return {'id': str(a.id), 'action': a.action, 'severity': a.severity, 'success': a.success,
            'actor': user_brief(a.actor_user) if a.actor_user_id else None,
            'target': user_brief(a.target_user) if a.target_user_id else None,
            'device': ({'id': str(a.device_id), 'device_code': a.device.device_code, 'name': a.device.name}
                       if a.device_id else None),
            'username_attempt': a.username_attempt, 'ip_address': a.ip_address,
            'user_agent': a.user_agent, 'metadata': a.metadata, 'created_at': iso(a.created_at)}


def login_attempt_item(a):
    who = a.target_user or a.actor_user
    ident = a.username_attempt or (who.email if who else None)
    return {'id': str(a.id), 'action': a.action, 'success': a.success, 'is_manage_portal': a.action.startswith('MANAGE_'),
            'identifier': ident, 'user': user_brief(who) if who else None, 'ip_address': a.ip_address,
            'user_agent': a.user_agent, 'created_at': iso(a.created_at)}


def announcement_item(a):
    return {'id': str(a.id), 'title': a.title, 'body': a.body, 'level': a.level, 'is_active': a.is_active,
            'created_by': user_brief(a.created_by) if a.created_by_id else None, 'created_at': iso(a.created_at)}


def settings_item(s):
    return {'registration_enabled': s.registration_enabled,
            'verification_token_expiry_minutes': s.verification_token_expiry_minutes,
            'share_code_expiry_minutes': s.share_code_expiry_minutes,
            'session_timeout_hours': s.session_timeout_hours,
            'login_lockout_stage_minutes': list(s.login_lockout_stage_minutes or []),
            'updated_at': iso(s.updated_at), 'updated_by': user_brief(s.updated_by) if s.updated_by_id else None}


def command_item(c):
    return {'id': str(c.id), 'command_type': c.command_type, 'status': c.status,
            'issued_by': user_brief(c.issued_by), 'created_at': iso(c.created_at),
            'acknowledged_at': iso(c.acknowledged_at)}


def access_item(x):
    return {'id': str(x.id), 'user': user_brief(x.user), 'source': x.source,
            'permissions': [p.code for p in x.permissions.all()], 'valid_from': iso(x.valid_from),
            'expires_at': iso(x.expires_at), 'created_at': iso(x.created_at)}


def reader_item(r):
    return {'id': str(r.id), 'name': r.name, 'mode': r.reader_mode, 'is_active': r.is_active,
            'auto_register_active': r.auto_register_active, 'last_seen_at': iso(r.last_seen_at),
            'created_at': iso(r.created_at)}
