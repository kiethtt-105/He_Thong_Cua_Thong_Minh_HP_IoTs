"""Serializer + helper lấy thiết bị / kiểm tra quyền dùng chung cho API app."""
from smartlock import services
from smartlock.api.common import ApiError, iso, uuid_or_404


# ======================================================================
# serializers.py - Chuyển model -> dict JSON trả về cho app.
# ======================================================================

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


# ======================================================================
# helpers.py - Hàm dùng chung: lấy khoá theo quyền (chủ / quyền được chia sẻ).
# ======================================================================

def get_device(request, device_id):
    d = (services.accessible_devices(request.user).select_related('owner')
         .filter(pk=uuid_or_404(device_id)).first())
    if not d:
        raise ApiError('DEVICE_NOT_FOUND', 'Không tìm thấy khoá.', 404)
    return d


def need_owner(request, device, action='DEVICE_ACTION'):
    if device.owner_id != request.user.id:
        services.audit(request, f'{action}_DENIED', device=device, success=False, severity='warning')
        raise ApiError('OWNER_ONLY', 'Chỉ chủ khoá mới được thực hiện thao tác này.', 403)


def _need_perm(request, device, code, action='DEVICE_ACTION'):
    if not services.has_permission(request.user, device, code):
        services.audit(request, f'{action}_DENIED', device=device, success=False, severity='warning')
        raise ApiError('FORBIDDEN', 'Bạn không có quyền thực hiện thao tác này.', 403, permission=code)


def managed_device(request, device_id, code):
    """Khoá mà user có quyền `code` (chủ luôn có). 404 nếu không thấy, 403 nếu thiếu quyền."""
    device = get_device(request, device_id)
    _need_perm(request, device, code)
    return device
