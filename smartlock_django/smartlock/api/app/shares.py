"""Chia sẻ khoá: danh mục quyền, chia sẻ / thu hồi / tự rời."""
from django.db.models import Q
from django.utils import timezone

from smartlock import services
from smartlock.api.common import api, ApiError, iso, ok, parse_iso, read_json, s, uuid_or_404
from smartlock.models import DeviceAccess, DeviceCommand, Permission

from .helpers import get_device, need_owner


def _share_json(a) -> dict:
    return {
        'id': str(a.id), 'device_id': str(a.device_id), 'device_name': a.device.name,
        'user': {'id': str(a.user_id), 'username': a.user.username, 'full_name': a.user.full_name or ''},
        'shared_by': a.created_by.full_name or a.created_by.username,
        'permissions': sorted(p.code for p in a.permissions.all()),
        'valid_from': iso(a.valid_from), 'expires_at': iso(a.expires_at), 'created_at': iso(a.created_at),
    }


def _wanted_permissions(data):
    services.ensure_default_permissions()
    preset = s(data, 'preset', 30)
    if preset:
        codes = services.preset_codes(preset)
        if codes is None:
            raise ApiError('BAD_PRESET', 'Vai trò mẫu không hợp lệ.', 400, presets=sorted(services.ROLE_PRESETS))
    else:
        raw = data.get('permissions')
        if not isinstance(raw, list):
            raise ApiError('MISSING_FIELD', 'Cần "preset" hoặc "permissions" (mảng mã quyền).', 400)
        codes = [str(c) for c in raw]
        bad = [c for c in codes if c not in services.PERMISSION_CODES]
        if bad:
            raise ApiError('BAD_PERMISSION', f'Mã quyền không hợp lệ: {", ".join(bad[:5])}', 400)
    perms = list(Permission.objects.filter(code__in=codes))
    if not perms:
        raise ApiError('NO_PERMISSION', 'Hãy chọn ít nhất một quyền để chia sẻ.', 400)
    return perms


@api('GET')
def permissions_catalog(request):
    services.ensure_default_permissions()
    ctx = services.permission_form_context()
    return ok({
        'groups': [{'key': g['key'], 'name': g['name'], 'description': g['description'],
                    'items': [{k: v for k, v in i.items() if k != 'id'} for i in g['items']]}
                   for g in ctx['permission_groups']],
        'role_presets': ctx['role_presets'],
        'owner_only_actions': ctx['owner_only_actions'],
    })


@api('GET', 'POST')
def device_shares(request, device_id):
    device = get_device(request, device_id)
    need_owner(request, device, 'ACCESS_MANAGE')
    user = request.user
    if request.method == 'POST':
        data = read_json(request)
        identifier = s(data, 'identifier', 150, required=True)
        expires = parse_iso(data.get('expires_at'))
        perms = _wanted_permissions(data)
        target = services.find_user(identifier)
        if not target or not target.is_active:
            services.audit(request, 'ACCESS_GRANT_FAILED', device=device, success=False,
                           username_attempt=identifier[:150], metadata={'reason': 'user_not_found'})
            raise ApiError('USER_NOT_FOUND', 'Không tìm thấy người dùng (email hoặc username).', 404)
        if target.id == user.id:
            raise ApiError('SELF_SHARE', 'Bạn đã là chủ thiết bị này.', 400)
        if expires and expires <= timezone.now():
            raise ApiError('BAD_DATETIME', 'Thời điểm hết hạn phải ở tương lai.', 400, field='expires_at')
        access, created = services.grant_access(device, user, target, perms, expires)
        codes = sorted(p.code for p in perms)
        services.audit(request, 'ACCESS_GRANTED' if created else 'ACCESS_UPDATED', device=device, target_user=target,
                       metadata={'access_id': str(access.id), 'permissions': codes,
                                 'expires_at': expires.isoformat() if expires else None, 'channel': 'mobile'})
        emailed = services.notify_access_shared(request, access, created)
        access = (DeviceAccess.objects.select_related('device', 'user', 'created_by')
                  .prefetch_related('permissions').get(pk=access.pk))
        return ok({'share': _share_json(access), 'created': created, 'emailed': emailed}, 201 if created else 200)
    qs = (DeviceAccess.objects.filter(device=device, is_active=True)
          .select_related('device', 'user', 'created_by').prefetch_related('permissions').order_by('-created_at'))
    return ok({'shares': [_share_json(a) for a in qs]})


@api('GET')
def shares_incoming(request):
    now = timezone.now()
    qs = (DeviceAccess.objects.filter(user=request.user, is_active=True)
          .filter(Q(expires_at__isnull=True) | Q(expires_at__gt=now))
          .select_related('device', 'user', 'created_by').prefetch_related('permissions').order_by('-created_at'))
    return ok({'shares': [_share_json(a) for a in qs]})


@api('PATCH', 'DELETE')
def share_detail(request, share_id):
    access = (DeviceAccess.objects.select_related('device', 'user', 'created_by')
              .filter(pk=uuid_or_404(share_id), is_active=True).first())
    if not access or access.device.owner_id != request.user.id:
        raise ApiError('NOT_FOUND', 'Không tìm thấy quyền truy cập.', 404)
    device = access.device
    if request.method == 'PATCH':
        perms = _wanted_permissions(read_json(request))
        old = sorted(p.code for p in access.permissions.all())
        access.permissions.set(perms)
        services.audit(request, 'ACCESS_UPDATED', device=device, target_user=access.user,
                       metadata={'access_id': str(access.id), 'from': old, 'to': sorted(p.code for p in perms)})
        services.notify_access_shared(request, access, created=False)
        access = (DeviceAccess.objects.select_related('device', 'user', 'created_by')
                  .prefetch_related('permissions').get(pk=access.pk))
        return ok({'share': _share_json(access)})
    access.is_active = False
    access.revoked_at = timezone.now()
    access.save(update_fields=['is_active', 'revoked_at'])
    cancelled = DeviceCommand.objects.filter(device=device, issued_by=access.user, status='pending').update(status='failed')
    services.audit(request, 'ACCESS_REVOKED', device=device, target_user=access.user, severity='warning',
                   metadata={'access_id': str(access.id), 'cancelled_commands': cancelled})
    services.notify(access.user, 'Quyền truy cập bị thu hồi', f'Quyền của bạn trên "{device.name}" đã bị thu hồi.',
                    severity='warning', device=device, type_='SHARE')
    return ok()


@api('POST')
def share_leave(request, share_id):
    access = (DeviceAccess.objects.select_related('device', 'device__owner')
              .filter(pk=uuid_or_404(share_id), user=request.user, is_active=True).first())
    if not access:
        raise ApiError('NOT_FOUND', 'Không tìm thấy quyền truy cập.', 404)
    access.is_active = False
    access.revoked_at = timezone.now()
    access.save(update_fields=['is_active', 'revoked_at'])
    services.audit(request, 'ACCESS_LEFT', device=access.device, target_user=access.device.owner,
                   metadata={'access_id': str(access.id)})
    if access.device.owner_id:
        services.notify(access.device.owner, 'Người dùng đã rời khỏi khoá được chia sẻ',
                        f'{request.user.username} không còn dùng khoá "{access.device.name}" nữa.',
                        device=access.device, type_='SHARE')
    return ok()
