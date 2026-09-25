# smartlock/admin_audit.py
"""
Tự động ghi AuditLog cho MỌI thay đổi dữ liệu do admin thực hiện
NGOÀI phạm vi manage_sys (vd: Django admin /admin/, shell chạy qua request,
script chạy dưới danh nghĩa 1 request giả admin...).

Các action trong manage_sys/views.py đã tự gọi audit(...) thủ công với action
name + metadata rõ ràng (MANAGE_USER_ACTIVATED, MANAGE_DEVICE_MAINTENANCE_ON,
MANAGE_SUPPORT_APPROVE, ...), nên signal ở đây PHẢI bỏ qua các request có
path nằm trong MANAGE_SYS_URL_PREFIX, nếu không mỗi thao tác trong trang
quản trị sẽ bị ghi 2 lần (1 dòng MANAGE_* do view ghi + 1 dòng ADMIN_*_UPDATED
do signal ghi) vào AuditLog.

Cách hoạt động:
  - AuditRequestMiddleware giữ request hiện tại (để biết ai đang thao tác, IP, user-agent).
  - Signal pre_save/post_save/post_delete trên các model được theo dõi.
  - Chỉ ghi khi người thao tác là admin VÀ request KHÔNG thuộc manage_sys
    (đường dẫn quản trị đã tự ghi log rồi).

Lưu ý: QuerySet.update() / bulk_create() / bulk_update() KHÔNG bắn signal.
Trong view admin nếu dùng các hàm đó thì phải gọi audit(...) thủ công (đã làm
đúng ở manage_sys.helpers/views cho reset_lockout).
"""
import contextvars
import datetime
import decimal
import logging
import uuid

from django.conf import settings
from django.db.models.signals import post_delete, post_save, pre_save

logger = logging.getLogger('smartlock.audit')

_current_request = contextvars.ContextVar('smartlock_audit_request', default=None)

# Trường không cần so sánh / không được ghi giá trị ra log.
_SKIP_FIELDS = {'updated_at', 'last_login'}
_MASKED_FIELDS = {
    'password', 'provisioning_secret_hash', 'card_uid_hash', 'code_encrypted',
    'authorization_code_hash', 'recovery_code_hash', 'command_token_hash',
}
# Thay đổi các trường này được đánh dấu severity=warning.
_SENSITIVE_FIELDS = {'is_active', 'is_admin', 'is_staff', 'is_superuser', 'password',
                     'email', 'username', 'owner_id', 'status'}


class AuditRequestMiddleware:
    """Thêm 'smartlock.admin_audit.AuditRequestMiddleware' vào MIDDLEWARE (sau AuthenticationMiddleware)."""

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        token = _current_request.set(request)
        try:
            return self.get_response(request)
        finally:
            _current_request.reset(token)


# ------------------------------------------------------------------ helpers
def _manage_sys_prefix():
    return getattr(settings, 'MANAGE_SYS_URL_PREFIX', '/manage-sys/')


def _admin_request():
    request = _current_request.get()
    user = getattr(request, 'user', None)
    if not request or not user or not user.is_authenticated:
        return None
    # manage_sys/views.py đã tự ghi audit (MANAGE_*) cho mọi action của nó,
    # nên bỏ qua ở đây để không bị ghi trùng.
    if request.path_info.startswith(_manage_sys_prefix()):
        return None
    if user.is_staff or user.is_superuser or getattr(user, 'is_admin', False):
        return request
    return None


def _jsonable(value):
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    if isinstance(value, (datetime.datetime, datetime.date, datetime.time)):
        return value.isoformat()
    if isinstance(value, (uuid.UUID, decimal.Decimal)):
        return str(value)
    return str(value)[:200]


def _snapshot(obj):
    return {f.attname: getattr(obj, f.attname) for f in obj._meta.concrete_fields
            if f.attname not in _SKIP_FIELDS}


def _diff(before, after):
    changes = {}
    for key, new in after.items():
        old = before.get(key)
        if old != new:
            changes[key] = ['***', '***'] if key in _MASKED_FIELDS else [_jsonable(old), _jsonable(new)]
    return changes


def _target_user(instance):
    from .models import User
    if isinstance(instance, User):
        return instance
    for attr in ('user', 'requested_by', 'owner'):
        try:
            value = getattr(instance, attr, None)
        except Exception:
            value = None
        if isinstance(value, User):
            return value
    return None


def _device_of(instance):
    from .models import Device
    if isinstance(instance, Device):
        return instance
    try:
        return getattr(instance, 'device', None)
    except Exception:
        return None


def _write(request, instance, verb, metadata, severity='info'):
    from .models import AuditLog
    from .views import _client_ip, _user_agent  # import muộn để tránh vòng lặp import
    try:
        AuditLog.objects.create(
            actor_user=request.user,
            target_user=_target_user(instance),
            device=_device_of(instance),
            action=f'ADMIN_{instance.__class__.__name__.upper()}_{verb}'[:50],
            severity=severity, success=True,
            ip_address=_client_ip(request), user_agent=_user_agent(request),
            metadata=metadata,
        )
    except Exception:
        logger.exception('admin_audit: không ghi được log %s %s', instance.__class__.__name__, verb)


# ------------------------------------------------------------------ signal handlers
def _on_pre_save(sender, instance, **kwargs):
    instance._audit_before = None
    if not instance.pk or not _admin_request():
        return
    old = sender.objects.filter(pk=instance.pk).first()
    if old is not None:
        instance._audit_before = _snapshot(old)


def _on_post_save(sender, instance, created, **kwargs):
    request = _admin_request()
    if not request:
        return
    if created:
        _write(request, instance, 'CREATED', {'id': str(instance.pk), 'repr': str(instance)[:100]})
        return
    before = getattr(instance, '_audit_before', None)
    if before is None:
        return
    changes = _diff(before, _snapshot(instance))
    if not changes:
        return
    severity = 'warning' if _SENSITIVE_FIELDS & set(changes) else 'info'
    _write(request, instance, 'UPDATED', {'id': str(instance.pk), 'changes': changes}, severity)


def _on_post_delete(sender, instance, **kwargs):
    request = _admin_request()
    if request:
        _write(request, instance, 'DELETED',
               {'id': str(instance.pk), 'repr': str(instance)[:100]}, 'warning')


def register_signals():
    """Gọi 1 lần trong AppConfig.ready()."""
    from .models import (AccessCard, Announcement, Device, DeviceAccess, LoginLockout,
                         ShareAccessCode, SupportRequest, SystemSettings, User)
    tracked = (User, Device, DeviceAccess, AccessCard, ShareAccessCode, SupportRequest,
               Announcement, SystemSettings, LoginLockout)
    for model in tracked:
        name = model.__name__
        pre_save.connect(_on_pre_save, sender=model, dispatch_uid=f'audit_pre_{name}')
        post_save.connect(_on_post_save, sender=model, dispatch_uid=f'audit_post_{name}')
        post_delete.connect(_on_post_delete, sender=model, dispatch_uid=f'audit_del_{name}')