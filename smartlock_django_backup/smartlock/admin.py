# smartlock/admin.py
"""
Django admin (/admin/) - phân quyền theo VAI TRÒ, đồng bộ với /manage-sys/ (cùng cờ settings.ADMIN_FULL_POWER).

  ADMIN_FULL_POWER=True (mặc định): MỌI tài khoản quản trị (is_admin, hoặc Superuser có is_staff) đều có
               QUYỀN CAO NHẤT như Superuser: xem + thêm + sửa + xoá gần như mọi thứ, đổi cài đặt hệ thống,
               cấp/thu hồi admin, sửa cả tài khoản Superuser khác. Admin KHÔNG cần is_staff để vào /admin/.
  ADMIN_FULL_POWER=False: chính sách cũ - Admin chỉ xem + vận hành, Superuser mới có quyền cao nhất.
  Khác       : không thấy gì ở /admin/ (kể cả nếu có is_staff).

Những chỗ LUÔN giữ cho Superuser thật (kể cả khi ADMIN_FULL_POWER=True), vì Django admin không hỏi lại được mật khẩu:
  - Bật/tắt cờ is_superuser và đổi mật khẩu của người khác (chiếm tài khoản).
  - Không ai tự đổi quyền của chính mình, không hạ Superuser cuối cùng, không để tài khoản quản trị làm chủ khoá.
  - Log chỉ-xoá-không-sửa, dữ liệu sinh trắc/hash không bao giờ hiện.

Mọi thao tác thêm/sửa/xoá đều ghi AuditLog (ADMIN_<MODEL>_*). Thao tác nhạy cảm ghi strict: không ghi được
log => thao tác bị huỷ (changeform của Django admin nằm trong transaction).

Việc cần NHẬP LẠI MẬT KHẨU + gõ mã thiết bị (gán chủ khoá, gỡ chủ, xoay secret) vẫn nằm ở /manage-sys/
vì admin action của Django không hỏi được mật khẩu.
"""
import re
import secrets

from django import forms
from django.conf import settings
from django.contrib import admin, messages
from django.contrib.admin.models import LogEntry
from django.contrib.auth.admin import UserAdmin
from django.contrib.auth.forms import UserChangeForm, UserCreationForm
from django.core.exceptions import PermissionDenied, ValidationError
from django.utils import timezone

from . import services
from .models import (
    AccessCard, AccessEvent, Announcement, AuditLog, CardDeviceAccess, Device, DeviceAccess,
    DeviceCommand, DeviceStatusLog, DoorPinCode, FaceProfile, Fido2Credential, MobileSession,
    NfcLog, NfcReader, Notification, OneTimeCode, Permission, SystemSettings, TwoFactorConfig, User,
)

admin.site.site_header = 'Smart Lock - Quản trị'
admin.site.site_title = 'Smart Lock'

# ================================================================ VAI TRÒ + CHÍNH SÁCH
V, A, C, D = 'view', 'add', 'change', 'delete'
FULL = frozenset({V, A, C, D})
VIEW = frozenset({V})
VIEW_DELETE = frozenset({V, D})          # log: không ai sửa/thêm; Superuser được xoá (lưu trữ) và việc xoá cũng bị ghi log


def _full_power() -> bool:
    return bool(getattr(settings, 'ADMIN_FULL_POWER', True))


def _role(request):
    """'super' | 'admin' | None.
    Superuser: is_active + is_staff + is_superuser. Admin (is_admin): ADMIN_FULL_POWER=True -> vai trò 'super'
    (quyền cao nhất, không cần is_staff); False -> vai trò 'admin' (cần is_staff, chỉ xem + vận hành)."""
    u = request.user
    if not getattr(u, 'is_active', False):
        return None
    is_staff = getattr(u, 'is_staff', False)
    if u.is_superuser and is_staff:
        return 'super'
    if getattr(u, 'is_admin', False):
        if _full_power():
            return 'super'
        return 'admin' if is_staff else None
    return None


def _is_real_superuser(request) -> bool:
    """Superuser thật (cờ is_superuser) - dùng cho việc không thể xác nhận lại mật khẩu ở Django admin."""
    u = request.user
    return bool(getattr(u, 'is_active', False) and getattr(u, 'is_staff', False) and u.is_superuser)


class RoleAdminMixin:
    """Quyền theo bảng `policy` = {'super': {...}, 'admin': {...}}. Không có vai trò => không có quyền gì
    (KHÔNG rơi về quyền Django mặc định, để Superuser không bị "chỉ-xem" như trước và staff thường không lách được)."""
    policy = {'super': FULL, 'admin': VIEW}

    def _can(self, request, op):
        role = _role(request)
        return bool(role) and op in self.policy.get(role, ())

    def has_module_permission(self, request):
        role = _role(request)
        return bool(role) and bool(self.policy.get(role))

    def has_view_permission(self, request, obj=None):
        return self._can(request, V) or self._can(request, C)

    def has_add_permission(self, request):
        return self._can(request, A)

    def has_change_permission(self, request, obj=None):
        return self._can(request, C)

    def has_delete_permission(self, request, obj=None):
        return self._can(request, D)

    # Dùng cho @admin.action(permissions=['operate']): thao tác vận hành (thu hồi, ping...) cho cả 2 vai trò.
    def has_operate_permission(self, request):
        return _role(request) is not None


# ================================================================ GHI AUDITLOG
BULK_AUDIT_LIMIT = 200


class AuditedAdminMixin(RoleAdminMixin):
    """Ghi AuditLog (ADMIN_<MODEL>_ADDED/CHANGED/DELETED) cho mọi thao tác. Với sửa: chỉ ghi TÊN trường đổi
    (không ghi giá trị để khỏi lộ dữ liệu nhạy cảm); riêng cờ quyền của User ghi thêm giá trị cũ->mới ở bên dưới."""

    def _log(self, request, verb, obj, severity='warning', extra=None, strict=False):
        model = obj._meta.model_name.upper()
        meta = {'model': obj._meta.label, 'object_id': str(obj.pk), 'object': str(obj)[:120],
                'via': 'django_admin', **(extra or {})}
        target = obj if isinstance(obj, User) else getattr(obj, 'user', None)
        device = obj if isinstance(obj, Device) else getattr(obj, 'device', None)
        services.audit(request, f'ADMIN_{model}_{verb}'[:50],
                       device=device if isinstance(device, Device) else None,
                       target_user=target if isinstance(target, User) else None,
                       severity=severity, metadata=meta, strict=strict)

    def save_model(self, request, obj, form, change):
        super().save_model(request, obj, form, change)
        if change:
            self._log(request, 'CHANGED', obj, extra={'fields': sorted(form.changed_data)})
        else:
            self._log(request, 'ADDED', obj)

    def delete_model(self, request, obj):
        self._log(request, 'DELETED', obj, severity='critical', strict=True)   # ghi TRƯỚC khi xoá để còn thông tin
        super().delete_model(request, obj)

    def delete_queryset(self, request, queryset):
        objs = list(queryset[:BULK_AUDIT_LIMIT + 1])
        if len(objs) <= BULK_AUDIT_LIMIT:
            for obj in objs:
                self._log(request, 'DELETED', obj, severity='critical', extra={'bulk': True}, strict=True)
        else:   # xoá hàng loạt lớn (vd. dọn log cũ): ghi 1 dòng tổng kết thay vì hàng nghìn dòng
            services.audit(request, f'ADMIN_{self.model._meta.model_name.upper()}_BULKDEL'[:50],
                           severity='critical', strict=True,
                           metadata={'model': self.model._meta.label, 'count': queryset.count(),
                                     'via': 'django_admin'})
        super().delete_queryset(request, queryset)


# ================================================================ NHÓM CỘT NHẠY CẢM: KHÔNG BAO GIỜ HIỆN / SỬA
_EXTRA_SECRET_FIELDS = {'snapshot_url', 'fcm_token', 'public_key'}


def _secret_fields(model):
    """Mọi cột hash/mã hoá (token, PIN, UID thẻ, secret thiết bị, embedding khuôn mặt, TOTP...) + ảnh chụp + token push."""
    return [f.name for f in model._meta.fields
            if f.name.endswith(('_hash', '_encrypted')) or f.name in _EXTRA_SECRET_FIELDS]


class BaseModelAdmin(AuditedAdminMixin, admin.ModelAdmin):
    list_per_page = 50
    show_full_result_count = False    # tránh COUNT(*) toàn bảng ở mỗi lần mở danh sách (bảng log lớn + DB ở xa = chậm)

    def get_exclude(self, request, obj=None):
        return _secret_fields(self.model)


# ================================================================ USER
FLAGS = ('is_active', 'is_staff', 'is_superuser', 'is_admin')


def _is_last_superuser(user) -> bool:
    return bool(user.is_superuser and user.is_active
                and not User.objects.filter(is_superuser=True, is_active=True).exclude(pk=user.pk).exists())


def _revoke_mobile_sessions(user) -> int:
    n = 0
    for s in MobileSession.objects.filter(user=user, revoked_at__isnull=True):
        s.revoke()
        n += 1
    return n


def _privilege_errors(actor, target, cleaned) -> list:
    """Các chốt chặn khi đổi cờ quyền / kích hoạt (kể cả Superuser)."""
    new = {f: cleaned.get(f, getattr(target, f)) for f in FLAGS}
    errors = []
    if new['is_superuser'] != target.is_superuser and not actor.is_superuser:
        errors.append('Chỉ Superuser mới được bật/tắt cờ Superuser (Django admin không xác nhận lại mật khẩu được).')
    if target.pk == actor.pk and any(new[f] != getattr(target, f) for f in FLAGS):
        errors.append('Không thể tự đổi quyền / trạng thái của chính mình (tránh tự khoá hoặc tự nâng quyền).')
    if target.is_superuser and (not new['is_superuser'] or not new['is_active']) and _is_last_superuser(target):
        errors.append('Không thể hạ quyền hoặc vô hiệu hoá Superuser cuối cùng của hệ thống.')
    if new['is_superuser'] and not new['is_staff']:
        errors.append('Superuser bắt buộc phải có is_staff (nếu không sẽ không vào được trang quản trị).')
    gaining = any(new[f] and not getattr(target, f) for f in ('is_staff', 'is_superuser', 'is_admin'))
    if gaining:
        owned = Device.objects.filter(owner=target).count()
        if owned:
            errors.append(f'Tài khoản đang là chủ của {owned} khoá. Tài khoản quản trị không được làm chủ khoá: '
                          'hãy gỡ chủ các khoá đó ở /manage-sys/ trước.')
        if not new['is_active']:
            errors.append('Hãy kích hoạt tài khoản trước khi cấp quyền quản trị.')
    return errors


class UserCreateForm(UserCreationForm):
    class Meta(UserCreationForm.Meta):
        model = User
        fields = ('email', 'username')


class UserEditForm(UserChangeForm):
    class Meta(UserChangeForm.Meta):
        model = User
        fields = '__all__'


@admin.register(User)
class CustomUserAdmin(AuditedAdminMixin, UserAdmin):
    policy = {'super': FULL, 'admin': frozenset({V, C})}
    form = UserEditForm
    add_form = UserCreateForm
    ordering = ('email',)
    list_display = ('email', 'username', 'is_active', 'is_admin', 'is_superuser', 'two_fa_enabled', 'last_login')
    list_filter = ('is_active', 'is_admin', 'is_superuser', 'email_verified', 'two_fa_enabled')
    search_fields = ('email', 'username', 'full_name')
    list_per_page = 50
    show_full_result_count = False

    fieldsets = (
        (None, {'fields': ('email', 'username', 'password')}),
        ('Thông tin cá nhân', {'fields': ('full_name', 'phone', 'avatar_url')}),
        ('Quyền', {'fields': ('is_active', 'email_verified', 'is_staff', 'is_superuser', 'is_admin',
                              'groups', 'user_permissions')}),
        ('Khoá đăng nhập tạm', {'fields': ('login_failed_attempts', 'login_lock_stage', 'login_locked_until')}),
        ('Mốc thời gian', {'fields': ('last_login',)}),
    )
    add_fieldsets = (
        (None, {'classes': ('wide',), 'fields': ('email', 'username', 'password1', 'password2')}),
    )
    # Admin thường chỉ sửa được các trường này (và chỉ trên user thường).
    _ADMIN_EDITABLE = {'full_name', 'phone', 'is_active'}

    def get_readonly_fields(self, request, obj=None):
        if obj is None:
            return ()
        if _role(request) == 'super':
            # Tự sửa mình: khoá cờ quyền/kích hoạt để không tự khoá tài khoản.
            if obj.pk == request.user.pk:
                return FLAGS + ('last_login',)
            # Cờ is_superuser chỉ Superuser thật được đổi (xem _privilege_errors).
            return ('last_login',) if _is_real_superuser(request) else ('last_login', 'is_superuser')
        every = {f for _, opts in self.fieldsets for f in opts['fields']}
        return tuple(sorted(every - self._ADMIN_EDITABLE - {'password'}))

    def has_change_permission(self, request, obj=None):
        if not super().has_change_permission(request, obj):
            return False
        # Admin thường không sửa Superuser và không sửa chính mình (xem thông tin thì được).
        if obj is not None and _role(request) == 'admin' and (obj.is_superuser or obj.pk == request.user.pk):
            return False
        return True

    def has_delete_permission(self, request, obj=None):
        if not super().has_delete_permission(request, obj):
            return False
        if obj is None:
            return True
        # Không xoá chính mình / Superuser cuối. User đang là chủ khoá bị RESTRICT chặn ở tầng DB (Django báo rõ).
        return obj.pk != request.user.pk and not _is_last_superuser(obj)

    def get_actions(self, request):
        actions = super().get_actions(request)
        actions.pop('delete_selected', None)   # xoá user chỉ từng người một (có kiểm tra ở trên)
        return actions

    def get_form(self, request, obj=None, **kwargs):
        base = super().get_form(request, obj, **kwargs)
        if obj is None:
            return base

        class GuardedForm(base):
            def clean(self_form):
                cleaned = super().clean()
                errors = _privilege_errors(request.user, obj, cleaned)
                if errors:
                    raise ValidationError(errors)
                return cleaned
        return GuardedForm

    def save_model(self, request, obj, form, change):
        old = None
        if change:
            old = User.objects.filter(pk=obj.pk).values(*FLAGS).first()
        else:
            # User tạo từ admin: chuẩn hoá giống UserManager.create_user và kích hoạt sẵn (đã được quản trị tin cậy).
            obj.username = (obj.username or '').strip().lower()
            obj.email = User.objects.normalize_email(obj.email)
            obj.is_active = True
            obj.email_verified = True
        super().save_model(request, obj, form, change)

        diff = {f: [old[f], getattr(obj, f)] for f in FLAGS if old and old[f] != getattr(obj, f)}
        if diff:
            revoked = 0
            if diff.get('is_active') == [True, False] or any(f in diff for f in ('is_staff', 'is_superuser', 'is_admin')):
                revoked = _revoke_mobile_sessions(obj)
            self._log(request, 'PRIVILEGE_CHANGED', obj, severity='critical', strict=True,
                      extra={'changes': diff, 'mobile_sessions_revoked': revoked})
            services.notify(obj, 'Quyền tài khoản đã thay đổi',
                            'Quản trị viên vừa thay đổi quyền / trạng thái tài khoản của bạn. '
                            'Nếu bạn không biết việc này, hãy liên hệ quản trị ngay.',
                            severity='warning', type_='SECURITY')

    def user_change_password(self, request, id, form_url=''):
        if not _is_real_superuser(request):
            raise PermissionDenied   # đổi mật khẩu người khác = chiếm tài khoản: chỉ Superuser thật
        response = super().user_change_password(request, id, form_url)
        if request.method == 'POST' and response.status_code == 302:
            target = User.objects.filter(pk=id).first()
            services.audit(request, 'ADMIN_USER_PASSWORD_CHANGED', target_user=target, severity='critical',
                           metadata={'via': 'django_admin'})
        return response

    @admin.action(description='Mở khoá đăng nhập (xoá bộ đếm sai)', permissions=['operate'])
    def action_unlock(self, request, queryset):
        n = 0
        for u in queryset.filter(is_superuser=False)[:100]:
            services.reset_lockout(u)
            self._log(request, 'UNLOCKED', u, severity='info')
            n += 1
        self.message_user(request, f'Đã mở khoá {n} tài khoản.')

    actions = ['action_unlock']


# ================================================================ SYSTEM SETTINGS (singleton)
class SystemSettingsForm(forms.ModelForm):
    class Meta:
        model = SystemSettings
        fields = ('registration_enabled', 'verification_token_expiry_minutes', 'share_code_expiry_minutes',
                  'login_lockout_stage_minutes', 'session_timeout_hours')

    def _range(self, name, lo, hi):
        v = self.cleaned_data.get(name)
        if v is not None and not (lo <= v <= hi):
            raise ValidationError(f'Giá trị phải từ {lo} đến {hi}.')
        return v

    def clean_verification_token_expiry_minutes(self):
        return self._range('verification_token_expiry_minutes', 1, 10080)

    def clean_share_code_expiry_minutes(self):
        return self._range('share_code_expiry_minutes', 1, 1440)

    def clean_session_timeout_hours(self):
        return self._range('session_timeout_hours', 1, 720)

    def clean_login_lockout_stage_minutes(self):
        v = self.cleaned_data.get('login_lockout_stage_minutes')
        ok = isinstance(v, list) and 1 <= len(v) <= 10 and all(
            isinstance(x, int) and not isinstance(x, bool) and 1 <= x <= 10080 for x in v)
        if not ok:
            raise ValidationError('Nhập danh sách 1-10 số phút (nguyên, 1-10080), vd. [5, 10, 30].')
        return v


@admin.register(SystemSettings)
class SystemSettingsAdmin(BaseModelAdmin):
    policy = {'super': frozenset({V, C}), 'admin': VIEW}
    form = SystemSettingsForm
    list_display = ('id', 'registration_enabled', 'session_timeout_hours', 'updated_at', 'updated_by')
    list_select_related = ('updated_by',)

    def save_model(self, request, obj, form, change):
        obj.updated_by = request.user
        super().save_model(request, obj, form, change)


# ================================================================ DEVICE
_DEVICE_CODE_RE = re.compile(r'^[A-Z0-9][A-Z0-9_-]{2,49}$')


class DeviceCreateForm(forms.ModelForm):
    """Admin tạo khoá MỚI. Mã tự sinh nếu để trống; secret sinh tự động và chỉ hiện MỘT lần sau khi lưu."""
    class Meta:
        model = Device
        fields = ('name', 'device_code', 'device_mode', 'mac_address', 'location')

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields['device_code'].required = False
        self.fields['device_code'].help_text = 'Để trống để tự sinh (DEV-XXXXXXXX). 3-50 ký tự A-Z, 0-9, _ hoặc -.'

    def clean_device_code(self):
        code = (self.cleaned_data.get('device_code') or '').strip().upper()
        if not code:
            code = f'DEV-{secrets.token_hex(4).upper()}'
            while Device.objects.filter(device_code=code).exists():
                code = f'DEV-{secrets.token_hex(4).upper()}'
        if not _DEVICE_CODE_RE.match(code):
            raise ValidationError('Mã thiết bị 3-50 ký tự (A-Z, 0-9, _ hoặc -).')
        if Device.objects.filter(device_code=code).exists():
            raise ValidationError('Mã thiết bị đã tồn tại.')
        return code

    def clean_mac_address(self):
        mac = (self.cleaned_data.get('mac_address') or '').strip().upper().replace('-', ':')
        return mac or None


@admin.register(Device)
class DeviceAdmin(BaseModelAdmin):
    policy = {'super': FULL, 'admin': frozenset({V, A, C})}      # CHỈ quản trị mới tạo được khoá mới
    list_display = ('name', 'device_code', 'owner', 'status', 'device_mode', 'battery_level', 'last_seen_at')
    list_filter = ('status', 'device_mode', 'is_purchased')
    search_fields = ('name', 'device_code', 'mac_address', 'owner__email', 'owner__username')
    list_select_related = ('owner',)

    def get_fields(self, request, obj=None):
        if obj is None:
            return ['name', 'device_code', 'device_mode', 'mac_address', 'location']
        return ['name', 'device_code', 'device_mode', 'mac_address', 'firmware_version', 'location', 'owner',
                'status', 'battery_level', 'is_purchased', 'purchased_at', 'last_seen_at',
                'bluetooth_enabled', 'wifi_enabled', 'nfc_enabled']

    def get_readonly_fields(self, request, obj=None):
        # Gán/gỡ chủ + xoay secret đi qua /manage-sys/ (nhập lại mật khẩu, kiểm tra kết nối, audit strict).
        ro = ['device_code', 'owner', 'status', 'battery_level', 'is_purchased', 'purchased_at', 'last_seen_at']
        if obj is not None and obj.owner_id:
            ro.append('device_mode')
        return ro

    def get_form(self, request, obj=None, **kwargs):
        if obj is None:
            kwargs['form'] = DeviceCreateForm
        return super().get_form(request, obj, **kwargs)

    def has_delete_permission(self, request, obj=None):
        if not super().has_delete_permission(request, obj):
            return False
        return obj is None or not obj.owner_id      # khoá còn chủ: phải gỡ chủ trước (mất thẻ/PIN/khuôn mặt của chủ)

    def get_actions(self, request):
        actions = super().get_actions(request)
        actions.pop('delete_selected', None)        # xoá từng khoá (có kiểm tra chủ ở trên), không xoá hàng loạt
        return actions

    def save_model(self, request, obj, form, change):
        if change:
            return super().save_model(request, obj, form, change)
        secret = secrets.token_urlsafe(24)
        obj.owner = None
        obj.status = 'provisioning'
        obj.provisioning_secret_hash = services.hash_token(secret)    # cùng kiểu hash với MQTT webhook / BLE
        super().save_model(request, obj, form, change)
        messages.warning(
            request, f'Khoá {obj.device_code} đã tạo. Provisioning secret: {secret} '
                     '(CHỈ HIỂN THỊ MỘT LẦN, hãy nạp vào khoá và lưu lại ngay). '
                     'Gán chủ ở /manage-sys/ sau khi khoá kết nối.')

    @admin.action(description='Gửi PING kiểm tra kết nối', permissions=['operate'])
    def action_ping(self, request, queryset):
        sent = 0
        for device in queryset[:20]:
            cmd = services.ping_device(device, issued_by=request.user)
            sent += cmd.status == 'sent'
        services.audit(request, 'ADMIN_DEVICE_PING', severity='info',
                       metadata={'count': min(queryset.count(), 20), 'sent': sent, 'via': 'django_admin'})
        self.message_user(request, f'Đã gửi PING {sent} khoá (thiết bị phải ack, xem trạng thái ở danh sách lệnh).')

    actions = ['action_ping']


@admin.register(DeviceCommand)
class DeviceCommandAdmin(BaseModelAdmin):
    policy = {'super': VIEW_DELETE, 'admin': VIEW}
    list_display = ('created_at', 'device', 'command_type', 'status', 'issued_by')
    list_filter = ('command_type', 'status')
    search_fields = ('device__name', 'device__device_code')
    list_select_related = ('device', 'issued_by')
    date_hierarchy = None


@admin.register(DeviceStatusLog)
class DeviceStatusLogAdmin(BaseModelAdmin):
    policy = {'super': VIEW_DELETE, 'admin': VIEW}
    list_display = ('recorded_at', 'device', 'lock_state', 'battery_level', 'tamper_detected')
    list_filter = ('lock_state', 'tamper_detected')
    list_select_related = ('device',)


# ================================================================ QUYỀN / CHIA SẺ
@admin.register(Permission)
class PermissionAdmin(BaseModelAdmin):
    policy = {'super': frozenset({V, C}), 'admin': VIEW}      # mã quyền gắn với code: không thêm/xoá tay
    list_display = ('code', 'name', 'is_sensitive')

    def get_readonly_fields(self, request, obj=None):
        return ('code',) if obj else ()


class DeviceAccessForm(forms.ModelForm):
    class Meta:
        model = DeviceAccess
        fields = ('device', 'user', 'permissions', 'valid_from', 'expires_at', 'is_active')

    def clean(self):
        c = super().clean()
        device, user = c.get('device'), c.get('user')
        if user and services.is_admin(user):
            raise ValidationError('Tài khoản quản trị không được cấp quyền mở khoá (admin không làm chủ/khách khoá).')
        if device and not device.owner_id:
            raise ValidationError('Khoá chưa có chủ: chưa thể chia sẻ.')
        if device and user and device.owner_id == user.id:
            raise ValidationError('Người này là chủ khoá, đã có đủ quyền.')
        vf, ex = c.get('valid_from'), c.get('expires_at')
        if vf and ex and ex <= vf:
            raise ValidationError('Thời điểm hết hạn phải sau thời điểm bắt đầu.')
        if device and user and c.get('is_active'):
            dup = DeviceAccess.objects.filter(device=device, user=user, is_active=True)
            if self.instance.pk:
                dup = dup.exclude(pk=self.instance.pk)
            if dup.exists():
                raise ValidationError('Người này đã có quyền đang hiệu lực trên khoá này (hãy sửa bản ghi đó).')
        return c


@admin.register(DeviceAccess)
class DeviceAccessAdmin(BaseModelAdmin):
    policy = {'super': FULL, 'admin': VIEW}
    form = DeviceAccessForm
    list_display = ('device', 'user', 'is_active', 'expires_at', 'created_by', 'created_at')
    list_filter = ('is_active', 'source')
    search_fields = ('device__name', 'device__device_code', 'user__email', 'user__username')
    list_select_related = ('device', 'user', 'created_by')
    autocomplete_fields = ('device', 'user')
    filter_horizontal = ('permissions',)

    def save_model(self, request, obj, form, change):
        if not change:
            obj.created_by = request.user
            obj.accepted = True
            obj.source = 'DIRECT'
        obj.revoked_at = None if obj.is_active else (obj.revoked_at or timezone.now())
        super().save_model(request, obj, form, change)

    def save_related(self, request, form, formsets, change):
        super().save_related(request, form, formsets, change)      # M2M permissions lưu ở đây
        if form.instance.is_active:
            try:
                services.notify_access_shared(request, form.instance, created=not change)
            except Exception:
                pass


# ================================================================ NFC / THẺ / PIN / KHUÔN MẶT
@admin.register(NfcReader)
class NfcReaderAdmin(BaseModelAdmin):
    policy = {'super': FULL, 'admin': VIEW}
    list_display = ('device', 'name', 'reader_mode', 'is_active', 'auto_register', 'last_seen_at')
    list_filter = ('is_active', 'reader_mode', 'auto_register')
    list_select_related = ('device',)
    autocomplete_fields = ('device',)


@admin.register(AccessCard)
class AccessCardAdmin(BaseModelAdmin):
    policy = {'super': frozenset({V, C, D}), 'admin': VIEW}   # thêm thẻ phải quẹt thật (cần UID) nên không thêm tay
    list_display = ('name', 'user', 'is_active', 'created_at')
    list_filter = ('is_active',)
    search_fields = ('name', 'user__email')
    list_select_related = ('user',)

    def get_readonly_fields(self, request, obj=None):
        return ('user', 'created_at', 'updated_at') if obj else ()

    @admin.action(description='Vô hiệu hoá thẻ', permissions=['operate'])
    def action_deactivate(self, request, queryset):
        n = 0
        for card in queryset[:200]:
            card.is_active = False
            card.save(update_fields=['is_active', 'updated_at'])
            self._log(request, 'DEACTIVATED', card)
            n += 1
        self.message_user(request, f'Đã vô hiệu hoá {n} thẻ.')

    actions = ['action_deactivate']


class CardDeviceAccessForm(forms.ModelForm):
    class Meta:
        model = CardDeviceAccess
        fields = ('access_card', 'device', 'is_active')

    def clean(self):
        c = super().clean()
        card, device = c.get('access_card'), c.get('device')
        if card and services.is_admin(card.user):
            raise ValidationError('Thẻ của tài khoản quản trị không được gắn vào khoá.')
        if device and not device.owner_id:
            raise ValidationError('Khoá chưa có chủ.')
        return c


@admin.register(CardDeviceAccess)
class CardDeviceAccessAdmin(BaseModelAdmin):
    policy = {'super': FULL, 'admin': VIEW}
    form = CardDeviceAccessForm
    list_display = ('access_card', 'device', 'is_active', 'created_at')
    list_filter = ('is_active',)
    list_select_related = ('access_card', 'device')
    autocomplete_fields = ('access_card', 'device')


@admin.register(DoorPinCode)
class DoorPinCodeAdmin(BaseModelAdmin):
    policy = {'super': VIEW_DELETE, 'admin': VIEW}     # PIN chỉ sinh từ luồng của chủ khoá (hiện 1 lần); không thêm tay
    list_display = ('device', 'label', 'created_by', 'expires_at', 'use_count', 'max_uses', 'is_revoked')
    list_filter = ('is_revoked',)
    search_fields = ('device__name', 'label')
    list_select_related = ('device', 'created_by')

    @admin.action(description='Thu hồi PIN', permissions=['operate'])
    def action_revoke(self, request, queryset):
        n = 0
        for pin in queryset.filter(is_revoked=False)[:200]:
            pin.revoke()
            self._log(request, 'REVOKED', pin)
            n += 1
        self.message_user(request, f'Đã thu hồi {n} mã PIN.')

    actions = ['action_revoke']


@admin.register(FaceProfile)
class FaceProfileAdmin(BaseModelAdmin):
    policy = {'super': VIEW_DELETE, 'admin': VIEW}     # embedding sinh trắc: không xem/sửa/thêm ở admin (NĐ 13/2023)
    list_display = ('user', 'device', 'name', 'is_active', 'consent_confirmed', 'created_at')
    list_filter = ('is_active', 'consent_confirmed')
    list_select_related = ('user', 'device')

    @admin.action(description='Vô hiệu hoá hồ sơ khuôn mặt', permissions=['operate'])
    def action_deactivate(self, request, queryset):
        n = 0
        for p in queryset.filter(is_active=True)[:200]:
            p.is_active = False
            p.save(update_fields=['is_active', 'updated_at'])
            self._log(request, 'DEACTIVATED', p)
            n += 1
        self.message_user(request, f'Đã vô hiệu hoá {n} hồ sơ.')

    actions = ['action_deactivate']


@admin.register(NfcLog)
class NfcLogAdmin(BaseModelAdmin):
    policy = {'super': VIEW_DELETE, 'admin': VIEW}
    list_display = ('created_at', 'device', 'event_type', 'success', 'user')
    list_filter = ('event_type', 'success')
    list_select_related = ('device', 'user')


@admin.register(AccessEvent)
class AccessEventAdmin(BaseModelAdmin):
    policy = {'super': VIEW_DELETE, 'admin': VIEW}
    list_display = ('created_at', 'device', 'method', 'success', 'reason', 'user')
    list_filter = ('method', 'success')
    list_select_related = ('device', 'user')


# ================================================================ THÔNG BÁO / LOG / OTP
@admin.register(Notification)
class NotificationAdmin(BaseModelAdmin):
    policy = {'super': FULL, 'admin': VIEW}
    list_display = ('created_at', 'user', 'device', 'title', 'severity', 'is_read')
    list_filter = ('is_read', 'severity', 'type')
    search_fields = ('title', 'user__email')
    list_select_related = ('user', 'device')
    autocomplete_fields = ('user', 'device')

    def save_model(self, request, obj, form, change):
        if obj.is_read and not obj.read_at:
            obj.read_at = timezone.now()          # constraint chk_notification_readat_requires_read
        if not obj.is_read:
            obj.read_at = None
        super().save_model(request, obj, form, change)


@admin.register(AuditLog)
class AuditLogAdmin(BaseModelAdmin):
    policy = {'super': VIEW_DELETE, 'admin': VIEW}
    list_display = ('created_at', 'action', 'actor_user', 'target_user', 'device', 'success', 'severity', 'ip_address')
    list_filter = ('success', 'severity')
    search_fields = ('action', 'username_attempt', 'actor_user__email', 'target_user__email')
    list_select_related = ('actor_user', 'target_user', 'device')


@admin.register(OneTimeCode)
class OneTimeCodeAdmin(BaseModelAdmin):
    policy = {'super': VIEW_DELETE, 'admin': VIEW}
    list_display = ('user', 'purpose', 'is_used', 'expires_at', 'created_at')
    list_filter = ('purpose', 'is_used')
    search_fields = ('user__email',)
    list_select_related = ('user',)


@admin.register(Announcement)
class AnnouncementAdmin(BaseModelAdmin):
    policy = {'super': FULL, 'admin': FULL}       # thông báo hệ thống: cả 2 vai trò quản trị đều đăng/sửa/gỡ
    list_display = ('title', 'level', 'is_active', 'created_by', 'created_at')
    list_filter = ('level', 'is_active')
    list_select_related = ('created_by',)
    readonly_fields = ('created_by',)

    def save_model(self, request, obj, form, change):
        if not change:
            obj.created_by = request.user
        super().save_model(request, obj, form, change)


# ================================================================ PHIÊN APP / 2FA (chỉ xem; không lộ token/khoá)
@admin.register(MobileSession)
class MobileSessionAdmin(BaseModelAdmin):
    policy = {'super': VIEW, 'admin': VIEW}
    list_display = ('user', 'device_name', 'platform', 'last_used_at', 'expires_at', 'revoked_at')
    list_filter = ('platform',)
    search_fields = ('user__email', 'device_name')
    list_select_related = ('user',)

    @admin.action(description='Thu hồi phiên app', permissions=['operate'])
    def action_revoke(self, request, queryset):
        n = 0
        for s in queryset.filter(revoked_at__isnull=True)[:200]:
            s.revoke()
            self._log(request, 'REVOKED', s)
            n += 1
        self.message_user(request, f'Đã thu hồi {n} phiên.')

    actions = ['action_revoke']


@admin.register(TwoFactorConfig)
class TwoFactorConfigAdmin(BaseModelAdmin):
    policy = {'super': VIEW, 'admin': VIEW}      # không ai tắt 2FA của người khác từ đây
    list_display = ('user', 'totp_confirmed', 'email_otp_enabled', 'preferred_method', 'enabled_at')
    list_select_related = ('user',)


@admin.register(Fido2Credential)
class Fido2CredentialAdmin(BaseModelAdmin):
    policy = {'super': VIEW, 'admin': VIEW}
    list_display = ('user', 'name', 'created_at', 'last_used_at')
    list_select_related = ('user',)


# ================================================================ SITE: ai được vào /admin/ + 2FA (ADMIN_REQUIRE_2FA=True trong .env)
_REQUIRE_2FA = bool(getattr(settings, 'ADMIN_REQUIRE_2FA', False))
_SiteBase = admin.site.__class__
if _REQUIRE_2FA:
    from django_otp.admin import OTPAdminSite
    _SiteBase = OTPAdminSite


class SmartLockAdminSite(_SiteBase):
    def has_permission(self, request):
        if super().has_permission(request):          # is_staff (+ đã xác minh OTP nếu bật 2FA)
            return True
        if _role(request) is None:
            return False
        # Admin full-power không có is_staff: vẫn vào được; 2FA (nếu bật) vẫn bắt buộc.
        return (not _REQUIRE_2FA) or bool(getattr(request.user, 'is_verified', lambda: False)())


admin.site.__class__ = SmartLockAdminSite


# LogEntry của Django: chỉ xem (dấu vết admin còn nguyên).
@admin.register(LogEntry)
class LogEntryAdmin(RoleAdminMixin, admin.ModelAdmin):
    policy = {'super': VIEW, 'admin': VIEW}
    list_display = ('action_time', 'user', 'content_type', 'object_repr', 'action_flag')
    list_filter = ('action_flag',)
    list_select_related = ('user', 'content_type')
    show_full_result_count = False