# smartlock/admin.py
from django.contrib import admin
from django.contrib.admin.models import LogEntry
from django.contrib.auth.admin import UserAdmin
from django.contrib.auth.forms import UserChangeForm, UserCreationForm

from .models import (
    AccessCard, AccessEvent, Announcement, AuditLog,
    CardDeviceAccess, Device, DeviceAccess, DeviceCommand, DeviceStatusLog, DoorPinCode,
    FaceProfile, NfcLog, NfcReader, Notification, OneTimeCode, Permission,
    SystemSettings, User,
)


from . import services


# ---------------------------------------------------------------- Ghi AuditLog cho MỌI thao tác ở Django admin
class AuditedAdminMixin:
    """Django admin chỉ tự ghi LogEntry (không hiện ở trang audit, xoá được). Mixin này ghi thêm
    AuditLog (action ADMIN_<MODEL>_*): thêm / sửa (chỉ TÊN trường đổi, không ghi giá trị để khỏi
    lộ dữ liệu nhạy cảm) / xoá, kể cả xoá hàng loạt."""

    def _log(self, request, verb, obj, severity='warning', extra=None):
        model = obj._meta.model_name.upper()
        meta = {'model': obj._meta.label, 'object_id': str(obj.pk), 'object': str(obj)[:120],
                'via': 'django_admin', **(extra or {})}
        target = obj if isinstance(obj, User) else getattr(obj, 'user', None)
        services.audit(request, f'ADMIN_{model}_{verb}'[:50], device=obj if isinstance(obj, Device) else
                       getattr(obj, 'device', None), target_user=target if isinstance(target, User) else None,
                       severity=severity, metadata=meta)

    def save_model(self, request, obj, form, change):
        super().save_model(request, obj, form, change)
        if change:
            self._log(request, 'CHANGED', obj, extra={'fields': sorted(form.changed_data)})
        else:
            self._log(request, 'ADDED', obj)

    def delete_model(self, request, obj):
        self._log(request, 'DELETED', obj, severity='critical')   # ghi TRƯỚC khi xoá để còn thông tin
        super().delete_model(request, obj)

    def delete_queryset(self, request, queryset):
        for obj in list(queryset):
            self._log(request, 'DELETED', obj, severity='critical', extra={'bulk': True})
        super().delete_queryset(request, queryset)


# ---------------------------------------------------------------- User
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
    form = UserEditForm
    add_form = UserCreateForm
    ordering = ('email',)
    list_display = ('email', 'username', 'is_active', 'is_admin', 'is_superuser', 'two_fa_enabled')
    list_filter = ('is_active', 'is_admin', 'is_superuser', 'email_verified')
    search_fields = ('email', 'username', 'full_name')
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


# ---------------------------------------------------------------- Các model còn lại
class ReadOnlyAdmin(admin.ModelAdmin):
    """Bảng log: chỉ xem, không thêm/sửa/xoá (để log còn đáng tin)."""
    def has_add_permission(self, request):
        return False

    def has_change_permission(self, request, obj=None):
        return False

    def has_delete_permission(self, request, obj=None):
        return False


def _secret_fields(model):
    """Ẩn mọi cột hash/mã hoá (token, PIN, UID thẻ, secret thiết bị, embedding khuôn mặt...)."""
    return [f.name for f in model._meta.fields if f.name.endswith(('_hash', '_encrypted'))]


# model -> cấu hình admin. Model trong READ_ONLY dùng ReadOnlyAdmin.
CONFIG = {
    SystemSettings: dict(list_display=('id', 'registration_enabled', 'updated_by')),
    # Gán/gỡ chủ phải đi qua manage_sys / luồng claim (có kiểm tra kết nối + audit), không sửa tay ở đây.
    Device: dict(list_display=('name', 'owner', 'status', 'device_code', 'battery_level'),
                 list_filter=('status',), search_fields=('name', 'device_code', 'owner__email'),
                 readonly_fields=('owner', 'status', 'is_purchased', 'purchased_at', 'device_code'),
                 has_add_permission=lambda self, request: False,
                 has_delete_permission=lambda self, request, obj=None: False),
    DeviceCommand: dict(list_display=('device', 'command_type', 'status', 'issued_by', 'created_at'),
                        list_filter=('command_type', 'status')),
    DeviceStatusLog: dict(list_display=('device', 'lock_state', 'battery_level', 'tamper_detected', 'recorded_at'),
                          list_filter=('lock_state', 'tamper_detected')),
    Permission: dict(list_display=('code', 'name', 'is_sensitive')),
    DeviceAccess: dict(list_display=('device', 'user', 'source', 'is_active', 'created_at'),
                       list_filter=('is_active', 'source'), search_fields=('device__name', 'user__email')),
    NfcReader: dict(list_display=('device', 'name', 'is_active', 'reader_mode', 'auto_register'),
                    list_filter=('is_active', 'reader_mode', 'auto_register')),
    AccessCard: dict(list_display=('name', 'user', 'is_active', 'created_at'),
                     list_filter=('is_active',), search_fields=('name', 'user__email')),
    CardDeviceAccess: dict(list_display=('access_card', 'device', 'is_active')),
    NfcLog: dict(list_display=('device', 'event_type', 'success', 'user', 'created_at'),
                 list_filter=('event_type', 'success')),
    Notification: dict(list_display=('user', 'device', 'title', 'severity', 'is_read', 'created_at'),
                       list_filter=('is_read', 'severity'), search_fields=('title',)),
    AuditLog: dict(list_display=('created_at', 'action', 'actor_user', 'target_user', 'device', 'success', 'severity'),
                   list_filter=('success', 'severity'), search_fields=('action', 'username_attempt')),
    OneTimeCode: dict(list_display=('user', 'purpose', 'is_used', 'expires_at', 'created_at'),
                      list_filter=('purpose', 'is_used'), search_fields=('user__email',)),
    Announcement: dict(list_display=('title', 'level', 'is_active', 'created_at'), list_filter=('level', 'is_active')),
    DoorPinCode: dict(list_display=('device', 'label', 'created_by', 'expires_at', 'use_count', 'max_uses', 'is_revoked'),
                      list_filter=('is_revoked',), search_fields=('device__name', 'label')),
    FaceProfile: dict(list_display=('user', 'device', 'name', 'is_active', 'consent_confirmed'),
                      list_filter=('is_active', 'consent_confirmed')),
    AccessEvent: dict(list_display=('created_at', 'device', 'method', 'success', 'reason', 'user'),
                      list_filter=('method', 'success')),
}
READ_ONLY = {AuditLog, AccessEvent, DeviceStatusLog, DeviceCommand, NfcLog}

for model, options in CONFIG.items():
    base = ReadOnlyAdmin if model in READ_ONLY else admin.ModelAdmin
    admin.site.register(
        model, type(f'{model.__name__}Admin', (AuditedAdminMixin, base),
                    {**options, 'exclude': _secret_fields(model)}),
    )


# LogEntry của Django: chỉ xem (không cho sửa/xoá để dấu vết admin còn nguyên).
@admin.register(LogEntry)
class LogEntryAdmin(ReadOnlyAdmin):
    list_display = ('action_time', 'user', 'content_type', 'object_repr', 'action_flag')
    list_filter = ('action_flag',)