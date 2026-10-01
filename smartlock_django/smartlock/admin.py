# smartlock/admin.py
from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from django.contrib.auth.forms import UserChangeForm, UserCreationForm

from .models import (
    AccessCard, AccessEvent, Announcement, AuditLog, AutomationRule, AutomationRuleLog,
    CardDeviceAccess, Device, DeviceAccess, DeviceCommand, DeviceStatusLog, DoorPinCode,
    FaceProfile, NfcLog, NfcReader, Notification, OneTimeCode, Permission, ShareAccessCode,
    SupportRequest, SystemSettings, User,
)


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
class CustomUserAdmin(UserAdmin):
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
    Device: dict(list_display=('name', 'owner', 'status', 'device_code', 'battery_level'),
                 list_filter=('status',), search_fields=('name', 'device_code', 'owner__email')),
    DeviceCommand: dict(list_display=('device', 'command_type', 'status', 'issued_by', 'created_at'),
                        list_filter=('command_type', 'status')),
    DeviceStatusLog: dict(list_display=('device', 'lock_state', 'battery_level', 'tamper_detected', 'recorded_at'),
                          list_filter=('lock_state', 'tamper_detected')),
    Permission: dict(list_display=('code', 'name', 'is_sensitive')),
    DeviceAccess: dict(list_display=('device', 'user', 'source', 'is_active', 'created_at'),
                       list_filter=('is_active', 'source'), search_fields=('device__name', 'user__email')),
    ShareAccessCode: dict(list_display=('device', 'created_by', 'expires_at', 'created_at'),
                          search_fields=('device__name',)),
    NfcReader: dict(list_display=('device', 'name', 'is_active', 'reader_mode', 'auto_register'),
                    list_filter=('is_active', 'reader_mode', 'auto_register')),
    AccessCard: dict(list_display=('name', 'user', 'is_active', 'created_at'),
                     list_filter=('is_active',), search_fields=('name', 'user__email')),
    CardDeviceAccess: dict(list_display=('access_card', 'device', 'is_active')),
    NfcLog: dict(list_display=('device', 'event_type', 'success', 'user', 'created_at'),
                 list_filter=('event_type', 'success')),
    SupportRequest: dict(list_display=('device', 'requested_by', 'action', 'status', 'created_at'),
                         list_filter=('status', 'action'), search_fields=('device__name',)),
    Notification: dict(list_display=('user', 'device', 'title', 'severity', 'is_read', 'created_at'),
                       list_filter=('is_read', 'severity'), search_fields=('title',)),
    AuditLog: dict(list_display=('created_at', 'action', 'actor_user', 'target_user', 'device', 'success', 'severity'),
                   list_filter=('success', 'severity'), search_fields=('action', 'username_attempt')),
    OneTimeCode: dict(list_display=('user', 'purpose', 'is_used', 'expires_at', 'created_at'),
                      list_filter=('purpose', 'is_used'), search_fields=('user__email',)),
    Announcement: dict(list_display=('title', 'level', 'is_active', 'created_at'), list_filter=('level', 'is_active')),
    AutomationRule: dict(list_display=('name', 'owner', 'device', 'trigger_type', 'action_type', 'is_active'),
                         list_filter=('trigger_type', 'action_type', 'is_active')),
    AutomationRuleLog: dict(list_display=('rule', 'device', 'action_taken', 'measured_value', 'triggered_at')),
    DoorPinCode: dict(list_display=('device', 'label', 'created_by', 'expires_at', 'use_count', 'max_uses', 'is_revoked'),
                      list_filter=('is_revoked',), search_fields=('device__name', 'label')),
    FaceProfile: dict(list_display=('user', 'device', 'name', 'is_active', 'consent_confirmed'),
                      list_filter=('is_active', 'consent_confirmed')),
    AccessEvent: dict(list_display=('created_at', 'device', 'method', 'success', 'reason', 'user'),
                      list_filter=('method', 'success')),
}
READ_ONLY = {AuditLog, AccessEvent, AutomationRuleLog, DeviceStatusLog, DeviceCommand, NfcLog}

for model, options in CONFIG.items():
    base = ReadOnlyAdmin if model in READ_ONLY else admin.ModelAdmin
    admin.site.register(
        model, type(f'{model.__name__}Admin', (base,), {**options, 'exclude': _secret_fields(model)}),
    )