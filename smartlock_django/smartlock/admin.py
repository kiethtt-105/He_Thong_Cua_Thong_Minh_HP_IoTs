from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from .models import (
    User, SystemSettings, Device, DeviceStatusLog, DeviceCommand,
    Permission, DeviceAccess, ShareAccessCode, NfcReader, NfcReaderConfig,
    NfcSession, AccessCard, CardDeviceAccess, NfcLog, SupportRequest,
    Notification, AuditLog, LoginAttemptLog, LoginLockout, EmailVerificationToken,
    LoginIdentifier
)

@admin.register(User)
class CustomUserAdmin(UserAdmin):
    fieldsets = (
        (None, {'fields': ('email', 'username', 'password')}),
        ('Personal info', {'fields': ('full_name', 'phone', 'avatar_url')}),
        ('Permissions', {'fields': ('is_active', 'email_verified', 'is_staff',
                                    'is_superuser', 'is_admin', 'groups', 'user_permissions')}),
        ('Important dates', {'fields': ('last_login', 'date_joined')}),
    )
    list_display = ('email', 'username', 'is_active', 'is_admin', 'is_superuser')
    list_filter = ('is_active', 'is_admin', 'is_superuser', 'email_verified')
    search_fields = ('email', 'username', 'full_name')


@admin.register(SystemSettings)
class SystemSettingsAdmin(admin.ModelAdmin):
    list_display = ('id', 'registration_enabled', 'updated_by')
    list_filter = ('registration_enabled',)


@admin.register(Device)
class DeviceAdmin(admin.ModelAdmin):
    list_display = ('name', 'owner', 'status', 'device_code')
    list_filter = ('status', 'owner')
    search_fields = ('name', 'device_code')


@admin.register(AuditLog)
class AuditLogAdmin(admin.ModelAdmin):
    list_display = ('actor_user', 'target_user', 'device', 'action', 'success', 'created_at')
    list_filter = ('success', 'severity', 'created_at')
    search_fields = ('action', 'username_attempt')
    readonly_fields = ('created_at',)


# ====================== 9 MODEL CÒN LẠI ======================

@admin.register(NfcReader)
class NfcReaderAdmin(admin.ModelAdmin):
    list_display = ('device', 'name', 'is_active', 'reader_mode')
    list_filter = ('is_active', 'reader_mode')


@admin.register(NfcReaderConfig)
class NfcReaderConfigAdmin(admin.ModelAdmin):
    list_display = ('reader', 'auto_register', 'grant_permission')
    list_filter = ('auto_register',)


@admin.register(AccessCard)
class AccessCardAdmin(admin.ModelAdmin):
    list_display = ('card_uid_hash', 'user', 'name', 'is_active')
    list_filter = ('is_active',)
    search_fields = ('card_uid_hash', 'name')


@admin.register(SupportRequest)
class SupportRequestAdmin(admin.ModelAdmin):
    list_display = ('device', 'requested_by', 'action', 'status', 'created_at')
    list_filter = ('status', 'action')
    search_fields = ('device__name',)


@admin.register(Notification)
class NotificationAdmin(admin.ModelAdmin):
    list_display = ('user', 'device', 'title', 'severity', 'is_read', 'created_at')
    list_filter = ('is_read', 'severity')
    search_fields = ('title',)


@admin.register(DeviceAccess)
class DeviceAccessAdmin(admin.ModelAdmin):
    list_display = ('device', 'user', 'source', 'is_active', 'created_at')
    list_filter = ('is_active', 'source')
    search_fields = ('device__name', 'user__email')


@admin.register(ShareAccessCode)
class ShareAccessCodeAdmin(admin.ModelAdmin):
    list_display = ('device', 'created_by', 'expires_at', 'created_at')
    list_filter = ('created_at',)
    search_fields = ('device__name',)


@admin.register(LoginAttemptLog)
class LoginAttemptLogAdmin(admin.ModelAdmin):
    list_display = ('identifier', 'user', 'ip_address', 'success', 'created_at')
    list_filter = ('success', 'created_at')
    search_fields = ('identifier',)


@admin.register(LoginLockout)
class LoginLockoutAdmin(admin.ModelAdmin):
    list_display = ('user', 'failed_attempts', 'locked_until', 'stage')
    list_filter = ('stage',)
    search_fields = ('user__email',)


@admin.register(EmailVerificationToken)
class EmailVerificationTokenAdmin(admin.ModelAdmin):
    list_display = ('user', 'purpose', 'is_used', 'expires_at', 'created_at')
    list_filter = ('is_used',)
    search_fields = ('user__email',)


admin.site.register(DeviceStatusLog)
admin.site.register(DeviceCommand)
admin.site.register(Permission)
admin.site.register(NfcSession)
admin.site.register(CardDeviceAccess)
admin.site.register(NfcLog)