from django.db import models
from django.contrib.postgres.fields import ArrayField, JSONField
import uuid
from datetime import timedelta

class User(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4)
    email = models.EmailField(unique=True)
    password_hash = models.CharField(max_length=255)
    full_name = models.CharField(max_length=100, blank=True)
    phone = models.CharField(max_length=20, blank=True)
    avatar_url = models.CharField(max_length=512, blank=True)
    is_admin = models.BooleanField(default=False)
    is_owner = models.BooleanField(default=False)
    is_active = models.BooleanField(default=False)
    email_verified = models.BooleanField(default=False)
    two_fa_enabled = models.BooleanField(default=False)
    totp_enabled = models.BooleanField(default=False)
    hotp_enabled = models.BooleanField(default=False)
    fido2_enabled = models.BooleanField(default=False)
    force_disable_2fa = models.BooleanField(default=False)
    is_2fa_required = models.BooleanField(default=False)
    force_logout = models.BooleanField(default=False)
    allow_push_auth = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    last_login = models.DateTimeField(null=True, blank=True)
    is_staff = models.BooleanField(default=False)
    is_superuser = models.BooleanField(default=False)

    class Meta:
        db_table = 'users'


class Session(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4)
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='sessions')
    refresh_token_hash = models.CharField(max_length=255, unique=True)
    device_info = models.TextField(blank=True)
    ip_address = models.CharField(max_length=45, blank=True)
    is_revoked = models.BooleanField(default=False)
    expires_at = models.DateTimeField()
    created_at = models.DateTimeField(auto_now_add=True)
    last_active_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = 'sessions'


class WebauthnCredentials(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4)
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='webauthn_credentials')
    credential_id = models.CharField(max_length=512, unique=True)
    public_key = models.TextField()
    sign_count = models.BigIntegerField(default=0)
    transports = ArrayField(models.CharField(max_length=50), blank=True, null=True)
    aaguid = models.CharField(max_length=36, blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    last_used_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        db_table = 'webauthn_credentials'


class PendingRegistration(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4)
    email = models.EmailField(unique=True)
    otp_code_hash = models.CharField(max_length=64)
    temp_data = models.JSONField(default=dict)
    is_used = models.BooleanField(default=False)
    expires_at = models.DateTimeField()
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = 'pending_registrations'


class EmailOtpChallenges(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4)
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='email_otp_challenges')
    purpose = models.CharField(max_length=50)
    otp_code_hash = models.CharField(max_length=255)
    attempts = models.IntegerField(default=0)
    max_attempts = models.IntegerField(default=3)
    is_used = models.BooleanField(default=False)
    used_at = models.DateTimeField(null=True, blank=True)
    expires_at = models.DateTimeField()
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = 'email_otp_challenges'


class TotpCredentials(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4)
    user = models.ForeignKey(User, on_delete=models.CASCADE, unique=True, related_name='totp_credentials')
    secret_encrypted = models.TextField()
    algorithm = models.CharField(max_length=10, default='SHA1')
    digits = models.IntegerField(default=6)
    period_seconds = models.IntegerField(default=30)
    is_active = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    activated_at = models.DateTimeField(null=True, blank=True)
    last_used_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        db_table = 'totp_credentials'


class HotpCredentials(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4)
    user = models.ForeignKey(User, on_delete=models.CASCADE, unique=True, related_name='hotp_credentials')
    secret_encrypted = models.TextField()
    counter = models.BigIntegerField(default=0)
    digits = models.IntegerField(default=6)
    is_active = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    activated_at = models.DateTimeField(null=True, blank=True)
    last_used_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        db_table = 'hotp_credentials'


class AccountBackupCodes(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4)
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='backup_codes')
    code_hash = models.CharField(max_length=255)
    is_used = models.BooleanField(default=False)
    used_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = 'account_backup_codes'


class TrustedLoginDevices(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4)
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='trusted_devices')
    device_uid = models.UUIDField(unique=True, default=uuid.uuid4)
    session_key = models.CharField(max_length=40, blank=True)
    name = models.CharField(max_length=255, default='Thiết bị không xác định')
    user_agent = models.TextField(blank=True)
    ip_address = models.CharField(max_length=45, blank=True)
    is_active = models.BooleanField(default=True)
    is_trusted = models.BooleanField(default=False)
    last_seen_at = models.DateTimeField(auto_now_add=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = 'trusted_login_devices'


class RemoteAuthRequests(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4)
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='remote_auth_requests')
    session_key = models.CharField(max_length=40)
    target_device_id = models.ForeignKey(TrustedLoginDevices, on_delete=models.SET_NULL, null=True)
    device_info = models.CharField(max_length=255)
    status = models.CharField(max_length=20, default='pending')
    expires_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = 'remote_auth_requests'


class LoginOtpAttempts(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4)
    user = models.ForeignKey(User, on_delete=models.SET_NULL, null=True)
    ip_address = models.CharField(max_length=45)
    action = models.CharField(max_length=20)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = 'login_otp_attempts'


class SystemSettings(models.Model):
    id = models.SmallIntegerField(primary_key=True, default=1)
    registration_enabled = models.BooleanField(default=True)
    require_2fa_all = models.BooleanField(default=False)
    otp_expiry_minutes = models.IntegerField(default=5)
    otp_max_retry = models.IntegerField(default=5)
    session_timeout_hours = models.IntegerField(default=24)
    ip_whitelist = models.TextField(default='')
    ip_blacklist = models.TextField(default='')
    updated_at = models.DateTimeField(auto_now=True)
    updated_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True)

    class Meta:
        db_table = 'system_settings'


class Announcement(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4)
    title = models.CharField(max_length=200)
    body = models.TextField()
    level = models.CharField(max_length=10, default='info')
    created_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True)
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = 'announcements'


class Device(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4)
    device_code = models.CharField(max_length=50, unique=True)
    provisioning_secret_hash = models.CharField(max_length=255)
    device_mode = models.CharField(max_length=20, default='physical')
    owner = models.ForeignKey(User, on_delete=models.SET_NULL, null=True)
    name = models.CharField(max_length=100)
    mac_address = models.CharField(max_length=17, blank=True)
    firmware_version = models.CharField(max_length=30, blank=True)
    status = models.CharField(max_length=20, default='provisioning')
    battery_level = models.IntegerField(default=100)
    location = models.CharField(max_length=255, blank=True)
    last_seen_at = models.DateTimeField(null=True, blank=True)
    bluetooth_enabled = models.BooleanField(default=True)
    wifi_enabled = models.BooleanField(default=True)
    nfc_enabled = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = 'devices'


class DeviceStatusLog(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4)
    device = models.ForeignKey(Device, on_delete=models.CASCADE, related_name='status_logs')
    battery_level = models.IntegerField()
    signal = models.FloatField(null=True)
    temperature = models.FloatField(null=True)
    tamper = models.BooleanField(default=False)
    lock_state = models.CharField(max_length=10)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = 'device_status_logs'


class DeviceCommand(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4)
    device = models.ForeignKey(Device, on_delete=models.CASCADE, related_name='commands')
    command_type = models.CharField(max_length=50)
    command_token_hash = models.CharField(max_length=255)
    status = models.CharField(max_length=20, default='pending')
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = 'device_commands'


class Permission(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4)
    code = models.CharField(max_length=100, unique=True)
    name = models.CharField(max_length=255)
    is_sensitive = models.BooleanField(default=False)

    class Meta:
        db_table = 'permissions'


class DeviceAccess(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4)
    device = models.ForeignKey(Device, on_delete=models.CASCADE, related_name='device_access')
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='granted_access')
    permissions = ArrayField(models.CharField(max_length=100))
    share_code_hash = models.CharField(max_length=255, blank=True)
    accepted = models.BooleanField(default=False)
    valid_from = models.DateTimeField(null=True)
    expires_at = models.DateTimeField(null=True)

    class Meta:
        db_table = 'device_access'


class AccessCard(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4)
    card_uid_hash = models.CharField(max_length=255, unique=True)
    status = models.CharField(max_length=20, default='active')
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = 'access_cards'


class CardDeviceAccess(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4)
    access_card = models.ForeignKey(AccessCard, on_delete=models.CASCADE)
    device = models.ForeignKey(Device, on_delete=models.CASCADE)
    is_active = models.BooleanField(default=True)
    expires_at = models.DateTimeField(null=True)

    class Meta:
        db_table = 'card_device_access'


class NfcReader(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4)
    device = models.ForeignKey(Device, on_delete=models.SET_NULL, null=True)
    type = models.CharField(max_length=20)
    name = models.CharField(max_length=100)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = 'nfc_readers'


class NfcReaderConfig(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4)
    reader = models.ForeignKey(NfcReader, on_delete=models.CASCADE)
    auto_register = models.BooleanField(default=False)

    class Meta:
        db_table = 'nfc_reader_configs'


class NfcSession(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4)
    session_token = models.CharField(max_length=255, unique=True)
    reader = models.ForeignKey(NfcReader, on_delete=models.CASCADE)
    card = models.ForeignKey(AccessCard, on_delete=models.SET_NULL, null=True)
    device = models.ForeignKey(Device, on_delete=models.SET_NULL, null=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = 'nfc_sessions'


class NfcLog(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4)
    session = models.ForeignKey(NfcSession, on_delete=models.CASCADE)
    action = models.CharField(max_length=50)
    status = models.CharField(max_length=20)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = 'nfc_logs'


class SupportRequest(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4)
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='support_requests')
    device = models.ForeignKey(Device, on_delete=models.SET_NULL, null=True)
    action = models.CharField(max_length=50)
    authorization_code_hash = models.CharField(max_length=255, blank=True)
    recovery_code_hash = models.CharField(max_length=255, blank=True)
    status = models.CharField(max_length=20, default='pending')
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = 'support_requests'


class Notification(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4)
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='notifications')
    device = models.ForeignKey(Device, on_delete=models.SET_NULL, null=True)
    type = models.CharField(max_length=50)
    title = models.CharField(max_length=150)
    message = models.TextField()
    severity = models.CharField(max_length=20, default='info')
    is_read = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    read_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        db_table = 'notifications'


class AuditLog(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4)
    actor_user = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, related_name='audit_logs_actor')
    target_user = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, related_name='audit_logs_target')
    device = models.ForeignKey(Device, on_delete=models.SET_NULL, null=True)
    action = models.CharField(max_length=50)
    username_attempt = models.CharField(max_length=150, blank=True)
    severity = models.CharField(max_length=20, default='info')
    success = models.BooleanField(default=True)
    ip_address = models.CharField(max_length=45, blank=True)
    user_agent = models.TextField(blank=True)
    metadata = models.JSONField(default=dict)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = 'audit_logs'


print("✅ Models.py đã được tạo thành công!")