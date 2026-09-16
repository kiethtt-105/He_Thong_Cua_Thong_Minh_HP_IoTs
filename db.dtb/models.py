# smartlock/models.py

from django.db import models
from django.utils import timezone
from django.contrib.auth.models import AbstractBaseUser, PermissionsMixin, BaseUserManager
from django.core.validators import MinValueValidator, MaxValueValidator
import uuid
import os
from cryptography.fernet import Fernet

from django.db.models.signals import pre_save
from django.dispatch import receiver


# ==================== CẤU HÌNH BÍ MẬT (FERNET) ====================
# NANG CAP #1: chỉ đọc key từ environment, không hard-code, không đọc 2 lần.
FERNET_KEY = os.environ.get("FERNET_KEY")
if not FERNET_KEY:
    raise RuntimeError(
        "Vui lòng khai báo biến FERNET_KEY trong .env!\n"
        "Tạo key bằng lệnh: python -c \"from cryptography.fernet import Fernet; print(Fernet.generate_key())\"\n"
        "Nếu key cũ từng bị commit lên Git thì phải tạo key mới và re-encrypt dữ liệu cũ."
    )

fernet = Fernet(FERNET_KEY.encode())


# ==================== NHÓM A: NGƯỜI DÙNG & XÁC THỰC ====================

# NANG CAP #2: User chuyển sang AbstractBaseUser + PermissionsMixin
class UserManager(BaseUserManager):
    def create_user(self, email, password=None, **extra_fields):
        if not email:
            raise ValueError("User phải có email")
        email = self.normalize_email(email)
        user = self.model(email=email, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, email, password=None, **extra_fields):
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)
        extra_fields.setdefault('is_active', True)
        extra_fields.setdefault('email_verified', True)
        return self.create_user(email, password, **extra_fields)


class User(AbstractBaseUser, PermissionsMixin):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    email = models.EmailField(unique=True)
    full_name = models.CharField(max_length=100, blank=True, null=True)
    phone = models.CharField(max_length=20, blank=True, null=True)
    avatar_url = models.URLField(max_length=512, blank=True, null=True)
    is_admin = models.BooleanField(default=False)
    # NANG CAP #3: bỏ is_owner (dữ liệu trùng lặp) — quyền sở hữu xác định
    # trực tiếp qua Device.owner_id, không đồng bộ ngược lên User nữa.
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
    # last_login đã có sẵn từ AbstractBaseUser, không khai báo lại.
    is_staff = models.BooleanField(default=False)
    # is_superuser đã có sẵn từ PermissionsMixin, không khai báo lại.

    objects = UserManager()

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = []

    # SUA LOI: tránh đụng reverse accessor với auth.User (khi AUTH_USER_MODEL
    # chưa/không được set đúng, cả 2 model đều kế thừa PermissionsMixin).
    groups = models.ManyToManyField(
        'auth.Group', related_name='smartlock_user_set', blank=True
    )
    user_permissions = models.ManyToManyField(
        'auth.Permission', related_name='smartlock_user_set', blank=True
    )

    def __str__(self):
        return self.email


class Session(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='sessions')
    refresh_token_hash = models.CharField(max_length=255, unique=True)
    device_info = models.TextField(blank=True, null=True)
    ip_address = models.GenericIPAddressField(blank=True, null=True)
    is_revoked = models.BooleanField(default=False)
    expires_at = models.DateTimeField()
    created_at = models.DateTimeField(auto_now_add=True)
    last_active_at = models.DateTimeField(auto_now=True)


class WebauthnCredential(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='webauthn_credentials')
    credential_id = models.CharField(max_length=512, unique=True)
    public_key = models.TextField()
    sign_count = models.BigIntegerField(default=0)
    transports = models.JSONField(default=list)
    aaguid = models.CharField(max_length=36, blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    last_used_at = models.DateTimeField(null=True, blank=True)


class PendingRegistration(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    email = models.EmailField(unique=True)
    otp_code_hash = models.CharField(max_length=64)
    temp_data = models.JSONField(default=dict)
    is_used = models.BooleanField(default=False)
    expires_at = models.DateTimeField()
    created_at = models.DateTimeField(auto_now_add=True)


class EmailOtpChallenge(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    purpose = models.CharField(
        max_length=50,
        choices=[
            ('EMAIL_VERIFY', 'Verify email'),
            ('LOGIN_2FA', 'Login 2FA'),
            ('SUPPORT_AUTH', 'Support auth'),
            ('PASSWORD_RESET', 'Password reset'),
            ('RECOVERY_CONFIRM', 'Recovery confirm'),
            ('UPDATE_INFO', 'Update info'),
            ('DISABLE_2FA', 'Disable 2FA'),
        ]
    )
    otp_code_hash = models.CharField(max_length=255)
    attempts = models.IntegerField(default=0)
    max_attempts = models.IntegerField(default=3)
    is_used = models.BooleanField(default=False)
    used_at = models.DateTimeField(null=True, blank=True)
    expires_at = models.DateTimeField()
    created_at = models.DateTimeField(auto_now_add=True)


class TotpCredential(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='totp_credential')
    secret_encrypted = models.TextField()  # Đã mã hóa Fernet
    algorithm = models.CharField(max_length=10, default='SHA1', choices=[('SHA1', 'SHA1'), ('SHA256', 'SHA256'), ('SHA512', 'SHA512')])
    digits = models.IntegerField(default=6, choices=[(6, 6), (8, 8)])
    period_seconds = models.IntegerField(default=30)
    is_active = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    activated_at = models.DateTimeField(null=True, blank=True)
    last_used_at = models.DateTimeField(null=True, blank=True)


class HotpCredential(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='hotp_credential')
    secret_encrypted = models.TextField()
    counter = models.BigIntegerField(default=0)
    digits = models.IntegerField(default=6, choices=[(6, 6), (8, 8)])
    is_active = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    activated_at = models.DateTimeField(null=True, blank=True)
    last_used_at = models.DateTimeField(null=True, blank=True)


class AccountBackupCode(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    code_hash = models.CharField(max_length=255)
    is_used = models.BooleanField(default=False)
    used_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)


class TrustedLoginDevice(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    device_uid = models.UUIDField(unique=True, default=uuid.uuid4, editable=False)
    session_key = models.CharField(max_length=40, blank=True, null=True)
    name = models.CharField(max_length=255, default='Thiết bị không xác định')
    user_agent = models.TextField(blank=True, null=True)
    ip_address = models.GenericIPAddressField(blank=True, null=True)
    is_active = models.BooleanField(default=True)
    is_trusted = models.BooleanField(default=False)
    last_seen_at = models.DateTimeField(auto_now=True)
    created_at = models.DateTimeField(auto_now_add=True)


class RemoteAuthRequest(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    session_key = models.CharField(max_length=40)
    target_device_id = models.UUIDField(null=True, blank=True)
    device_info = models.CharField(max_length=255)
    status = models.CharField(max_length=20, default='pending', choices=[('pending', 'Pending'), ('approved', 'Approved'), ('denied', 'Denied')])
    expires_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)


class LoginOtpAttempt(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(User, on_delete=models.CASCADE, null=True, blank=True)
    ip_address = models.GenericIPAddressField()
    action = models.CharField(
        max_length=20,
        choices=[('LOGIN_2FA', 'Login 2FA'), ('EMAIL_OTP', 'Email OTP'), ('TOTP', 'TOTP'), ('HOTP', 'HOTP'), ('BACKUP_CODE', 'Backup Code')]
    )
    created_at = models.DateTimeField(auto_now_add=True)


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
    updated_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True)


class Announcement(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    title = models.CharField(max_length=200)
    body = models.TextField()
    level = models.CharField(max_length=10, default='info', choices=[('info', 'Info'), ('warning', 'Warning'), ('danger', 'Danger')])
    created_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True)
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)


# ==================== NHÓM B: THIẾT BỊ ====================
class Device(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    device_code = models.CharField(max_length=50, unique=True)
    provisioning_secret_hash = models.CharField(max_length=255)
    device_mode = models.CharField(max_length=20, default='physical', choices=[('physical', 'Physical'), ('simulated', 'Simulated')])
    owner = models.ForeignKey(User, on_delete=models.RESTRICT, null=True, blank=True)
    name = models.CharField(max_length=100)
    mac_address = models.CharField(max_length=17, blank=True, null=True)
    firmware_version = models.CharField(max_length=30, blank=True, null=True)
    status = models.CharField(max_length=20, default='provisioning', choices=[('online', 'Online'), ('offline', 'Offline'), ('maintenance', 'Maintenance'), ('provisioning', 'Provisioning')])
    # NANG CAP #5: bỏ lambda validator, dùng MinValueValidator/MaxValueValidator chuẩn.
    battery_level = models.IntegerField(default=100, validators=[MinValueValidator(0), MaxValueValidator(100)])
    location = models.CharField(max_length=255, blank=True, null=True)
    last_seen_at = models.DateTimeField(null=True, blank=True)
    bluetooth_enabled = models.BooleanField(default=True)
    wifi_enabled = models.BooleanField(default=True)
    nfc_enabled = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        constraints = [
            # SUA LOI: status__ne không phải lookup hợp lệ của Django -> dùng ~Q(...)
            models.CheckConstraint(
                check=(
                    models.Q(status='provisioning', owner__isnull=True) |
                    (~models.Q(status='provisioning') & models.Q(owner__isnull=False))
                ),
                name='chk_devices_owner_vs_status'
            )
        ]


class DeviceStatusLog(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    device = models.ForeignKey(Device, on_delete=models.CASCADE)
    battery_level = models.IntegerField(validators=[MinValueValidator(0), MaxValueValidator(100)])
    signal_strength = models.IntegerField(null=True, blank=True)
    lock_state = models.CharField(max_length=20, choices=[('locked', 'Locked'), ('unlocked', 'Unlocked'), ('jammed', 'Jammed'), ('unknown', 'Unknown')])
    tamper_detected = models.BooleanField(default=False)
    temperature = models.DecimalField(max_digits=4, decimal_places=1, null=True, blank=True)
    raw_payload = models.JSONField(null=True, blank=True)
    recorded_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        # NANG CAP #7: index theo device + recorded_at cho truy vấn log theo thời gian
        indexes = [
            models.Index(fields=['device', 'recorded_at'], name='idx_devstatuslog_dev_time'),
        ]


class DeviceCommand(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    device = models.ForeignKey(Device, on_delete=models.CASCADE)
    issued_by = models.ForeignKey(User, on_delete=models.RESTRICT)
    command_type = models.CharField(
        max_length=50,
        choices=[
            ('UNLOCK', 'Unlock'), ('LOCK', 'Lock'), ('ADD_CARD', 'Add Card'), ('REMOVE_CARD', 'Remove Card'),
            ('RESET', 'Reset'), ('OTA_UPDATE', 'OTA Update'), ('REBOOT', 'Reboot')
        ]
    )
    payload = models.JSONField(null=True, blank=True)
    status = models.CharField(max_length=20, default='pending', choices=[('pending', 'Pending'), ('sent', 'Sent'), ('acknowledged', 'Acknowledged'), ('failed', 'Failed'), ('expired', 'Expired')])
    command_token_hash = models.CharField(max_length=255)
    expires_at = models.DateTimeField()
    created_at = models.DateTimeField(auto_now_add=True)
    acknowledged_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        indexes = [
            models.Index(fields=['device', 'created_at'], name='idx_devcommand_dev_time'),
        ]


# ==================== NHÓM C: QUYỀN & CHIA SẺ ====================
class Permission(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    code = models.CharField(max_length=50, unique=True)
    name = models.CharField(max_length=100)
    description = models.TextField(blank=True, null=True)
    is_sensitive = models.BooleanField(default=False)

    def __str__(self):
        return f"{self.code} - {self.name}"


class DeviceAccess(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    device = models.ForeignKey(Device, on_delete=models.CASCADE)
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='user_deviceaccesses')
    # NANG CAP #4: thay JSONField bằng quan hệ M2M tới Permission — nguồn quyền duy nhất.
    permissions = models.ManyToManyField(Permission, blank=True, related_name='device_accesses')
    share_code_hash = models.CharField(max_length=255, blank=True, null=True)
    valid_from = models.DateTimeField(default=timezone.now)
    expires_at = models.DateTimeField(null=True, blank=True)
    is_active = models.BooleanField(default=True)
    accepted = models.BooleanField(default=False)
    created_by = models.ForeignKey(User, on_delete=models.RESTRICT, related_name='created_deviceaccesses')
    created_at = models.DateTimeField(auto_now_add=True)
    revoked_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        constraints = [
            models.CheckConstraint(
                check=models.Q(expires_at__isnull=True) | models.Q(expires_at__gt=models.F('valid_from')),
                name='chk_device_access_expiry'
            )
        ]


class AccessCard(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    card_uid_hash = models.CharField(max_length=255, unique=True)
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='access_cards')
    name = models.CharField(max_length=100, blank=True, null=True)
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)


class CardDeviceAccess(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    access_card = models.ForeignKey(AccessCard, on_delete=models.CASCADE)
    device = models.ForeignKey(Device, on_delete=models.CASCADE)
    created_at = models.DateTimeField(auto_now_add=True)
    is_active = models.BooleanField(default=True)

    class Meta:
        # NANG CAP #6: chặn trùng cặp (card, device)
        constraints = [
            models.UniqueConstraint(fields=['access_card', 'device'], name='uniq_card_device')
        ]


# ==================== NHÓM D: NFC READER ====================
class NfcReader(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    device = models.ForeignKey(Device, on_delete=models.CASCADE)
    reader_mode = models.CharField(max_length=20, choices=[('physical', 'Physical'), ('simulated', 'Simulated')])
    name = models.CharField(max_length=100, blank=True, null=True)
    last_seen_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)


class NfcReaderConfig(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    reader = models.OneToOneField(NfcReader, on_delete=models.CASCADE, related_name='config')
    auto_register = models.BooleanField(default=False)
    grant_permission = models.JSONField(default=list)
    valid_from = models.DateTimeField(default=timezone.now)
    expires_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)


class NfcSession(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    reader = models.ForeignKey(NfcReader, on_delete=models.CASCADE)
    nfc_tag = models.ForeignKey(AccessCard, on_delete=models.SET_NULL, null=True, blank=True)
    device = models.ForeignKey(Device, on_delete=models.SET_NULL, null=True, blank=True)
    user = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True)
    session_token = models.CharField(max_length=255, unique=True)
    started_at = models.DateTimeField(default=timezone.now)
    ended_at = models.DateTimeField(null=True, blank=True)
    success = models.BooleanField(default=False)
    payload = models.JSONField(null=True, blank=True)


class NfcLog(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    reader = models.ForeignKey(NfcReader, on_delete=models.SET_NULL, null=True, blank=True)
    nfc_tag = models.ForeignKey(AccessCard, on_delete=models.SET_NULL, null=True, blank=True)
    device = models.ForeignKey(Device, on_delete=models.SET_NULL, null=True, blank=True)
    user = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True)
    event_type = models.CharField(
        max_length=50,
        choices=[
            ('TAP_SUCCESS', 'Tap Success'), ('TAP_FAILED', 'Tap Failed'),
            ('CARD_REGISTER', 'Card Register'), ('READER_CONNECTED', 'Reader Connected'),
            ('READER_DISCONNECTED', 'Reader Disconnected'), ('CONFIG_UPDATED', 'Config Updated'),
            ('SESSION_TIMEOUT', 'Session Timeout')
        ]
    )
    success = models.BooleanField(default=True)
    ip_address = models.GenericIPAddressField(blank=True, null=True)
    user_agent = models.TextField(blank=True, null=True)
    metadata = models.JSONField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        indexes = [
            models.Index(fields=['device', 'created_at'], name='idx_nfclog_dev_time'),
            models.Index(fields=['user', 'created_at'], name='idx_nfclog_user_time'),
        ]


# ==================== NHÓM E: HỖ TRỢ & NHẬT KÝ ====================
class SupportRequest(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    device = models.ForeignKey(Device, on_delete=models.CASCADE)
    requested_by = models.ForeignKey(User, on_delete=models.RESTRICT, related_name='requested_supportrequests')
    action = models.CharField(
        max_length=50,
        choices=[('ADD_CARD', 'Add Card'), ('REMOVE_CARD', 'Remove Card'), ('CHANGE_PERMISSION', 'Change Permission'), ('RESET_REMOTE', 'Reset Remote'), ('RECOVERY', 'Recovery'), ('TRANSFER_OWNER', 'Transfer Owner'), ('OTA_SENSITIVE', 'OTA Sensitive'), ('OTHER', 'Other')]
    )
    scope = models.CharField(max_length=100, blank=True, null=True)
    authorization_code_hash = models.CharField(max_length=255)
    recovery_code_hash = models.CharField(max_length=255, blank=True, null=True)
    status = models.CharField(max_length=20, default='pending', choices=[('pending', 'Pending'), ('approved', 'Approved'), ('executed', 'Executed'), ('expired', 'Expired'), ('rejected', 'Rejected'), ('cancelled', 'Cancelled')])
    expires_at = models.DateTimeField()
    processed_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True, related_name='processed_supportrequests')
    created_at = models.DateTimeField(auto_now_add=True)
    completed_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        constraints = [
            # SUA LOI: action__notin không phải lookup hợp lệ -> dùng ~Q(action__in=[...])
            models.CheckConstraint(
                check=(
                    models.Q(action__in=['RESET_REMOTE', 'RECOVERY', 'TRANSFER_OWNER'], recovery_code_hash__isnull=False) |
                    (~models.Q(action__in=['RESET_REMOTE', 'RECOVERY', 'TRANSFER_OWNER']) & models.Q(recovery_code_hash__isnull=True))
                ),
                name='chk_support_requires_recovery'
            )
        ]


class Notification(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    device = models.ForeignKey(Device, on_delete=models.SET_NULL, null=True, blank=True)
    type = models.CharField(max_length=50)
    title = models.CharField(max_length=150)
    message = models.TextField()
    severity = models.CharField(max_length=20, default='info', choices=[('info', 'Info'), ('warning', 'Warning'), ('critical', 'Critical')])
    is_read = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    read_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        indexes = [
            models.Index(fields=['user', 'created_at'], name='idx_notification_user_time'),
        ]


class AuditLog(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    actor_user = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True, related_name='audit_logs_actor')
    target_user = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True, related_name='audit_logs_target')
    device = models.ForeignKey(Device, on_delete=models.SET_NULL, null=True, blank=True)
    action = models.CharField(max_length=50)
    username_attempt = models.CharField(max_length=150, blank=True, null=True)
    severity = models.CharField(max_length=20, default='info', choices=[('info', 'Info'), ('warning', 'Warning'), ('critical', 'Critical')])
    success = models.BooleanField(default=True)
    ip_address = models.GenericIPAddressField(blank=True, null=True)
    user_agent = models.TextField(blank=True, null=True)
    metadata = models.JSONField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        indexes = [
            models.Index(fields=['device', 'created_at'], name='idx_auditlog_dev_time'),
            models.Index(fields=['actor_user', 'created_at'], name='idx_auditlog_actor_time'),
        ]


# ==================== INDEXES (tương tự SQL) ====================
# (Django tự động tạo index cho FK/unique khi migrate; các index tổ hợp khai báo trong Meta ở trên)

# ==================== SIGNALS (tương tự TRIGGER SQL) ====================

@receiver(pre_save, sender=User)
def set_updated_at_user(sender, instance, **kwargs):
    instance.updated_at = timezone.now()


@receiver(pre_save, sender=Device)
def set_updated_at_device(sender, instance, **kwargs):
    instance.updated_at = timezone.now()


@receiver(pre_save, sender=NfcReader)
def set_updated_at_nfc_reader(sender, instance, **kwargs):
    instance.updated_at = timezone.now()


@receiver(pre_save, sender=SystemSettings)
def set_updated_at_system_settings(sender, instance, **kwargs):
    instance.updated_at = timezone.now()

