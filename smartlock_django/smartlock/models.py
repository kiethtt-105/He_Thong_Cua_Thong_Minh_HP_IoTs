# smartlock/models.py

from django.db import models
from django.utils import timezone
from django.contrib.auth.models import AbstractBaseUser, PermissionsMixin, BaseUserManager
from django.core.validators import MinValueValidator, MaxValueValidator
from django.core.exceptions import ValidationError
from django.db.models.signals import pre_save, post_save
from django.dispatch import receiver
import uuid
import os
from cryptography.fernet import Fernet


# ==================== CẤU HÌNH BÍ MẬT (FERNET) ====================
FERNET_KEY = os.environ.get("FERNET_KEY")
if not FERNET_KEY:
    raise RuntimeError(
        "Vui lòng khai báo biến FERNET_KEY trong .env!\n"
        "Tạo key bằng lệnh: python -c \"from cryptography.fernet import Fernet; print(Fernet.generate_key())\""
    )

fernet = Fernet(FERNET_KEY.encode())


def default_lockout_stage_minutes():
    return [5, 10, 30]


# ==================== NHÓM A: NGƯỜI DÙNG & XÁC THỰC ====================
class UserManager(BaseUserManager):
    def create_user(self, email, username, password=None, **extra_fields):
        if not email:
            raise ValueError("User phải có email")
        if not username:
            raise ValueError("User phải có username")
        email = self.normalize_email(email)
        username = username.strip().lower()
        user = self.model(email=email, username=username, **extra_fields)
        user.set_password(password)
        user.full_clean(exclude=['password'])
        user.save(using=self._db)
        return user

    def create_superuser(self, email, username, password=None, **extra_fields):
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)
        extra_fields.setdefault('is_active', True)
        extra_fields.setdefault('email_verified', True)
        return self.create_user(email, username, password, **extra_fields)


class User(AbstractBaseUser, PermissionsMixin):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    email = models.EmailField(unique=True)
    username = models.CharField(max_length=50, unique=True)
    full_name = models.CharField(max_length=100, blank=True, null=True)
    phone = models.CharField(max_length=20, blank=True, null=True)
    avatar_url = models.URLField(max_length=512, blank=True, null=True)
    is_admin = models.BooleanField(default=False)
    is_active = models.BooleanField(default=False)
    email_verified = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    is_staff = models.BooleanField(default=False)
    is_superuser = models.BooleanField(default=False)

    objects = UserManager()

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['username']

    def clean(self):
        super().clean()
        self.email = self.__class__.objects.normalize_email(self.email)
        self.username = (self.username or '').strip().lower()
        conflict = User.objects.filter(
            models.Q(email=self.username) | models.Q(username=self.email)
        ).exclude(pk=self.pk)
        if conflict.exists():
            raise ValidationError("Username/email bị trùng với email/username của tài khoản khác.")

    def __str__(self):
        return self.email


class LoginIdentifier(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='login_identifiers')
    kind = models.CharField(max_length=10, choices=[('EMAIL', 'Email'), ('USERNAME', 'Username')])
    value = models.CharField(max_length=255, unique=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        constraints = [
            models.UniqueConstraint(fields=['user', 'kind'], name='uniq_identifier_per_user_kind')
        ]


class EmailVerificationToken(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='verification_tokens')
    purpose = models.CharField(
        max_length=50,
        choices=[
            ('EMAIL_VERIFY', 'Verify email'),
            ('PASSWORD_RESET', 'Password reset'),
            ('SUPPORT_AUTH', 'Support auth'),
            ('RECOVERY_CONFIRM', 'Recovery confirm'),
            ('UPDATE_INFO', 'Update info'),
        ]
    )
    token_hash = models.CharField(max_length=255)
    is_used = models.BooleanField(default=False)
    used_at = models.DateTimeField(null=True, blank=True)
    expires_at = models.DateTimeField()
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        indexes = [models.Index(fields=['user', 'purpose', 'created_at'], name='idx_evt_user_purpose')]


class LoginAttemptLog(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    identifier = models.CharField(max_length=255)
    user = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True)
    ip_address = models.GenericIPAddressField()
    user_agent = models.TextField(blank=True, null=True)
    success = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        indexes = [
            models.Index(fields=['identifier', 'created_at'], name='idx_loginattempt_id_time'),
            models.Index(fields=['ip_address', 'created_at'], name='idx_loginattempt_ip_time'),
        ]


class LoginLockout(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='login_lockout')
    failed_attempts = models.IntegerField(default=0)
    stage = models.IntegerField(default=0)
    locked_until = models.DateTimeField(null=True, blank=True)
    last_failed_at = models.DateTimeField(null=True, blank=True)
    last_failed_ip = models.GenericIPAddressField(null=True, blank=True)
    warning_sent_at = models.DateTimeField(null=True, blank=True)
    updated_at = models.DateTimeField(auto_now=True)


class SystemSettings(models.Model):
    id = models.SmallIntegerField(primary_key=True, default=1)
    registration_enabled = models.BooleanField(default=True)
    verification_token_expiry_minutes = models.IntegerField(default=30)
    share_code_expiry_minutes = models.IntegerField(default=15)
    login_lockout_stage_minutes = models.JSONField(default=default_lockout_stage_minutes)
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
    is_purchased = models.BooleanField(default=False)          # <--- THAY ĐỔI MỚI
    name = models.CharField(max_length=100)
    mac_address = models.CharField(max_length=17, blank=True, null=True)
    firmware_version = models.CharField(max_length=30, blank=True, null=True)
    status = models.CharField(max_length=20, default='provisioning', choices=[('online', 'Online'), ('offline', 'Offline'), ('maintenance', 'Maintenance'), ('provisioning', 'Provisioning')])
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
    lock_state = models.CharField(max_length=20, choices=[('locked', 'Locked'), ('unlocked', 'Unlocked'), ('jammed', 'Jam'), ('unknown', 'Unknown')])
    tamper_detected = models.BooleanField(default=False)
    temperature = models.DecimalField(max_digits=4, decimal_places=1, null=True, blank=True)
    raw_payload = models.JSONField(null=True, blank=True)
    recorded_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        indexes = [models.Index(fields=['device', 'recorded_at'], name='idx_devstatuslog_dev_time')]


class DeviceCommand(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    device = models.ForeignKey(Device, on_delete=models.CASCADE)
    issued_by = models.ForeignKey(User, on_delete=models.RESTRICT)
    command_type = models.CharField(
        max_length=50,
        choices=[('UNLOCK', 'Unlock'), ('LOCK', 'Lock'), ('ADD_CARD', 'Add Card'), ('REMOVE_CARD', 'Remove Card'),
                 ('RESET', 'Reset'), ('OTA_UPDATE', 'OTA Update'), ('REBOOT', 'Reboot')]
    )
    payload = models.JSONField(null=True, blank=True)
    status = models.CharField(max_length=20, default='pending', choices=[('pending', 'Pending'), ('sent', 'Sent'), ('acknowledged', 'Acknowledged'), ('failed', 'Failed'), ('expired', 'Expired')])
    command_token_hash = models.CharField(max_length=255)
    expires_at = models.DateTimeField()
    created_at = models.DateTimeField(auto_now_add=True)
    acknowledged_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        indexes = [models.Index(fields=['device', 'created_at'], name='idx_devcommand_dev_time')]


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
    permissions = models.ManyToManyField(Permission, blank=True, related_name='device_accesses')
    source = models.CharField(
        max_length=20, default='DIRECT',
        choices=[('DIRECT', 'Chủ thiết bị cấp trực tiếp'), ('SHARE_CODE', 'Qua mã chia sẻ 6 số')]
    )
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


class ShareAccessCode(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    device = models.ForeignKey(Device, on_delete=models.CASCADE, related_name='share_codes')
    created_by = models.ForeignKey(User, on_delete=models.RESTRICT, related_name='created_sharecodes')
    permissions = models.ManyToManyField(Permission, blank=True, related_name='share_codes')
    code_encrypted = models.CharField(max_length=255)
    expires_at = models.DateTimeField()
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        indexes = [models.Index(fields=['device', 'expires_at'], name='idx_sharecode_dev_exp')]

    def set_code(self, plain_6_digit_code: str):
        self.code_encrypted = fernet.encrypt(plain_6_digit_code.encode()).decode()

    def check_code(self, plain_6_digit_code: str) -> bool:
        try:
            return fernet.decrypt(self.code_encrypted.encode()).decode() == plain_6_digit_code
        except Exception:
            return False


# ==================== NHÓM D: NFC READER & THẺ TỪ ====================
class NfcReader(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    device = models.ForeignKey(Device, on_delete=models.CASCADE)
    reader_mode = models.CharField(max_length=20, choices=[('physical', 'Physical'), ('simulated', 'Simulated')])
    name = models.CharField(max_length=100, blank=True, null=True)
    is_active = models.BooleanField(default=False)           
    last_seen_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    class Meta:
        indexes = [models.Index(fields=['device', 'created_at'], name='idx_nfcreader_dev_time')]
        #indexes = [models.Index(fields=['user', 'is_active'], name='idx_accesscard_user_active')]


class NfcReaderConfig(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    reader = models.OneToOneField(NfcReader, on_delete=models.CASCADE, related_name='config')
    auto_register = models.BooleanField(default=False)
    grant_permission = models.JSONField(default=list)
    valid_from = models.DateTimeField(default=timezone.now)
    expires_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)


class NfcSession(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    reader = models.ForeignKey(NfcReader, on_delete=models.CASCADE)
    nfc_tag = models.ForeignKey('AccessCard', on_delete=models.SET_NULL, null=True, blank=True)
    device = models.ForeignKey(Device, on_delete=models.SET_NULL, null=True, blank=True)
    user = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True)
    session_token = models.CharField(max_length=255, unique=True)
    started_at = models.DateTimeField(default=timezone.now)
    ended_at = models.DateTimeField(null=True, blank=True)
    success = models.BooleanField(default=False)
    payload = models.JSONField(null=True, blank=True)


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
        constraints = [models.UniqueConstraint(fields=['access_card', 'device'], name='uniq_card_device')]


class NfcLog(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    reader = models.ForeignKey(NfcReader, on_delete=models.SET_NULL, null=True, blank=True)
    nfc_tag = models.ForeignKey(AccessCard, on_delete=models.SET_NULL, null=True, blank=True)
    device = models.ForeignKey(Device, on_delete=models.SET_NULL, null=True, blank=True)
    user = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True)
    event_type = models.CharField(
        max_length=50,
        choices=[('TAP_SUCCESS', 'Tap Success'), ('TAP_FAILED', 'Tap Failed'),
                 ('CARD_REGISTER', 'Card Register'), ('READER_CONNECTED', 'Reader Connected'),
                 ('READER_DISCONNECTED', 'Reader Disconnected'), ('CONFIG_UPDATED', 'Config Updated'),
                 ('SESSION_TIMEOUT', 'Session Timeout')]
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
        choices=[('ADD_CARD', 'Add Card'), ('REMOVE_CARD', 'Remove Card'), ('CHANGE_PERMISSION', 'Change Permission'),
                 ('RESET_REMOTE', 'Reset Remote'), ('RECOVERY', 'Recovery'), ('TRANSFER_OWNER', 'Transfer Owner'),
                 ('OTA_SENSITIVE', 'OTA Sensitive'), ('OTHER', 'Other')]
    )
    scope = models.CharField(max_length=100, blank=True, null=True)
    authorization_code_hash = models.CharField(max_length=255)
    recovery_code_hash = models.CharField(max_length=255, blank=True, null=True)
    status = models.CharField(max_length=20, default='pending', choices=[('pending', 'Pending'), ('approved', 'Approved'),
                                                                     ('executed', 'Executed'), ('expired', 'Expired'),
                                                                     ('rejected', 'Rejected'), ('cancelled', 'Cancelled')])
    expires_at = models.DateTimeField()
    processed_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True, related_name='processed_supportrequests')
    created_at = models.DateTimeField(auto_now_add=True)
    completed_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        constraints = [
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
        indexes = [models.Index(fields=['user', 'created_at'], name='idx_notification_user_time')]


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


# ==================== SIGNALS ====================
@receiver(pre_save, sender=User)
def set_updated_at_user(sender, instance, **kwargs):
    instance.updated_at = timezone.now()


@receiver(post_save, sender=User)
def sync_login_identifiers(sender, instance, **kwargs):
    LoginIdentifier.objects.update_or_create(
        user=instance, kind='EMAIL', defaults={'value': instance.email.lower()}
    )
    LoginIdentifier.objects.update_or_create(
        user=instance, kind='USERNAME', defaults={'value': instance.username.lower()}
    )


@receiver(pre_save, sender=Device)
def set_updated_at_device(sender, instance, **kwargs):
    instance.updated_at = timezone.now()


@receiver(pre_save, sender=NfcReader)
def set_updated_at_nfc_reader(sender, instance, **kwargs):
    instance.updated_at = timezone.now()


@receiver(pre_save, sender=SystemSettings)
def set_updated_at_system_settings(sender, instance, **kwargs):
    instance.updated_at = timezone.now()