# smartlock/models.py

from django.db import models
from django.utils import timezone
from django.contrib.auth.models import AbstractBaseUser, PermissionsMixin, BaseUserManager
from django.core.validators import MinValueValidator, MaxValueValidator, RegexValidator
from django.db.models.functions import Lower
from django.core.exceptions import ValidationError
from django.db.models.signals import pre_save, pre_delete
from django.dispatch import receiver
import uuid
import os
import hmac
import json  
import hashlib
from cryptography.fernet import Fernet

FERNET_KEY = os.environ.get("FERNET_KEY")
if not FERNET_KEY:
    raise RuntimeError(
        "Vui lòng khai báo biến FERNET_KEY trong .env!\n"
        "Tạo key bằng lệnh: python -c \"from cryptography.fernet import Fernet; print(Fernet.generate_key())\""
    )

fernet = Fernet(FERNET_KEY.encode())

SHARE_CODE_PEPPER = os.environ.get('SHARE_CODE_PEPPER')
if not SHARE_CODE_PEPPER:
    if os.environ.get('DEBUG', '').strip().lower() in ('1', 'true', 'yes', 'on'):
        import warnings
        warnings.warn("SHARE_CODE_PEPPER chưa khai báo: đang dùng pepper tạm (chỉ chấp nhận khi DEBUG).",
                      RuntimeWarning)
        SHARE_CODE_PEPPER = 'dev-only:' + FERNET_KEY
    else:
        raise RuntimeError(
            "Thiếu biến môi trường SHARE_CODE_PEPPER (chuỗi bí mật riêng, khác FERNET_KEY). "
            "Tạo bằng: python -c \"import secrets; print(secrets.token_urlsafe(48))\""
        )
elif SHARE_CODE_PEPPER == FERNET_KEY:
    raise RuntimeError("SHARE_CODE_PEPPER không được trùng FERNET_KEY.")


def _pepper_hmac(namespace: str, value: str) -> str:
    return hmac.new(SHARE_CODE_PEPPER.encode(), f'{namespace}:{value}'.encode(), hashlib.sha256).hexdigest()


def hash_card_uid(uid: str) -> str:
    return _pepper_hmac('carduid', uid)


def default_lockout_stage_minutes():
    return [5, 10, 30]


def _hash_door_pin(device_id, plain_pin: str) -> str:
    return _pepper_hmac(f'doorpin:{device_id}', plain_pin)


class KindManager(models.Manager):

    def __init__(self, kind):
        super().__init__()
        self._kind = kind

    def get_queryset(self):
        return super().get_queryset().filter(kind=self._kind)


class KindModel(models.Model):
    KIND = None
    KIND_DEFAULTS = {}

    class Meta:
        abstract = True

    def __init__(self, *args, **kwargs):
        if not args and self.KIND:
            kwargs.setdefault('kind', self.KIND)
            for name, value in self.KIND_DEFAULTS.items():
                kwargs.setdefault(name, value() if callable(value) else value)
        super().__init__(*args, **kwargs)

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
    two_fa_enabled = models.BooleanField(
        default=False,
        help_text='True nếu user có ít nhất 1 phương thức 2FA đang hoạt động. '
                   'Được đồng bộ tự động bởi sync_two_fa_flag(), KHÔNG set tay.'
    )

    login_failed_attempts = models.IntegerField(default=0)
    login_lock_stage = models.IntegerField(default=0)
    login_locked_until = models.DateTimeField(null=True, blank=True)
    login_last_failed_at = models.DateTimeField(null=True, blank=True)
    login_last_failed_ip = models.GenericIPAddressField(null=True, blank=True)

    class Meta:
        constraints = [
            models.UniqueConstraint(Lower('email'), name='uniq_user_email_ci'),
            models.UniqueConstraint(Lower('username'), name='uniq_user_username_ci'),
            models.CheckConstraint(
                check=models.Q(login_failed_attempts__gte=0, login_lock_stage__gte=0),
                name='chk_user_lock_counters_nonneg'),
        ]

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

    @property
    def one_time_codes(self):
        return OneTimeCode.objects.filter(user=self)

    @property
    def mobile_sessions(self):
        return MobileSession.objects.filter(user=self)

    @property
    def fido2_credentials(self):
        return Fido2Credential.objects.filter(user=self)

    @property
    def access_cards(self):
        return AccessCard.objects.filter(user=self)

    @property
    def face_profiles(self):
        return FaceProfile.objects.filter(user=self)

    @property
    def created_door_pins(self):
        return DoorPinCode.objects.filter(created_by=self)

    @property
    def two_factor(self):
        cfg = TwoFactorConfig.objects.filter(user=self).first()
        if cfg is None:
            raise TwoFactorConfig.DoesNotExist('User chưa có cấu hình 2FA.')
        return cfg


class SystemSettings(models.Model):
    id = models.SmallIntegerField(primary_key=True, default=1)
    registration_enabled = models.BooleanField(default=True)
    verification_token_expiry_minutes = models.IntegerField(default=30)
    share_code_expiry_minutes = models.IntegerField(default=15)
    login_lockout_stage_minutes = models.JSONField(default=default_lockout_stage_minutes)
    session_timeout_hours = models.IntegerField(default=24)
    updated_at = models.DateTimeField(auto_now=True)
    updated_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True)

    class Meta:
        constraints = [
            models.CheckConstraint(check=models.Q(id=1), name='chk_settings_singleton'),
            models.CheckConstraint(
                check=models.Q(verification_token_expiry_minutes__gte=1, verification_token_expiry_minutes__lte=10080,
                               share_code_expiry_minutes__gte=1, share_code_expiry_minutes__lte=1440,
                               session_timeout_hours__gte=1, session_timeout_hours__lte=720),
                name='chk_settings_ranges'),
        ]


class Announcement(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    title = models.CharField(max_length=200)
    body = models.TextField()
    level = models.CharField(max_length=10, default='info', choices=[('info', 'Info'), ('warning', 'Warning'), ('danger', 'Danger')])
    created_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True)
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)

class Device(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    device_code = models.CharField(max_length=50, unique=True)
    provisioning_secret_hash = models.CharField(max_length=255)
    device_mode = models.CharField(max_length=20, default='physical', choices=[('physical', 'Physical'), ('simulated', 'Simulated')])
    owner = models.ForeignKey(User, on_delete=models.RESTRICT, null=True, blank=True)
    is_purchased = models.BooleanField(
        default=False,
        help_text='True khi thiết bị đã được khách mua/kích hoạt chính thức, khác với '
                   'thiết bị demo/dùng thử nội bộ. Chỉ thiết bị đã mua mới được tính vào '
                   'doanh số.'
    )
    purchased_at = models.DateTimeField(null=True, blank=True)
    name = models.CharField(max_length=100)
    mac_address = models.CharField(
        max_length=17, blank=True, null=True,
        validators=[RegexValidator(r'^([0-9A-F]{2}:){5}[0-9A-F]{2}$',
                                   'MAC phải dạng AA:BB:CC:DD:EE:FF (chữ hoa).')])
    firmware_version = models.CharField(max_length=30, blank=True, null=True)
    status = models.CharField(
        max_length=20, default='provisioning',
        choices=[
            ('online', 'Online'), ('offline', 'Offline'), ('maintenance', 'Maintenance'),
            ('provisioning', 'Provisioning'),
            ('revoked', 'Revoked (đã factory reset, chờ gán chủ mới)'),
        ]
    )
    battery_level = models.IntegerField(default=100, validators=[MinValueValidator(0), MaxValueValidator(100)])
    location = models.CharField(max_length=255, blank=True, null=True)
    last_seen_at = models.DateTimeField(null=True, blank=True)
    bluetooth_enabled = models.BooleanField(default=True)
    wifi_enabled = models.BooleanField(default=True)
    nfc_enabled = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    NO_OWNER_STATUSES = ('provisioning', 'revoked')

    class Meta:
        constraints = [
            models.CheckConstraint(
                check=(
                    models.Q(status__in=('provisioning', 'revoked'), owner__isnull=True) |
                    (~models.Q(status__in=('provisioning', 'revoked')) & models.Q(owner__isnull=False))
                ),
                name='chk_devices_owner_vs_status'
            ),
            models.CheckConstraint(check=models.Q(battery_level__gte=0, battery_level__lte=100),
                                   name='chk_device_battery_range'),
            models.CheckConstraint(check=models.Q(is_purchased=False) | models.Q(purchased_at__isnull=False),
                                   name='chk_device_purchased_has_date'),
        ]

    def factory_reset(self, save=True):
        self.status = 'revoked'
        self.owner = None
        if save:
            self.save(update_fields=['status', 'owner', 'updated_at'])

    def mark_purchased(self, save=True):
        self.is_purchased = True
        self.purchased_at = timezone.now()
        if save:
            self.save(update_fields=['is_purchased', 'purchased_at', 'updated_at'])

    @property
    def access_events(self):
        return AccessEvent.objects.filter(device=self)

    @property
    def door_pins(self):
        return DoorPinCode.objects.filter(device=self)

    @property
    def face_profiles(self):
        return FaceProfile.objects.filter(device=self)


class DeviceCommand(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    device = models.ForeignKey(Device, on_delete=models.CASCADE)
    issued_by = models.ForeignKey(User, on_delete=models.RESTRICT)
    command_type = models.CharField(
        max_length=50,
        choices=[('UNLOCK', 'Unlock'), ('LOCK', 'Lock'), ('ADD_CARD', 'Add Card'), ('REMOVE_CARD', 'Remove Card'),
                 ('RESET', 'Reset'), ('OTA_UPDATE', 'OTA Update'), ('REBOOT', 'Reboot'),
                 ('PING', 'Ping (kiểm tra kết nối)')]
    )
    payload = models.JSONField(null=True, blank=True)
    status = models.CharField(max_length=20, default='pending', choices=[('pending', 'Pending'), ('sent', 'Sent'), ('acknowledged', 'Acknowledged'), ('failed', 'Failed'), ('expired', 'Expired')])
    command_token_hash = models.CharField(max_length=255)
    expires_at = models.DateTimeField()
    created_at = models.DateTimeField(auto_now_add=True)
    acknowledged_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        indexes = [models.Index(fields=['device', 'created_at'], name='idx_devcommand_dev_time')]


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
        choices=[('DIRECT', 'Chủ thiết bị chia sẻ trực tiếp'), ('SHARE_CODE', 'Mã chia sẻ (cũ)')]
    )
    valid_from = models.DateTimeField(default=timezone.now)
    expires_at = models.DateTimeField(null=True, blank=True)
    is_active = models.BooleanField(default=True)
    accepted = models.BooleanField(default=True)
    created_by = models.ForeignKey(User, on_delete=models.RESTRICT, related_name='created_deviceaccesses')
    created_at = models.DateTimeField(auto_now_add=True)
    revoked_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        constraints = [
            models.CheckConstraint(
                check=models.Q(expires_at__isnull=True) | models.Q(expires_at__gt=models.F('valid_from')),
                name='chk_device_access_expiry'
            ),
            models.UniqueConstraint(fields=['device', 'user'], condition=models.Q(is_active=True),
                                    name='uniq_active_device_access'),
        ]


class NfcReader(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    device = models.ForeignKey(Device, on_delete=models.CASCADE)
    reader_mode = models.CharField(max_length=20, choices=[('physical', 'Physical'), ('simulated', 'Simulated')])
    name = models.CharField(max_length=100, blank=True, null=True)
    is_active = models.BooleanField(default=False)           
    last_seen_at = models.DateTimeField(null=True, blank=True)
    auto_register = models.BooleanField(default=False)
    auto_register_until = models.DateTimeField(null=True, blank=True)
    grant_permission = models.JSONField(default=list)
    valid_from = models.DateTimeField(default=timezone.now)
    expires_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        indexes = [models.Index(fields=['device', 'created_at'], name='idx_nfcreader_dev_time')]
        constraints = [
            models.CheckConstraint(
                check=models.Q(expires_at__isnull=True) | models.Q(expires_at__gt=models.F('valid_from')),
                name='chk_nfcreader_expiry'),
        ]

    @property
    def auto_register_active(self) -> bool:
        return bool(self.auto_register and self.auto_register_until
                    and self.auto_register_until > timezone.now())

    @property
    def config(self):
        return self


class CardDeviceAccess(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    access_card = models.ForeignKey('AccessCredential', on_delete=models.CASCADE)
    device = models.ForeignKey(Device, on_delete=models.CASCADE)
    created_at = models.DateTimeField(auto_now_add=True)
    is_active = models.BooleanField(default=True)

    class Meta:
        constraints = [models.UniqueConstraint(fields=['access_card', 'device'], name='uniq_card_device')]


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
        constraints = [
            models.CheckConstraint(check=models.Q(read_at__isnull=True) | models.Q(is_read=True),
                                   name='chk_notification_readat_requires_read'),
        ]

class ActivityLog(KindModel):
    KIND_AUDIT = 'AUDIT'
    KIND_NFC = 'NFC'
    KIND_ACCESS = 'ACCESS'
    KIND_STATUS = 'STATUS'
    KIND_CHOICES = [(KIND_AUDIT, 'Audit log'), (KIND_NFC, 'NFC log'),
                    (KIND_ACCESS, 'Access event'), (KIND_STATUS, 'Device status log')]

    SEVERITY_CHOICES = [('info', 'Info'), ('warning', 'Warning'), ('critical', 'Critical')]
    LOCK_STATE_CHOICES = [('locked', 'Locked'), ('unlocked', 'Unlocked'), ('jammed', 'Jam'), ('unknown', 'Unknown')]
    NFC_EVENT_CHOICES = [('TAP_SUCCESS', 'Tap Success'), ('TAP_FAILED', 'Tap Failed'),
                         ('CARD_REGISTER', 'Card Register'), ('READER_CONNECTED', 'Reader Connected'),
                         ('READER_DISCONNECTED', 'Reader Disconnected'), ('CONFIG_UPDATED', 'Config Updated'),
                         ('SESSION_TIMEOUT', 'Session Timeout')]

    METHOD_RFID = 'RFID'
    METHOD_PIN = 'PIN'
    METHOD_FACE = 'FACE'
    METHOD_BLE = 'BLE'
    METHOD_NFC_PHONE = 'NFC_PHONE'
    METHOD_CHOICES = [
        (METHOD_RFID, 'Thẻ RFID'),
        (METHOD_PIN, 'Mã PIN'),
        (METHOD_FACE, 'Khuôn mặt'),
        (METHOD_BLE, 'Bluetooth'),
        (METHOD_NFC_PHONE, 'NFC trên điện thoại'),
    ]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    kind = models.CharField(max_length=10, choices=KIND_CHOICES)

    device = models.ForeignKey(Device, on_delete=models.SET_NULL, null=True, blank=True,
                               related_name='activity_logs')
    user = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True,
                             related_name='activity_logs')
    success = models.BooleanField(default=True)
    severity = models.CharField(max_length=20, default='info', choices=SEVERITY_CHOICES)
    ip_address = models.GenericIPAddressField(blank=True, null=True)
    user_agent = models.TextField(blank=True, null=True)
    metadata = models.JSONField(null=True, blank=True)

    actor_user = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True,
                                   related_name='audit_logs_actor')
    target_user = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True,
                                    related_name='audit_logs_target')
    action = models.CharField(max_length=50, blank=True, default='')
    username_attempt = models.CharField(max_length=150, blank=True, null=True)

    reader = models.ForeignKey('NfcReader', on_delete=models.SET_NULL, null=True, blank=True,
                               related_name='activity_logs')
    nfc_tag = models.ForeignKey('AccessCredential', on_delete=models.SET_NULL, null=True, blank=True,
                                related_name='nfc_logs')
    event_type = models.CharField(max_length=50, blank=True, default='', choices=NFC_EVENT_CHOICES)

    method = models.CharField(max_length=10, blank=True, default='', choices=METHOD_CHOICES)
    reason = models.CharField(max_length=100, blank=True, null=True, help_text='Lý do thất bại, nếu có.')
    access_card = models.ForeignKey('AccessCredential', on_delete=models.SET_NULL, null=True, blank=True,
                                    related_name='access_events_as_card')
    door_pin = models.ForeignKey('AccessCredential', on_delete=models.SET_NULL, null=True, blank=True,
                                 related_name='access_events_as_pin')
    face_profile = models.ForeignKey('AccessCredential', on_delete=models.SET_NULL, null=True, blank=True,
                                     related_name='access_events_as_face')
    confidence = models.FloatField(null=True, blank=True, help_text='Độ tin cậy nhận diện khuôn mặt (nếu có).')
    snapshot_url = models.URLField(
        max_length=512, blank=True, null=True,
        help_text='Ảnh chụp lúc mở cửa, lưu ở object storage (MinIO/S3), khuyến nghị giữ tối đa 30 ngày.')

    battery_level = models.IntegerField(null=True, blank=True,
                                        validators=[MinValueValidator(0), MaxValueValidator(100)])
    signal_strength = models.IntegerField(null=True, blank=True)
    lock_state = models.CharField(max_length=20, blank=True, default='', choices=LOCK_STATE_CHOICES)
    tamper_detected = models.BooleanField(default=False)
    temperature = models.DecimalField(max_digits=4, decimal_places=1, null=True, blank=True)
    raw_payload = models.JSONField(null=True, blank=True)
    recorded_at = models.DateTimeField(null=True, blank=True)

    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        indexes = [
            models.Index(fields=['kind', 'created_at'], name='idx_actlog_kind_time'),
            models.Index(fields=['device', 'kind', 'created_at'], name='idx_actlog_dev_kind_time'),
            models.Index(fields=['actor_user', 'created_at'], name='idx_actlog_actor_time'),
            models.Index(fields=['user', 'created_at'], name='idx_actlog_user_time'),
            models.Index(fields=['device', 'method', 'success', 'created_at'], name='idx_actlog_method_ok'),
            models.Index(fields=['device', 'recorded_at'], name='idx_actlog_dev_rec'),
        ]
        constraints = [
            models.CheckConstraint(check=models.Q(kind__in=['AUDIT', 'NFC', 'ACCESS', 'STATUS']),
                                   name='chk_actlog_kind'),
            models.CheckConstraint(
                check=models.Q(battery_level__isnull=True) |
                      models.Q(battery_level__gte=0, battery_level__lte=100),
                name='chk_actlog_battery_range'),
            models.CheckConstraint(
                check=~models.Q(kind='STATUS') |
                      (models.Q(battery_level__isnull=False) & ~models.Q(lock_state='')),
                name='chk_actlog_status_required'),
            models.CheckConstraint(check=~models.Q(kind='ACCESS') | ~models.Q(method=''),
                                   name='chk_actlog_access_method'),
        ]


@receiver(pre_delete, sender=Device)
def delete_device_bound_logs(sender, instance, **kwargs):
    ActivityLog.objects.filter(device=instance,
                               kind__in=[ActivityLog.KIND_ACCESS, ActivityLog.KIND_STATUS]).delete()


class AuditLog(ActivityLog):
    KIND = ActivityLog.KIND_AUDIT
    objects = KindManager(ActivityLog.KIND_AUDIT)
    VISIBLE_FIELDS = ('id', 'actor_user', 'target_user', 'device', 'action', 'username_attempt', 'severity',
                      'success', 'ip_address', 'user_agent', 'metadata', 'created_at')

    class Meta:
        proxy = True


class NfcLog(ActivityLog):
    KIND = ActivityLog.KIND_NFC
    objects = KindManager(ActivityLog.KIND_NFC)
    VISIBLE_FIELDS = ('id', 'reader', 'nfc_tag', 'device', 'user', 'event_type', 'success', 'ip_address',
                      'user_agent', 'metadata', 'created_at')

    class Meta:
        proxy = True


class AccessEvent(ActivityLog):
    KIND = ActivityLog.KIND_ACCESS
    objects = KindManager(ActivityLog.KIND_ACCESS)
    VISIBLE_FIELDS = ('id', 'device', 'method', 'success', 'reason', 'user', 'access_card', 'door_pin',
                      'face_profile', 'confidence', 'snapshot_url', 'ip_address', 'created_at')

    class Meta:
        proxy = True

    def __str__(self):
        return f'{self.get_method_display()} - {"OK" if self.success else "FAIL"} @ {self.device_id}'


class DeviceStatusLog(ActivityLog):
    KIND = ActivityLog.KIND_STATUS
    KIND_DEFAULTS = {'recorded_at': timezone.now}
    objects = KindManager(ActivityLog.KIND_STATUS)
    VISIBLE_FIELDS = ('id', 'device', 'battery_level', 'signal_strength', 'lock_state', 'tamper_detected',
                      'temperature', 'raw_payload', 'recorded_at')

    class Meta:
        proxy = True


class AccessCredential(KindModel):
    KIND_CARD = 'CARD'
    KIND_PIN = 'PIN'
    KIND_FACE = 'FACE'
    KIND_CHOICES = [(KIND_CARD, 'Thẻ RFID'), (KIND_PIN, 'Mã PIN'), (KIND_FACE, 'Khuôn mặt')]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    kind = models.CharField(max_length=10, choices=KIND_CHOICES)

    user = models.ForeignKey(User, on_delete=models.CASCADE, null=True, blank=True, related_name='+')
    created_by = models.ForeignKey(User, on_delete=models.RESTRICT, null=True, blank=True, related_name='+')
    device = models.ForeignKey(Device, on_delete=models.CASCADE, null=True, blank=True, related_name='+')

    name = models.CharField(max_length=100, blank=True, null=True)
    label = models.CharField(max_length=100, blank=True, null=True, help_text='VD: "Khách Booking #123"')

    card_uid_hash = models.CharField(max_length=255, blank=True, null=True)
    pin_hash = models.CharField(max_length=255, blank=True, null=True)
    embedding_encrypted = models.BinaryField(
        null=True, blank=True,
        help_text='Vector đặc trưng khuôn mặt (vd. 128 chiều), đã mã hoá Fernet.')

    valid_from = models.DateTimeField(null=True, blank=True)
    expires_at = models.DateTimeField(null=True, blank=True)
    max_uses = models.IntegerField(default=1)
    use_count = models.IntegerField(default=0)
    is_revoked = models.BooleanField(default=False)
    revoked_at = models.DateTimeField(null=True, blank=True)

    threshold = models.FloatField(default=0.6)
    consent_confirmed = models.BooleanField(
        default=False,
        help_text='Xác nhận người này đã đồng ý được thu thập dữ liệu khuôn mặt (bắt buộc theo NĐ 13/2023).')

    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        indexes = [
            models.Index(fields=['kind', 'user'], name='idx_cred_kind_user'),
            models.Index(fields=['kind', 'device'], name='idx_cred_kind_device'),
            models.Index(fields=['device', 'expires_at'], name='idx_cred_dev_exp'),
        ]
        constraints = [
            models.CheckConstraint(check=models.Q(kind__in=['CARD', 'PIN', 'FACE']), name='chk_cred_kind'),
            models.UniqueConstraint(fields=['card_uid_hash'], condition=models.Q(kind='CARD'),
                                    name='uniq_cred_card_uid'),
            models.CheckConstraint(
                check=~models.Q(kind='CARD') |
                      (models.Q(card_uid_hash__isnull=False) & models.Q(user__isnull=False)),
                name='chk_cred_card_required'),
            models.CheckConstraint(
                check=~models.Q(kind='PIN') | models.Q(max_uses__gte=0, use_count__gte=0),
                name='chk_cred_pin_uses_nonneg'),
            models.CheckConstraint(
                check=~models.Q(kind='PIN') |
                      (models.Q(expires_at__isnull=False) & models.Q(expires_at__gt=models.F('valid_from'))),
                name='chk_cred_pin_expiry'),
            models.CheckConstraint(
                check=~models.Q(kind='PIN') | models.Q(is_revoked=False) | models.Q(revoked_at__isnull=False),
                name='chk_cred_pin_revoked_date'),
            models.CheckConstraint(
                check=~models.Q(kind='PIN') |
                      (models.Q(pin_hash__isnull=False) & models.Q(device__isnull=False) &
                       models.Q(created_by__isnull=False)),
                name='chk_cred_pin_required'),
            models.UniqueConstraint(fields=['user', 'device'], condition=models.Q(kind='FACE'),
                                    name='uniq_cred_face_user_device'),
            models.CheckConstraint(
                check=~models.Q(kind='FACE') | models.Q(threshold__gt=0, threshold__lte=2),
                name='chk_cred_face_threshold'),
            models.CheckConstraint(
                check=~models.Q(kind='FACE') | models.Q(is_active=False) | models.Q(consent_confirmed=True),
                name='chk_cred_face_active_consent'),
            models.CheckConstraint(
                check=~models.Q(kind='FACE') |
                      (models.Q(user__isnull=False) & models.Q(device__isnull=False)),
                name='chk_cred_face_required'),
        ]


class AccessCard(AccessCredential):
    KIND = AccessCredential.KIND_CARD
    objects = KindManager(AccessCredential.KIND_CARD)
    VISIBLE_FIELDS = ('id', 'user', 'name', 'card_uid_hash', 'is_active', 'created_at', 'updated_at')

    class Meta:
        proxy = True


class DoorPinCode(AccessCredential):
    KIND = AccessCredential.KIND_PIN
    KIND_DEFAULTS = {'valid_from': timezone.now}
    objects = KindManager(AccessCredential.KIND_PIN)
    VISIBLE_FIELDS = ('id', 'device', 'created_by', 'label', 'pin_hash', 'valid_from', 'expires_at', 'max_uses',
                      'use_count', 'is_revoked', 'revoked_at', 'created_at')

    class Meta:
        proxy = True

    def set_pin(self, plain_pin: str):
        self.pin_hash = _hash_door_pin(self.device_id, plain_pin)

    def check_pin(self, plain_pin: str) -> bool:
        return hmac.compare_digest(self.pin_hash, _hash_door_pin(self.device_id, plain_pin))

    def is_valid_now(self) -> bool:
        now = timezone.now()
        if self.is_revoked:
            return False
        if not (self.valid_from <= now <= self.expires_at):
            return False
        if self.max_uses and self.use_count >= self.max_uses:
            return False
        return True

    def register_use(self, save=True):
        self.use_count += 1
        if save:
            self.save(update_fields=['use_count'])

    def revoke(self, save=True):
        self.is_revoked = True
        self.revoked_at = timezone.now()
        if save:
            self.save(update_fields=['is_revoked', 'revoked_at'])


class FaceProfile(AccessCredential):
    KIND = AccessCredential.KIND_FACE
    objects = KindManager(AccessCredential.KIND_FACE)
    VISIBLE_FIELDS = ('id', 'user', 'device', 'name', 'embedding_encrypted', 'threshold', 'consent_confirmed',
                      'is_active', 'created_at', 'updated_at')

    class Meta:
        proxy = True

    def set_embedding(self, vector) -> None:
        raw = json.dumps(list(vector)).encode()
        self.embedding_encrypted = fernet.encrypt(raw)

    def get_embedding(self) -> list:
        try:
            return json.loads(fernet.decrypt(bytes(self.embedding_encrypted)).decode())
        except Exception:
            return []


OTP_PURPOSE_CHOICES = [
    ('EMAIL_VERIFY', 'Verify email'),
    ('PASSWORD_RESET', 'Password reset'),
    ('SUPPORT_AUTH', 'Support auth'),
    ('RECOVERY_CONFIRM', 'Recovery confirm'),
    ('UPDATE_INFO', 'Update info'),
    ('TF_SETUP', '2FA email - thiết lập'),
    ('TF_VERIFY', '2FA email - xác thực'),
]
TWO_FA_METHOD_CHOICES = [
    ('totp', 'Google Authenticator (TOTP)'),
    ('fido2', 'Passkey / FIDO2'),
    ('email', 'Email OTP'),
]


class SecurityRecord(KindModel):
    KIND_OTP = 'OTP'
    KIND_SESSION = 'SESSION'
    KIND_PASSKEY = 'PASSKEY'
    KIND_TFCONFIG = 'TFCONFIG'
    KIND_CHOICES = [(KIND_OTP, 'One-time code'), (KIND_SESSION, 'Mobile session'),
                    (KIND_PASSKEY, 'Passkey / FIDO2'), (KIND_TFCONFIG, '2FA config')]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    kind = models.CharField(max_length=10, choices=KIND_CHOICES)
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='+')

    purpose = models.CharField(max_length=50, blank=True, default='', choices=OTP_PURPOSE_CHOICES)
    token_hash = models.CharField(max_length=255, blank=True, default='')
    attempts = models.IntegerField(default=0)
    is_used = models.BooleanField(default=False)
    used_at = models.DateTimeField(null=True, blank=True)

    refresh_hash = models.CharField(max_length=64, blank=True, null=True)
    prev_refresh_hash = models.CharField(max_length=64, blank=True, default='')
    device_name = models.CharField(max_length=100, blank=True, default='')
    platform = models.CharField(max_length=20, blank=True, default='')
    app_version = models.CharField(max_length=30, blank=True, default='')
    fcm_token = models.CharField(max_length=512, blank=True, default='')
    push_enabled = models.BooleanField(default=True)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    revoked_at = models.DateTimeField(null=True, blank=True)

    credential_id = models.CharField(max_length=512, blank=True, null=True)
    public_key = models.BinaryField(null=True, blank=True)
    sign_count = models.BigIntegerField(default=0)
    transports = models.JSONField(default=list, blank=True)
    name = models.CharField(max_length=100, blank=True, default='')
    rp_id = models.CharField(max_length=255, blank=True, null=True)

    totp_secret_encrypted = models.CharField(max_length=255, blank=True, default='')
    totp_confirmed = models.BooleanField(default=False)
    totp_last_step = models.BigIntegerField(default=0)
    email_otp_enabled = models.BooleanField(default=False)
    preferred_method = models.CharField(max_length=10, blank=True, default='', choices=TWO_FA_METHOD_CHOICES)
    enabled_at = models.DateTimeField(null=True, blank=True)

    expires_at = models.DateTimeField(null=True, blank=True)
    last_used_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        indexes = [
            models.Index(fields=['user', 'kind', 'purpose', 'created_at'], name='idx_secrec_user_purpose'),
            models.Index(fields=['user', 'kind', 'revoked_at'], name='idx_secrec_user_rev'),
            models.Index(fields=['prev_refresh_hash'], condition=models.Q(kind='SESSION'),
                         name='idx_secrec_prev_refresh'),
            models.Index(fields=['fcm_token'], condition=models.Q(kind='SESSION'), name='idx_secrec_fcm'),
        ]
        constraints = [
            models.CheckConstraint(check=models.Q(kind__in=['OTP', 'SESSION', 'PASSKEY', 'TFCONFIG']),
                                   name='chk_secrec_kind'),
            models.CheckConstraint(check=~models.Q(kind='OTP') | models.Q(attempts__gte=0),
                                   name='chk_secrec_otp_attempts'),
            models.CheckConstraint(
                check=~models.Q(kind='OTP') | models.Q(used_at__isnull=True) | models.Q(is_used=True),
                name='chk_secrec_otp_usedat'),
            models.CheckConstraint(
                check=~models.Q(kind='OTP') | (~models.Q(purpose='') & models.Q(expires_at__isnull=False)),
                name='chk_secrec_otp_required'),
            models.UniqueConstraint(fields=['refresh_hash'], condition=models.Q(kind='SESSION'),
                                    name='uniq_secrec_refresh_hash'),
            models.CheckConstraint(
                check=~models.Q(kind='SESSION') |
                      (models.Q(refresh_hash__isnull=False) & models.Q(expires_at__gt=models.F('created_at'))),
                name='chk_secrec_session'),
            models.UniqueConstraint(fields=['credential_id'], condition=models.Q(kind='PASSKEY'),
                                    name='uniq_secrec_credential_id'),
            models.CheckConstraint(
                check=~models.Q(kind='PASSKEY') |
                      (models.Q(credential_id__isnull=False) & models.Q(public_key__isnull=False)),
                name='chk_secrec_passkey'),
            models.UniqueConstraint(fields=['user'], condition=models.Q(kind='TFCONFIG'),
                                    name='uniq_secrec_tfconfig_user'),
        ]


class OneTimeCode(SecurityRecord):
    PURPOSE_CHOICES = OTP_PURPOSE_CHOICES
    KIND = SecurityRecord.KIND_OTP
    objects = KindManager(SecurityRecord.KIND_OTP)
    VISIBLE_FIELDS = ('id', 'user', 'purpose', 'token_hash', 'attempts', 'is_used', 'used_at', 'expires_at',
                      'created_at')

    class Meta:
        proxy = True


class MobileSession(SecurityRecord):
    KIND = SecurityRecord.KIND_SESSION
    KIND_DEFAULTS = {'platform': 'android'}
    objects = KindManager(SecurityRecord.KIND_SESSION)
    VISIBLE_FIELDS = ('id', 'user', 'refresh_hash', 'prev_refresh_hash', 'device_name', 'platform', 'app_version',
                      'fcm_token', 'push_enabled', 'ip_address', 'created_at', 'last_used_at', 'expires_at',
                      'revoked_at')

    class Meta:
        proxy = True
        ordering = ['-created_at']

    @property
    def is_active(self) -> bool:
        return self.revoked_at is None and self.expires_at > timezone.now()

    def revoke(self):
        if self.revoked_at is None:
            self.revoked_at = timezone.now()
            self.fcm_token = ''
            self.save(update_fields=['revoked_at', 'fcm_token'])

    def __str__(self):
        return f'MobileSession({self.user_id}, {self.device_name or self.platform})'


class Fido2Credential(SecurityRecord):
    KIND = SecurityRecord.KIND_PASSKEY
    KIND_DEFAULTS = {'name': 'Passkey'}
    objects = KindManager(SecurityRecord.KIND_PASSKEY)
    VISIBLE_FIELDS = ('id', 'user', 'credential_id', 'public_key', 'sign_count', 'transports', 'name', 'rp_id',
                      'created_at', 'last_used_at')

    class Meta:
        proxy = True


class TwoFactorConfig(SecurityRecord):
    METHOD_TOTP = 'totp'
    METHOD_FIDO2 = 'fido2'
    METHOD_EMAIL = 'email'
    METHOD_CHOICES = TWO_FA_METHOD_CHOICES

    KIND = SecurityRecord.KIND_TFCONFIG
    objects = KindManager(SecurityRecord.KIND_TFCONFIG)
    VISIBLE_FIELDS = ('id', 'user', 'totp_secret_encrypted', 'totp_confirmed', 'totp_last_step',
                      'email_otp_enabled', 'preferred_method', 'enabled_at', 'created_at', 'updated_at')

    class Meta:
        proxy = True

    def set_totp_secret(self, plain: str):
        self.totp_secret_encrypted = fernet.encrypt(plain.encode()).decode()

    def get_totp_secret(self) -> str:
        if not self.totp_secret_encrypted:
            return ''
        try:
            return fernet.decrypt(self.totp_secret_encrypted.encode()).decode()
        except Exception:
            return ''

    def available_methods(self):
        methods = []
        if self.totp_confirmed and self.totp_secret_encrypted:
            methods.append(self.METHOD_TOTP)
        if self.user.fido2_credentials.exists():
            methods.append(self.METHOD_FIDO2)
        if self.email_otp_enabled:
            methods.append(self.METHOD_EMAIL)
        return methods

    def __str__(self):
        return f'2FA({self.user_id}) enabled={bool(self.available_methods())}'


def sync_two_fa_flag(user):
    cfg = TwoFactorConfig.objects.filter(user=user).first()
    enabled = bool(cfg and cfg.available_methods())
    if user.two_fa_enabled != enabled:
        User.objects.filter(pk=user.pk).update(two_fa_enabled=enabled)
        user.two_fa_enabled = enabled
    return enabled


@receiver(pre_save, sender=User)
def set_updated_at_user(sender, instance, **kwargs):
    instance.updated_at = timezone.now()


@receiver(pre_save, sender=Device)
def set_updated_at_device(sender, instance, **kwargs):
    instance.updated_at = timezone.now()


AUTO_REGISTER_WINDOW_SECONDS = 60


@receiver(pre_save, sender=NfcReader)
def set_updated_at_nfc_reader(sender, instance, **kwargs):
    from datetime import timedelta
    now = timezone.now()
    instance.updated_at = now
    if instance.auto_register:
        if instance.auto_register_until is None:
            instance.auto_register_until = now + timedelta(seconds=AUTO_REGISTER_WINDOW_SECONDS)
        elif instance.auto_register_until <= now:
            instance.auto_register = False
            instance.auto_register_until = None
    else:
        instance.auto_register_until = None


@receiver(pre_save, sender=SystemSettings)
def set_updated_at_system_settings(sender, instance, **kwargs):
    instance.updated_at = timezone.now()
