# smartlock/models.py

from django.db import models
from django.utils import timezone
from django.contrib.auth.models import AbstractBaseUser, PermissionsMixin, BaseUserManager
from django.core.validators import MinValueValidator, MaxValueValidator, RegexValidator
from django.db.models.functions import Lower
from django.core.exceptions import ValidationError
from django.db.models.signals import pre_save, post_save
from django.dispatch import receiver
import uuid
import os
import hmac
import json  
import hashlib
from cryptography.fernet import Fernet

# ==================== CẤU HÌNH BÍ MẬT (FERNET) ====================
FERNET_KEY = os.environ.get("FERNET_KEY")
if not FERNET_KEY:
    raise RuntimeError(
        "Vui lòng khai báo biến FERNET_KEY trong .env!\n"
        "Tạo key bằng lệnh: python -c \"from cryptography.fernet import Fernet; print(Fernet.generate_key())\""
    )

fernet = Fernet(FERNET_KEY.encode())

# Pepper riêng (bí mật server) cho hash PIN cửa / mã chia sẻ / UID thẻ. BẮT BUỘC khai báo
# SHARE_CODE_PEPPER trong .env và phải KHÁC FERNET_KEY (tách khoá: lộ 1 khoá không kéo theo khoá kia).
# Chỉ khi DEBUG=True mới cho phép pepper tạm (dẫn xuất từ FERNET_KEY) để dev không bị kẹt.
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
    """HMAC-SHA256 keyed bằng pepper (thay cho SHA-256 nối chuỗi)."""
    return hmac.new(SHARE_CODE_PEPPER.encode(), f'{namespace}:{value}'.encode(), hashlib.sha256).hexdigest()


def hash_card_uid(uid: str) -> str:
    """Hash UID thẻ RFID (UID chỉ ~4 byte nên SHA-256 trần đảo ngược được ngay nếu lộ DB)."""
    return _pepper_hmac('carduid', uid)


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
    two_fa_enabled = models.BooleanField(
        default=False,
        help_text='True nếu user có ít nhất 1 phương thức 2FA đang hoạt động. '
                   'Được đồng bộ tự động bởi sync_two_fa_flag(), KHÔNG set tay.'
    )

    # --- Khoá đăng nhập tạm thời (trước đây là bảng LoginLockout, gộp vào User) ---
    login_failed_attempts = models.IntegerField(default=0)
    login_lock_stage = models.IntegerField(default=0)
    login_locked_until = models.DateTimeField(null=True, blank=True)
    login_last_failed_at = models.DateTimeField(null=True, blank=True)
    login_last_failed_ip = models.GenericIPAddressField(null=True, blank=True)

    class Meta:
        constraints = [
            # email/username không phân biệt hoa-thường (clean() chỉ chuẩn hoá ở tầng form, DB mới là chốt chặn).
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


class OneTimeCode(models.Model):
    """Mã/token dùng một lần có hạn. Gộp 2 bảng cũ EmailVerificationToken (link xác thực email...)
    và TwoFactorEmailCode (OTP 6 số của 2FA) - chỉ khác nhau ở cột `purpose`. Chỉ lưu hash."""
    PURPOSE_CHOICES = [
        ('EMAIL_VERIFY', 'Verify email'),
        ('PASSWORD_RESET', 'Password reset'),
        ('SUPPORT_AUTH', 'Support auth'),
        ('RECOVERY_CONFIRM', 'Recovery confirm'),
        ('UPDATE_INFO', 'Update info'),
        ('TF_SETUP', '2FA email - thiết lập'),
        ('TF_VERIFY', '2FA email - xác thực'),
    ]
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='one_time_codes')
    purpose = models.CharField(max_length=50, choices=PURPOSE_CHOICES)
    token_hash = models.CharField(max_length=255)
    attempts = models.IntegerField(default=0)
    is_used = models.BooleanField(default=False)
    used_at = models.DateTimeField(null=True, blank=True)
    expires_at = models.DateTimeField()
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        indexes = [models.Index(fields=['user', 'purpose', 'created_at'], name='idx_otc_user_purpose')]
        constraints = [
            models.CheckConstraint(check=models.Q(attempts__gte=0), name='chk_otc_attempts_nonneg'),
            # có used_at thì bắt buộc is_used=True (chiều ngược lại cho phép vì có chỗ chỉ .update(is_used=True)).
            models.CheckConstraint(check=models.Q(used_at__isnull=True) | models.Q(is_used=True),
                                   name='chk_otc_usedat_requires_used'),
        ]

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


# ==================== NHÓM B: THIẾT BỊ ====================
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

    # Các trạng thái hợp lệ để KHÔNG có owner (thiết bị chưa/không còn gán cho ai).
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
            # đã mua thì phải có thời điểm mua (mark_purchased() set cả hai).
            models.CheckConstraint(check=models.Q(is_purchased=False) | models.Q(purchased_at__isnull=False),
                                   name='chk_device_purchased_has_date'),
        ]

    def factory_reset(self, save=True):
        """
        Đưa thiết bị về trạng thái xuất xưởng: status='revoked' + owner=None CÙNG LÚC.
        Dùng hàm này thay vì set tay 2 field riêng lẻ ở view, để không còn xảy ra
        trường hợp quên set owner=None khi đổi status -> vi phạm chk_devices_owner_vs_status.
        """
        self.status = 'revoked'
        self.owner = None
        if save:
            self.save(update_fields=['status', 'owner', 'updated_at'])

    def mark_purchased(self, save=True):
        """Đánh dấu thiết bị đã được mua/kích hoạt chính thức (không set tay is_purchased
        + purchased_at riêng lẻ ở view, tránh quên set 1 trong 2 field như factory_reset)."""
        self.is_purchased = True
        self.purchased_at = timezone.now()
        if save:
            self.save(update_fields=['is_purchased', 'purchased_at', 'updated_at'])


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
        constraints = [
            models.CheckConstraint(check=models.Q(battery_level__gte=0, battery_level__lte=100),
                                   name='chk_statuslog_battery_range'),
        ]


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
    # Chia sẻ theo tài khoản (email/username), có hiệu lực NGAY - người nhận không cần xác nhận.
    # 'SHARE_CODE' chỉ còn là giá trị cũ trong các bản ghi đã tạo trước đây.
    source = models.CharField(
        max_length=20, default='DIRECT',
        choices=[('DIRECT', 'Chủ thiết bị chia sẻ trực tiếp'), ('SHARE_CODE', 'Mã chia sẻ (cũ)')]
    )
    valid_from = models.DateTimeField(default=timezone.now)
    expires_at = models.DateTimeField(null=True, blank=True)
    is_active = models.BooleanField(default=True)
    accepted = models.BooleanField(default=True)   # luôn True: chia sẻ không cần xác nhận
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


# ==================== NHÓM D: NFC READER & THẺ TỪ ====================
class NfcReader(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    device = models.ForeignKey(Device, on_delete=models.CASCADE)
    reader_mode = models.CharField(max_length=20, choices=[('physical', 'Physical'), ('simulated', 'Simulated')])
    name = models.CharField(max_length=100, blank=True, null=True)
    is_active = models.BooleanField(default=False)           
    last_seen_at = models.DateTimeField(null=True, blank=True)
    # --- Cấu hình đầu đọc (trước đây là bảng NfcReaderConfig, gộp vào đây) ---
    auto_register = models.BooleanField(default=False)
    # Đăng ký thẻ bằng cách quẹt tại đầu đọc chỉ có hiệu lực trong cửa sổ ngắn (tự tắt khi hết hạn).
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
        """Tương thích template cũ (reader.config.auto_register ...): cấu hình nay nằm ngay trên reader."""
        return self


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


# ==================== NHÓM G: XÁC THỰC 2 LỚP (2FA) ====================
class TwoFactorConfig(models.Model):
    """Cấu hình 2FA của 1 user (TOTP/Email). Trạng thái bật/tắt tổng thể không lưu ở đây
    mà lấy từ User.two_fa_enabled, luôn được đồng bộ bởi sync_two_fa_flag()."""
    METHOD_TOTP = 'totp'
    METHOD_FIDO2 = 'fido2'
    METHOD_EMAIL = 'email'
    METHOD_CHOICES = [
        (METHOD_TOTP, 'Google Authenticator (TOTP)'),
        (METHOD_FIDO2, 'Passkey / FIDO2'),
        (METHOD_EMAIL, 'Email OTP'),
    ]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='two_factor')
    totp_secret_encrypted = models.CharField(max_length=255, blank=True, default='')
    totp_confirmed = models.BooleanField(default=False)
    totp_last_step = models.BigIntegerField(default=0)          # chống dùng lại mã TOTP (replay)
    email_otp_enabled = models.BooleanField(default=False)
    preferred_method = models.CharField(max_length=10, choices=METHOD_CHOICES, blank=True, default='')
    enabled_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

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
        """Các phương thức đã thiết lập xong, theo thứ tự totp -> fido2 -> email."""
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
    """
    Nguồn sự thật DUY NHẤT cho 'user có đang bật 2FA hay không':
    True nếu có >= 1 phương thức 2FA khả dụng (đã confirm), ngược lại False.
    Gọi hàm này mỗi khi thêm/gỡ 1 phương thức (totp/email/passkey) để cột
    User.two_fa_enabled luôn khớp thực tế, tránh lệch dữ liệu như trước đây
    (khi is_enabled là 1 cờ set tay riêng, có thể quên set/reset).
    """
    cfg = TwoFactorConfig.objects.filter(user=user).first()
    enabled = bool(cfg and cfg.available_methods())
    if user.two_fa_enabled != enabled:
        User.objects.filter(pk=user.pk).update(two_fa_enabled=enabled)
        user.two_fa_enabled = enabled
    return enabled


class Fido2Credential(models.Model):
    """Passkey / khóa bảo mật FIDO2 (WebAuthn) của user."""
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='fido2_credentials')
    credential_id = models.CharField(max_length=512, unique=True)     # base64url
    public_key = models.BinaryField()
    sign_count = models.BigIntegerField(default=0)
    transports = models.JSONField(default=list, blank=True)
    name = models.CharField(max_length=100, default='Passkey')
    created_at = models.DateTimeField(auto_now_add=True)
    last_used_at = models.DateTimeField(null=True, blank=True)


# ==================== SIGNALS ====================
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
    # Bật auto_register => mở cửa sổ 60s; hết cửa sổ mà còn lưu lại => tự tắt.
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


# ==================== A2: MÃ PIN CỬA (KHÁCH THUÊ) ====================
def _hash_door_pin(device_id, plain_pin: str) -> str:
    """
    PIN chỉ có 4-6 chữ số => không được băm SHA-256 trần (dễ vét cạn 10^6 khả năng nếu
    lộ DB). Băm cùng device_id (salt theo từng thiết bị) + SHARE_CODE_PEPPER (bí mật
    server) để một PIN giống nhau ở 2 thiết bị khác nhau vẫn ra hash khác nhau, và kẻ
    tấn công không dò được bằng rainbow table dựng sẵn cho 1.000.000 mã 6 số.
    """
    return _pepper_hmac(f'doorpin:{device_id}', plain_pin)


class DoorPinCode(models.Model):
    """
    Mã PIN dùng một lần (OTP) do chủ nhà cấp từ xa cho khách thuê, nhập trực tiếp trên
    bàn phím ma trận 4x4 gắn ở khoá cửa. Đáp ứng đúng bài toán A2:
    "Chủ nhà cấp OTP từ xa cho 'khách thuê' -> nhập trên bàn phím -> mở được, hết hạn
    thì không mở" (kịch bản demo bắt buộc #3 của đề tài A2).
    """
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    device = models.ForeignKey(Device, on_delete=models.CASCADE, related_name='door_pins')
    created_by = models.ForeignKey(User, on_delete=models.RESTRICT, related_name='created_door_pins')
    label = models.CharField(max_length=100, blank=True, null=True, help_text='VD: "Khách Booking #123"')
    pin_hash = models.CharField(max_length=255)
    valid_from = models.DateTimeField(default=timezone.now)
    expires_at = models.DateTimeField()
    # 1 = mã dùng đúng 1 lần rồi hết hạn (khuyến nghị cho khách vãng lai);
    # 0 = không giới hạn số lần dùng trong thời hạn hiệu lực (khách thuê dài ngày).
    max_uses = models.IntegerField(default=1)
    use_count = models.IntegerField(default=0)
    is_revoked = models.BooleanField(default=False)
    revoked_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        indexes = [
            models.Index(fields=['device', 'expires_at'], name='idx_doorpin_dev_exp'),
        ]
        constraints = [
            models.CheckConstraint(check=models.Q(max_uses__gte=0, use_count__gte=0),
                                   name='chk_doorpin_uses_nonneg'),
            models.CheckConstraint(check=models.Q(expires_at__gt=models.F('valid_from')),
                                   name='chk_doorpin_expiry'),
            models.CheckConstraint(check=models.Q(is_revoked=False) | models.Q(revoked_at__isnull=False),
                                   name='chk_doorpin_revoked_has_date'),
        ]

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


# ==================== A2: NHẬN DIỆN KHUÔN MẶT TẠI BIÊN ====================
class FaceProfile(models.Model):
    """
    Đặc trưng khuôn mặt (embedding) của 1 thành viên được phép mở cửa bằng nhận diện
    khuôn mặt. ESP32-CAM chụp ảnh -> trích embedding (tại biên hoặc gửi ảnh lên server
    suy luận) -> so khớp với các FaceProfile.is_active=True của device đó.

    Dữ liệu sinh trắc học là dữ liệu cá nhân nhạy cảm theo Nghị định 13/2023/NĐ-CP =>
    embedding LUÔN được mã hoá (Fernet) trước khi lưu, không bao giờ lưu vector thô.
    """
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='face_profiles')
    device = models.ForeignKey(Device, on_delete=models.CASCADE, related_name='face_profiles')
    name = models.CharField(max_length=100, blank=True, null=True)
    embedding_encrypted = models.BinaryField(
        help_text='Vector đặc trưng khuôn mặt (vd. 128 chiều), đã mã hoá Fernet.'
    )
    # Với embedding chuẩn hoá (facenet/dlib): khoảng cách Euclid < threshold => coi là khớp.
    threshold = models.FloatField(default=0.6)
    consent_confirmed = models.BooleanField(
        default=False,
        help_text='Xác nhận người này đã đồng ý được thu thập dữ liệu khuôn mặt (bắt buộc theo NĐ 13/2023).'
    )
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        constraints = [
            models.UniqueConstraint(fields=['user', 'device'], name='uniq_faceprofile_user_device'),
            models.CheckConstraint(check=models.Q(threshold__gt=0, threshold__lte=2),
                                   name='chk_face_threshold_range'),
            # NĐ 13/2023: hồ sơ khuôn mặt chỉ được BẬT khi đã có sự đồng ý.
            models.CheckConstraint(check=models.Q(is_active=False) | models.Q(consent_confirmed=True),
                                   name='chk_face_active_requires_consent'),
        ]

    def set_embedding(self, vector) -> None:
        raw = json.dumps(list(vector)).encode()
        self.embedding_encrypted = fernet.encrypt(raw)

    def get_embedding(self) -> list:
        try:
            return json.loads(fernet.decrypt(bytes(self.embedding_encrypted)).decode())
        except Exception:
            return []


# ==================== A2: LOG HỢP NHẤT MỌI LƯỢT MỞ CỬA ====================
class AccessEvent(models.Model):
    """
    Log hợp nhất cho MỌI lượt mở cửa thành công/thất bại của A2, dù qua kênh nào (RFID
    / PIN / khuôn mặt / Bluetooth) - phục vụ đúng yêu cầu "toàn bộ lượt ra/vào được ghi log về máy
    chủ" và trang "xem lịch sử ra vào kèm ảnh chụp" của đề tài A2.

    NfcLog (model gốc) vẫn giữ nguyên riêng cho sự kiện đầu đọc NFC ở tầng thấp
    (reader connect/disconnect, config...). AccessEvent là log nghiệp vụ cấp cao hơn,
    dùng cho khoá tạm khi sai liên tiếp (services.py) và cho giao diện lịch sử ra vào.
    """
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
    device = models.ForeignKey(Device, on_delete=models.CASCADE, related_name='access_events')
    method = models.CharField(max_length=10, choices=METHOD_CHOICES)
    success = models.BooleanField()
    reason = models.CharField(max_length=100, blank=True, null=True, help_text='Lý do thất bại, nếu có.')
    user = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True)
    access_card = models.ForeignKey(AccessCard, on_delete=models.SET_NULL, null=True, blank=True)
    door_pin = models.ForeignKey(DoorPinCode, on_delete=models.SET_NULL, null=True, blank=True)
    face_profile = models.ForeignKey(FaceProfile, on_delete=models.SET_NULL, null=True, blank=True)
    confidence = models.FloatField(null=True, blank=True, help_text='Độ tin cậy nhận diện khuôn mặt (nếu có).')
    snapshot_url = models.URLField(
        max_length=512, blank=True, null=True,
        help_text='Ảnh chụp lúc mở cửa, lưu ở object storage (MinIO/S3), khuyến nghị giữ tối đa 30 ngày.'
    )
    ip_address = models.GenericIPAddressField(blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        indexes = [
            models.Index(fields=['device', 'created_at'], name='idx_accessevt_dev_time'),
            models.Index(fields=['device', 'method', 'success', 'created_at'], name='idx_accessevt_method_ok'),
        ]

    def __str__(self):
        return f'{self.get_method_display()} - {"OK" if self.success else "FAIL"} @ {self.device_id}'

# ==================== PHIÊN ĐĂNG NHẬP APP DI ĐỘNG ====================
class MobileSession(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='mobile_sessions')

    refresh_hash = models.CharField(max_length=64, unique=True)
    prev_refresh_hash = models.CharField(max_length=64, blank=True, default='', db_index=True)

    device_name = models.CharField(max_length=100, blank=True, default='')
    platform = models.CharField(max_length=20, default='android')
    app_version = models.CharField(max_length=30, blank=True, default='')

    fcm_token = models.CharField(max_length=512, blank=True, default='', db_index=True)
    push_enabled = models.BooleanField(default=True)

    ip_address = models.GenericIPAddressField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    last_used_at = models.DateTimeField(null=True, blank=True)
    expires_at = models.DateTimeField()
    revoked_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        indexes = [models.Index(fields=['user', 'revoked_at'], name='idx_mobsess_user_rev')]
        constraints = [
            models.CheckConstraint(check=models.Q(expires_at__gt=models.F('created_at')),
                                   name='chk_mobsession_expiry'),
        ]
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