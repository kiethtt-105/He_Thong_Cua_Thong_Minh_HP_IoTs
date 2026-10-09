# smartlock/models.py
"""
=====================================================================================================
SMARTLOCK - MODELS (bản đã GỘP BẢNG: 21 bảng -> 13 bảng, KHÔNG đổi cách code khác gọi model)
=====================================================================================================

CÁCH GỘP (đọc kỹ phần này trước khi sửa model)
----------------------------------------------
Các bảng "cùng họ" được gộp vào 1 bảng thật (concrete model) có thêm cột `kind` để phân loại dòng.
Tên model CŨ vẫn còn nguyên dưới dạng PROXY MODEL (Meta.proxy = True): proxy không có bảng riêng, nó chỉ là
"cái nhìn" lên bảng thật và tự lọc `kind` của mình. Vì vậy mọi nơi khác trong dự án (services.py, views.py,
admin.py, api/...) vẫn viết y như cũ, KHÔNG phải sửa gì:

    AuditLog.objects.filter(action='LOGIN_OK')        # tự thêm  WHERE kind = 'AUDIT'
    NfcLog.objects.create(reader=r, device=d, ...)     # tự gán   kind = 'NFC'
    MobileSession.objects.create(user=u, ...)          # tự gán   kind = 'SESSION'
    user.fido2_credentials.count()                     # property tương thích trên User

Hai cơ chế dùng chung (xem KindManager / KindModel bên dưới):
  * KindManager  : manager của proxy, luôn lọc đúng `kind` của proxy đó.
  * KindModel    : khi tạo object mới bằng kwargs, tự điền `kind` + các giá trị mặc định riêng của loại đó.

BẢNG THẬT (13)                      GỘP TỪ (tên model cũ vẫn dùng được qua proxy)
  1. User                           User  (đã gộp LoginLockout từ trước)
  2. SystemSettings                 -
  3. Announcement                   -
  4. Device                         -
  5. DeviceCommand                  -
  6. Permission                     -
  7. DeviceAccess                   -   (+ bảng M2M phụ DeviceAccess<->Permission do Django tự tạo)
  8. NfcReader                      -   (đã gộp NfcReaderConfig từ trước)
  9. CardDeviceAccess               -
 10. Notification                   -
 11. ActivityLog                    AuditLog + NfcLog + AccessEvent + DeviceStatusLog     (4 -> 1)
 12. AccessCredential               AccessCard + DoorPinCode + FaceProfile                (3 -> 1)
 13. SecurityRecord                 OneTimeCode + MobileSession + Fido2Credential + TwoFactorConfig  (4 -> 1)

Vì sao dừng ở 13 mà không ép về 10? 3 bảng nữa (SystemSettings, Permission/Announcement, CardDeviceAccess) chỉ gộp
được nếu SỬA code (khoá chính khác kiểu, bảng M2M, quan hệ N-N) -> trái yêu cầu "không đổi hệ thống".
"""

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


def _hash_door_pin(device_id, plain_pin: str) -> str:
    """
    PIN chỉ có 4-6 chữ số => không được băm SHA-256 trần (dễ vét cạn 10^6 khả năng nếu
    lộ DB). Băm cùng device_id (salt theo từng thiết bị) + SHARE_CODE_PEPPER (bí mật
    server) để một PIN giống nhau ở 2 thiết bị khác nhau vẫn ra hash khác nhau, và kẻ
    tấn công không dò được bằng rainbow table dựng sẵn cho 1.000.000 mã 6 số.
    """
    return _pepper_hmac(f'doorpin:{device_id}', plain_pin)


# ==================== HẠ TẦNG GỘP BẢNG: KindManager + KindModel ====================
class KindManager(models.Manager):
    """Manager của PROXY model: mọi truy vấn tự thêm `WHERE kind = <KIND của proxy>`.
    Nhờ vậy `AuditLog.objects.all()` chỉ thấy dòng AUDIT dù chung bảng smartlock_activitylog với NFC/ACCESS/STATUS.
    Cũng áp dụng cho .count(), .update(), .delete(), get_or_create(), select_for_update()... (đều đi qua queryset này)."""

    def __init__(self, kind):
        super().__init__()
        self._kind = kind

    def get_queryset(self):
        return super().get_queryset().filter(kind=self._kind)


class KindModel(models.Model):
    """Lớp cha (abstract) của 3 bảng thật được gộp. Mỗi proxy khai báo:
        KIND          : giá trị cột `kind` của loại này.
        KIND_DEFAULTS : {tên_cột: giá trị | hàm} - mặc định RIÊNG của loại này (thay cho default của model cũ,
                        vì cột dùng chung không thể có default khác nhau theo loại).
    Khi tạo object MỚI bằng kwargs (vd. NfcLog(reader=...), objects.create(...), get_or_create(...)) thì `kind` và các
    mặc định trên được điền tự động. Khi nạp từ DB (from_db gọi cls(*values) - tham số vị trí) thì KHÔNG đụng vào."""
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


# =====================================================================================================
# BẢNG 1/13 - User  (smartlock_user)
# -----------------------------------------------------------------------------------------------------
# Tài khoản đăng nhập (web + app). Khoá chính UUID, đăng nhập bằng email. Email/username KHÔNG phân biệt hoa-thường
# (ràng buộc Lower() ở DB). Có sẵn cờ phân quyền Django (is_staff/is_superuser) + is_admin (admin nghiệp vụ).
# Cột login_* : khoá đăng nhập tạm khi sai mật khẩu nhiều lần (trước là bảng LoginLockout, đã gộp từ trước).
# two_fa_enabled: cờ "đang bật 2FA" - CHỈ được ghi bởi sync_two_fa_flag(), không set tay.
# Các thuộc tính cuối class (two_factor, fido2_credentials...) là lối tắt TƯƠNG THÍCH cho các bảng đã gộp
# (trước đây là related_name của ForeignKey; nay các FK đó related_name='+' nên cần property thay thế).
# =====================================================================================================
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

    # ---- Lối tắt tương thích cho các related_name cũ (các bảng đã gộp vào ActivityLog/AccessCredential/SecurityRecord) ----
    # Trả về queryset nên .count() / .exists() / .filter() / .all() dùng y như reverse manager cũ.
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
        """Giống reverse OneToOne cũ: không có cấu hình thì raise TwoFactorConfig.DoesNotExist."""
        cfg = TwoFactorConfig.objects.filter(user=self).first()
        if cfg is None:
            raise TwoFactorConfig.DoesNotExist('User chưa có cấu hình 2FA.')
        return cfg


# =====================================================================================================
# BẢNG 2/13 - SystemSettings  (smartlock_systemsettings)
# -----------------------------------------------------------------------------------------------------
# Cấu hình toàn hệ thống, SINGLETON: luôn đúng 1 dòng id=1 (CheckConstraint chk_settings_singleton).
# Gồm: mở/đóng đăng ký, hạn token xác thực email, hạn mã chia sẻ, các mốc phút khoá đăng nhập, thời gian phiên.
# Dùng qua services.system_settings() (get_or_create(pk=1)). Giữ riêng vì khoá chính SmallInteger=1,
# khác kiểu khoá UUID của mọi bảng khác.
# =====================================================================================================
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


# =====================================================================================================
# BẢNG 3/13 - Announcement  (smartlock_announcement)
# -----------------------------------------------------------------------------------------------------
# Thông báo CHUNG của hệ thống do admin đăng (hiện ở dashboard web/app), có mức info/warning/danger và cờ is_active.
# Khác Notification (bảng 10): Announcement gửi cho TẤT CẢ, không thuộc user nào, không có trạng thái "đã đọc".
# =====================================================================================================
class Announcement(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    title = models.CharField(max_length=200)
    body = models.TextField()
    level = models.CharField(max_length=10, default='info', choices=[('info', 'Info'), ('warning', 'Warning'), ('danger', 'Danger')])
    created_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True)
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)

# ==================== NHÓM B: THIẾT BỊ ====================
# =====================================================================================================
# BẢNG 4/13 - Device  (smartlock_device)
# -----------------------------------------------------------------------------------------------------
# Một ổ khoá thông minh (ESP32) - bảng TRUNG TÂM, hầu hết bảng khác trỏ vào đây.
# device_code + provisioning_secret_hash : định danh / bí mật để thiết bị xác thực với server (chỉ lưu hash).
# owner        : chủ khoá (RESTRICT: không xoá được user còn sở hữu khoá). Khoá ở trạng thái provisioning/revoked
#                BẮT BUỘC owner=NULL, các trạng thái còn lại BẮT BUỘC có owner (chk_devices_owner_vs_status).
# status       : online/offline/maintenance/provisioning/revoked. battery_level 0-100.
# is_purchased : đã bán/kích hoạt chính thức (khác thiết bị demo) - luôn đi cùng purchased_at (mark_purchased()).
# bluetooth/wifi/nfc_enabled : bật/tắt từng kênh kết nối. factory_reset(): đưa về revoked + bỏ chủ cùng lúc.
# Các property cuối class (access_events, door_pins, face_profiles) = lối tắt tương thích cho related_name cũ.
# =====================================================================================================
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

    # ---- Lối tắt tương thích related_name cũ (các bảng đã gộp) ----
    @property
    def access_events(self):
        return AccessEvent.objects.filter(device=self)

    @property
    def door_pins(self):
        return DoorPinCode.objects.filter(device=self)

    @property
    def face_profiles(self):
        return FaceProfile.objects.filter(device=self)


# =====================================================================================================
# BẢNG 5/13 - DeviceCommand  (smartlock_devicecommand)
# -----------------------------------------------------------------------------------------------------
# Hàng đợi LỆNH gửi xuống thiết bị (LOCK/UNLOCK/ADD_CARD/REMOVE_CARD/RESET/OTA_UPDATE/REBOOT/PING).
# Vòng đời: pending -> sent -> acknowledged | failed | expired. Lệnh có hạn (expires_at, xem COMMAND_TTL_SECONDS).
# command_token_hash : token một lần để thiết bị xác nhận lệnh (chỉ lưu hash). issued_by: người ra lệnh (RESTRICT).
# Giữ riêng (không gộp vào ActivityLog) vì có vòng đời trạng thái, bị UPDATE liên tục và thiết bị phải đọc nhanh.
# =====================================================================================================
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
# =====================================================================================================
# BẢNG 6/13 - Permission  (smartlock_permission)
# -----------------------------------------------------------------------------------------------------
# Danh mục MÃ QUYỀN (LOCK, UNLOCK, view_history, manage_nfc, manage_face_profiles...). Dữ liệu danh mục, sinh từ
# services (PERMISSION_CODES), admin chỉ xem. is_sensitive=True: quyền nhạy cảm (vd. quản lý khuôn mặt).
# Được DeviceAccess.permissions (N-N) trỏ tới nên giữ bảng riêng.
# =====================================================================================================
class Permission(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    code = models.CharField(max_length=50, unique=True)
    name = models.CharField(max_length=100)
    description = models.TextField(blank=True, null=True)
    is_sensitive = models.BooleanField(default=False)

    def __str__(self):
        return f"{self.code} - {self.name}"


# =====================================================================================================
# BẢNG 7/13 - DeviceAccess  (smartlock_deviceaccess (+ smartlock_deviceaccess_permissions))
# -----------------------------------------------------------------------------------------------------
# QUYỀN CHIA SẺ khoá cho người khác: "user X được dùng khoá Y với các quyền Z trong khoảng thời gian T".
# permissions : N-N tới Permission -> Django tự sinh bảng phụ smartlock_deviceaccess_permissions (bảng #14, không đếm là model).
# Chia sẻ theo tài khoản, CÓ HIỆU LỰC NGAY (accepted luôn True). source='SHARE_CODE' chỉ còn ở bản ghi cũ.
# Ràng buộc: expires_at > valid_from; mỗi (device,user) chỉ có TỐI ĐA 1 bản ghi is_active=True (uniq_active_device_access).
# created_by (RESTRICT) = người chia sẻ, thường là chủ khoá.
# =====================================================================================================
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


# ==================== NHÓM D: ĐẦU ĐỌC NFC & THẺ TỪ ====================
# =====================================================================================================
# BẢNG 8/13 - NfcReader  (smartlock_nfcreader)
# -----------------------------------------------------------------------------------------------------
# Đầu đọc NFC/RFID gắn với 1 khoá (thật hoặc mô phỏng). Một khoá có thể có nhiều đầu đọc.
# Cấu hình đầu đọc nằm ngay đây (trước là bảng NfcReaderConfig): auto_register = cho phép "quẹt thẻ lạ để đăng ký",
# CHỈ có hiệu lực trong cửa sổ ngắn auto_register_until (signal pre_save bên dưới tự mở 60s / tự tắt khi hết hạn);
# grant_permission = quyền gán cho thẻ mới; valid_from/expires_at = hiệu lực của đầu đọc.
# =====================================================================================================
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


# =====================================================================================================
# BẢNG 9/13 - CardDeviceAccess  (smartlock_carddeviceaccess)
# -----------------------------------------------------------------------------------------------------
# Bảng NỐI "thẻ nào mở được khoá nào" (N-N giữa AccessCard và Device); is_active=False = thu hồi thẻ khỏi khoá đó.
# Mỗi cặp (thẻ, khoá) chỉ 1 dòng (uniq_card_device). Một thẻ của user có thể mở nhiều khoá.
# LƯU Ý sau khi gộp: FK access_card trỏ tới bảng thật AccessCredential (AccessCard chỉ là proxy lọc kind='CARD').
# Reverse `card.carddeviceaccess_set` vẫn dùng được trên AccessCard (proxy thừa kế từ AccessCredential).
# =====================================================================================================
class CardDeviceAccess(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    access_card = models.ForeignKey('AccessCredential', on_delete=models.CASCADE)   # chỉ nên trỏ tới dòng kind='CARD'
    device = models.ForeignKey(Device, on_delete=models.CASCADE)
    created_at = models.DateTimeField(auto_now_add=True)
    is_active = models.BooleanField(default=True)

    class Meta:
        constraints = [models.UniqueConstraint(fields=['access_card', 'device'], name='uniq_card_device')]


# ==================== NHÓM E: THÔNG BÁO ====================
# =====================================================================================================
# BẢNG 10/13 - Notification  (smartlock_notification)
# -----------------------------------------------------------------------------------------------------
# Thông báo gửi RIÊNG cho 1 user (cảnh báo bảo mật, khoá mở/đóng, pin yếu...). Có severity info/warning/critical,
# is_read/read_at (ràng buộc: có read_at thì is_read phải True). Mỗi Notification mới -> signal post_save
# (services.register_signals) đẩy FCM tới các MobileSession còn hạn của user. device có thể NULL (thông báo chung).
# Giữ riêng (không gộp với Announcement) vì có trạng thái đã-đọc theo từng user và kích hoạt push.
# =====================================================================================================
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

# =====================================================================================================
# BẢNG 11/13 - ActivityLog  (smartlock_activitylog)          *** GỘP 4 BẢNG LOG ***
# -----------------------------------------------------------------------------------------------------
# Một bảng NHẬT KÝ duy nhất, phân loại bằng cột `kind`. Mỗi loại dùng một nhóm cột riêng, các cột còn lại để
# NULL / giá trị rỗng. Tên model cũ còn nguyên dưới dạng proxy (xem cuối phần này):
#
#   kind    proxy (tên cũ)   Ý nghĩa                                          Nhóm cột dùng
#   ------  ---------------  -----------------------------------------------  ------------------------------------------
#   AUDIT   AuditLog         Nhật ký bảo mật/quản trị: đăng nhập, đổi mật     actor_user, target_user, device, action,
#                            khẩu, thao tác admin, 2FA, thu hồi phiên...       username_attempt, severity, success,
#                                                                              ip_address, user_agent, metadata
#   NFC     NfcLog           Sự kiện tầng thấp của đầu đọc NFC: quẹt thẻ,     reader, nfc_tag, device, user, event_type,
#                            đăng ký thẻ, kết nối/ngắt đầu đọc, đổi cấu hình   success, ip_address, user_agent, metadata
#   ACCESS  AccessEvent      Log nghiệp vụ MỌI lượt mở cửa (RFID/PIN/FACE/    device, method, success, reason, user,
#                            BLE/NFC điện thoại) - dùng cho trang lịch sử      access_card, door_pin, face_profile,
#                            ra vào và cho cơ chế khoá tạm khi sai liên tiếp   confidence, snapshot_url, ip_address
#   STATUS  DeviceStatusLog  Bản tin trạng thái định kỳ của thiết bị:         device, battery_level, signal_strength,
#                            pin, sóng, khoá đóng/mở, chống tháo, nhiệt độ     lock_state, tamper_detected, temperature,
#                                                                              raw_payload, recorded_at
#
# Điểm cần nhớ:
#  * created_at: thời điểm ghi (mọi loại). recorded_at: CHỈ loại STATUS (giữ nguyên tên cột cũ vì code sắp xếp theo nó).
#  * device: SET_NULL (giữ log khi xoá khoá) - RIÊNG loại ACCESS và STATUS trước đây là CASCADE (xoá khoá thì xoá
#    luôn log) nên có signal pre_delete(Device) ở cuối file để giữ đúng hành vi cũ.
#  * Các FK tới thẻ/PIN/khuôn mặt đều trỏ tới AccessCredential (bảng 12), related_name riêng để khỏi trùng nhau.
#  * Ràng buộc "bắt buộc" của từng loại (vd. STATUS phải có battery_level + lock_state, ACCESS phải có method) được
#    chuyển thành CheckConstraint có điều kiện theo kind, vì cột dùng chung buộc phải cho phép NULL/rỗng.
#  * Bảng append-only, tăng nhanh: nên dọn định kỳ (STATUS và ACCESS có snapshot_url theo kind).
# =====================================================================================================
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
    # Loại dòng log (AUDIT/NFC/ACCESS/STATUS). Proxy tự điền, KHÔNG set tay.
    kind = models.CharField(max_length=10, choices=KIND_CHOICES)

    # ---- Cột dùng CHUNG nhiều loại ----
    device = models.ForeignKey(Device, on_delete=models.SET_NULL, null=True, blank=True,
                               related_name='activity_logs')                       # AUDIT/NFC/ACCESS/STATUS
    user = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True,
                             related_name='activity_logs')                         # NFC/ACCESS: người liên quan
    success = models.BooleanField(default=True)                                    # AUDIT/NFC/ACCESS
    severity = models.CharField(max_length=20, default='info', choices=SEVERITY_CHOICES)   # AUDIT
    ip_address = models.GenericIPAddressField(blank=True, null=True)               # AUDIT/NFC/ACCESS
    user_agent = models.TextField(blank=True, null=True)                           # AUDIT/NFC
    metadata = models.JSONField(null=True, blank=True)                             # AUDIT/NFC: dữ liệu mở rộng

    # ---- Riêng AUDIT (AuditLog) ----
    actor_user = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True,
                                   related_name='audit_logs_actor')                # ai thực hiện
    target_user = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True,
                                    related_name='audit_logs_target')              # ai bị tác động
    action = models.CharField(max_length=50, blank=True, default='')               # mã hành động, vd. LOGIN_OK
    username_attempt = models.CharField(max_length=150, blank=True, null=True)     # tên đăng nhập đã thử (đăng nhập sai)

    # ---- Riêng NFC (NfcLog) ----
    reader = models.ForeignKey('NfcReader', on_delete=models.SET_NULL, null=True, blank=True,
                               related_name='activity_logs')
    nfc_tag = models.ForeignKey('AccessCredential', on_delete=models.SET_NULL, null=True, blank=True,
                                related_name='nfc_logs')                           # thẻ (kind='CARD')
    event_type = models.CharField(max_length=50, blank=True, default='', choices=NFC_EVENT_CHOICES)

    # ---- Riêng ACCESS (AccessEvent) ----
    method = models.CharField(max_length=10, blank=True, default='', choices=METHOD_CHOICES)   # kênh mở cửa
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

    # ---- Riêng STATUS (DeviceStatusLog) ----
    battery_level = models.IntegerField(null=True, blank=True,
                                        validators=[MinValueValidator(0), MaxValueValidator(100)])
    signal_strength = models.IntegerField(null=True, blank=True)
    lock_state = models.CharField(max_length=20, blank=True, default='', choices=LOCK_STATE_CHOICES)
    tamper_detected = models.BooleanField(default=False)
    temperature = models.DecimalField(max_digits=4, decimal_places=1, null=True, blank=True)
    raw_payload = models.JSONField(null=True, blank=True)
    recorded_at = models.DateTimeField(null=True, blank=True)    # giờ ghi của bản tin STATUS (proxy tự điền = now)

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
            # STATUS: bắt buộc có pin + trạng thái khoá (như DeviceStatusLog cũ).
            models.CheckConstraint(
                check=~models.Q(kind='STATUS') |
                      (models.Q(battery_level__isnull=False) & ~models.Q(lock_state='')),
                name='chk_actlog_status_required'),
            # ACCESS: bắt buộc có kênh mở cửa (như AccessEvent cũ).
            models.CheckConstraint(check=~models.Q(kind='ACCESS') | ~models.Q(method=''),
                                   name='chk_actlog_access_method'),
        ]


@receiver(pre_delete, sender=Device)
def delete_device_bound_logs(sender, instance, **kwargs):
    """Giữ đúng hành vi cũ: AccessEvent và DeviceStatusLog từng on_delete=CASCADE theo Device (xoá khoá -> xoá log
    ra vào + log trạng thái của khoá đó), còn AuditLog/NfcLog là SET_NULL (giữ lại). Cột device của bảng gộp là
    SET_NULL nên phải xoá 2 loại kia bằng tay ở đây."""
    ActivityLog.objects.filter(device=instance,
                               kind__in=[ActivityLog.KIND_ACCESS, ActivityLog.KIND_STATUS]).delete()


# ---- 4 PROXY của ActivityLog: giữ nguyên tên model cũ, không có bảng riêng ----
class AuditLog(ActivityLog):
    """Nhật ký bảo mật & quản trị (kind='AUDIT'). Xem services.audit()."""
    KIND = ActivityLog.KIND_AUDIT
    objects = KindManager(ActivityLog.KIND_AUDIT)
    # Cột có nghĩa với loại này (dùng cho admin: ẩn các cột của loại khác).
    VISIBLE_FIELDS = ('id', 'actor_user', 'target_user', 'device', 'action', 'username_attempt', 'severity',
                      'success', 'ip_address', 'user_agent', 'metadata', 'created_at')

    class Meta:
        proxy = True


class NfcLog(ActivityLog):
    """Log tầng thấp của đầu đọc NFC (kind='NFC')."""
    KIND = ActivityLog.KIND_NFC
    objects = KindManager(ActivityLog.KIND_NFC)
    VISIBLE_FIELDS = ('id', 'reader', 'nfc_tag', 'device', 'user', 'event_type', 'success', 'ip_address',
                      'user_agent', 'metadata', 'created_at')

    class Meta:
        proxy = True


class AccessEvent(ActivityLog):
    """Log hợp nhất MỌI lượt mở cửa thành công/thất bại, dù qua kênh nào (kind='ACCESS').
    Phục vụ "toàn bộ lượt ra/vào được ghi về máy chủ", trang lịch sử ra vào kèm ảnh chụp và cơ chế khoá tạm khi
    sai liên tiếp (services.py). NfcLog vẫn là log riêng cho sự kiện đầu đọc ở tầng thấp."""
    KIND = ActivityLog.KIND_ACCESS
    objects = KindManager(ActivityLog.KIND_ACCESS)
    VISIBLE_FIELDS = ('id', 'device', 'method', 'success', 'reason', 'user', 'access_card', 'door_pin',
                      'face_profile', 'confidence', 'snapshot_url', 'ip_address', 'created_at')

    class Meta:
        proxy = True

    def __str__(self):
        return f'{self.get_method_display()} - {"OK" if self.success else "FAIL"} @ {self.device_id}'


class DeviceStatusLog(ActivityLog):
    """Bản tin trạng thái định kỳ của thiết bị (kind='STATUS'). recorded_at tự = now khi tạo mới (như auto_now_add cũ)."""
    KIND = ActivityLog.KIND_STATUS
    KIND_DEFAULTS = {'recorded_at': timezone.now}
    objects = KindManager(ActivityLog.KIND_STATUS)
    VISIBLE_FIELDS = ('id', 'device', 'battery_level', 'signal_strength', 'lock_state', 'tamper_detected',
                      'temperature', 'raw_payload', 'recorded_at')

    class Meta:
        proxy = True


# =====================================================================================================
# BẢNG 12/13 - AccessCredential  (smartlock_accesscredential)     *** GỘP 3 BẢNG "CÁCH MỞ CỬA" ***
# -----------------------------------------------------------------------------------------------------
# Mọi thứ dùng để MỞ cửa mà server phải lưu: thẻ RFID, mã PIN khách thuê, hồ sơ khuôn mặt. Phân loại bằng `kind`:
#
#   kind   proxy (tên cũ)  Ý nghĩa                                              Cột dùng
#   -----  --------------  ---------------------------------------------------  --------------------------------------
#   CARD   AccessCard      Thẻ RFID của 1 user (mở được nhiều khoá, qua bảng    user, name, card_uid_hash, is_active
#                          nối CardDeviceAccess - bảng 9)
#   PIN    DoorPinCode     Mã PIN dùng-1-lần/có-hạn chủ nhà cấp từ xa cho khách  device, created_by, label, pin_hash,
#                          thuê, nhập trên bàn phím ma trận 4x4 (đề tài A2)      valid_from, expires_at, max_uses,
#                                                                                use_count, is_revoked, revoked_at
#   FACE   FaceProfile     Embedding khuôn mặt (MÃ HOÁ Fernet) của 1 thành      user, device, name, embedding_encrypted,
#                          viên được mở cửa bằng nhận diện khuôn mặt             threshold, consent_confirmed, is_active
#
# Bảo mật: card_uid_hash = HMAC(pepper, UID); pin_hash = HMAC(pepper, device_id:PIN) (salt theo từng khoá);
# embedding_encrypted = Fernet. KHÔNG bao giờ lưu UID/PIN/vector ở dạng thô. Sinh trắc học bị chặn bật nếu chưa có
# consent_confirmed (NĐ 13/2023) - chk_cred_face_active_consent.
# Các FK: user CASCADE (CARD/FACE), created_by RESTRICT (PIN - không xoá được người đã cấp mã), device CASCADE (PIN/FACE).
# =====================================================================================================
class AccessCredential(KindModel):
    KIND_CARD = 'CARD'
    KIND_PIN = 'PIN'
    KIND_FACE = 'FACE'
    KIND_CHOICES = [(KIND_CARD, 'Thẻ RFID'), (KIND_PIN, 'Mã PIN'), (KIND_FACE, 'Khuôn mặt')]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    kind = models.CharField(max_length=10, choices=KIND_CHOICES)

    # ---- Chủ sở hữu / gắn thiết bị (related_name='+': tra ngược dùng property trên User/Device) ----
    user = models.ForeignKey(User, on_delete=models.CASCADE, null=True, blank=True, related_name='+')          # CARD, FACE
    created_by = models.ForeignKey(User, on_delete=models.RESTRICT, null=True, blank=True, related_name='+')  # PIN
    device = models.ForeignKey(Device, on_delete=models.CASCADE, null=True, blank=True, related_name='+')     # PIN, FACE

    # ---- Nhãn ----
    name = models.CharField(max_length=100, blank=True, null=True)                 # CARD, FACE
    label = models.CharField(max_length=100, blank=True, null=True, help_text='VD: "Khách Booking #123"')   # PIN

    # ---- Bí mật đã băm/mã hoá (mỗi loại dùng đúng 1 cột) ----
    card_uid_hash = models.CharField(max_length=255, blank=True, null=True)        # CARD
    pin_hash = models.CharField(max_length=255, blank=True, null=True)             # PIN
    embedding_encrypted = models.BinaryField(
        null=True, blank=True,
        help_text='Vector đặc trưng khuôn mặt (vd. 128 chiều), đã mã hoá Fernet.')   # FACE

    # ---- Hiệu lực & số lần dùng (PIN) ----
    valid_from = models.DateTimeField(null=True, blank=True)        # PIN: proxy tự điền = now
    expires_at = models.DateTimeField(null=True, blank=True)        # PIN: bắt buộc
    # 1 = dùng đúng 1 lần rồi hết hạn (khách vãng lai); 0 = không giới hạn lượt trong thời hạn (khách thuê dài ngày).
    max_uses = models.IntegerField(default=1)
    use_count = models.IntegerField(default=0)
    is_revoked = models.BooleanField(default=False)
    revoked_at = models.DateTimeField(null=True, blank=True)

    # ---- Riêng khuôn mặt (FACE) ----
    # Embedding chuẩn hoá (facenet/dlib): khoảng cách Euclid < threshold => khớp.
    threshold = models.FloatField(default=0.6)
    consent_confirmed = models.BooleanField(
        default=False,
        help_text='Xác nhận người này đã đồng ý được thu thập dữ liệu khuôn mặt (bắt buộc theo NĐ 13/2023).')

    # ---- Trạng thái chung (CARD, FACE) ----
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
            # CARD: UID thẻ duy nhất toàn hệ thống (như AccessCard.card_uid_hash unique cũ) + bắt buộc có chủ.
            models.UniqueConstraint(fields=['card_uid_hash'], condition=models.Q(kind='CARD'),
                                    name='uniq_cred_card_uid'),
            models.CheckConstraint(
                check=~models.Q(kind='CARD') |
                      (models.Q(card_uid_hash__isnull=False) & models.Q(user__isnull=False)),
                name='chk_cred_card_required'),
            # PIN
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
            # FACE: mỗi (user, device) 1 hồ sơ; threshold hợp lệ; chỉ được BẬT khi đã đồng ý (NĐ 13/2023).
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


# ---- 3 PROXY của AccessCredential ----
class AccessCard(AccessCredential):
    """Thẻ RFID (kind='CARD'). Thẻ mở được những khoá nào: xem CardDeviceAccess (card.carddeviceaccess_set)."""
    KIND = AccessCredential.KIND_CARD
    objects = KindManager(AccessCredential.KIND_CARD)
    VISIBLE_FIELDS = ('id', 'user', 'name', 'card_uid_hash', 'is_active', 'created_at', 'updated_at')

    class Meta:
        proxy = True


class DoorPinCode(AccessCredential):
    """Mã PIN cấp từ xa cho khách thuê (kind='PIN'): chủ nhà cấp OTP -> khách nhập trên bàn phím ma trận 4x4 ->
    mở được, hết hạn thì không mở (kịch bản demo bắt buộc #3 của đề tài A2)."""
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
    """Đặc trưng khuôn mặt (kind='FACE') của 1 thành viên được mở cửa bằng nhận diện khuôn mặt. ESP32-CAM chụp ->
    trích embedding (tại biên hoặc server) -> so khớp với các FaceProfile is_active=True của khoá đó.
    Sinh trắc học là dữ liệu cá nhân nhạy cảm (NĐ 13/2023): embedding LUÔN mã hoá Fernet, không lưu vector thô."""
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



# =====================================================================================================
# BẢNG 13/13 - SecurityRecord  (smartlock_securityrecord)     *** GỘP 4 BẢNG XÁC THỰC CỦA USER ***
# -----------------------------------------------------------------------------------------------------
# Mọi "đồ nghề xác thực" gắn với 1 user. Phân loại bằng `kind`:
#
#   kind      proxy (tên cũ)   Ý nghĩa                                             Cột dùng
#   --------  ---------------  --------------------------------------------------  ------------------------------------
#   OTP       OneTimeCode      Mã/token dùng 1 lần có hạn: link xác thực email,    purpose, token_hash, attempts,
#                              đặt lại mật khẩu, OTP 6 số của 2FA email...         is_used, used_at, expires_at
#                              (chỉ lưu HASH, không lưu mã thô)
#   SESSION   MobileSession    Phiên đăng nhập APP di động: refresh token (hash,   refresh_hash, prev_refresh_hash,
#                              có xoay vòng + phát hiện dùng lại), thông tin máy,  device_name, platform, app_version,
#                              token FCM để đẩy thông báo                          fcm_token, push_enabled, ip_address,
#                                                                                  last_used_at, expires_at, revoked_at
#   PASSKEY   Fido2Credential  Passkey / khoá bảo mật FIDO2 (WebAuthn) của user    credential_id, public_key, sign_count,
#                                                                                  transports, name, last_used_at
#   TFCONFIG  TwoFactorConfig  Cấu hình 2FA của user (TOTP / Email OTP / ưu tiên)  totp_secret_encrypted, totp_confirmed,
#                              ĐÚNG 1 dòng / user                                  totp_last_step, email_otp_enabled,
#                                                                                  preferred_method, enabled_at
#
# Điểm cần nhớ:
#  * user: CASCADE (xoá user -> xoá hết). related_name='+' ; tra ngược dùng property trên User:
#    user.one_time_codes / mobile_sessions / fido2_credentials / two_factor.
#  * Tính duy nhất (UNIQUE) trước đây nằm trên cột nay là UNIQUE CÓ ĐIỀU KIỆN theo kind: refresh_hash (SESSION),
#    credential_id (PASSKEY), user (TFCONFIG = quan hệ 1-1 cũ).
#  * TOTP secret mã hoá Fernet (totp_secret_encrypted); không bao giờ lưu secret thô.
#  * Settings: 'smartlock.SecurityRecord' PHẢI có trong REPLICA_FRESH_MODELS (xem hướng dẫn) vì 4 model cũ đều nằm
#    trong danh sách "luôn đọc Supabase".
# =====================================================================================================
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

    # ---- OTP (OneTimeCode) ----
    purpose = models.CharField(max_length=50, blank=True, default='', choices=OTP_PURPOSE_CHOICES)
    token_hash = models.CharField(max_length=255, blank=True, default='')
    attempts = models.IntegerField(default=0)            # số lần nhập sai
    is_used = models.BooleanField(default=False)
    used_at = models.DateTimeField(null=True, blank=True)

    # ---- SESSION (MobileSession) ----
    refresh_hash = models.CharField(max_length=64, blank=True, null=True)          # hash refresh token hiện tại
    prev_refresh_hash = models.CharField(max_length=64, blank=True, default='')    # token vừa xoay: phát hiện bị dùng lại
    device_name = models.CharField(max_length=100, blank=True, default='')
    platform = models.CharField(max_length=20, blank=True, default='')             # proxy mặc định 'android'
    app_version = models.CharField(max_length=30, blank=True, default='')
    fcm_token = models.CharField(max_length=512, blank=True, default='')           # token đẩy thông báo FCM
    push_enabled = models.BooleanField(default=True)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    revoked_at = models.DateTimeField(null=True, blank=True)

    # ---- PASSKEY (Fido2Credential) ----
    credential_id = models.CharField(max_length=512, blank=True, null=True)        # base64url
    public_key = models.BinaryField(null=True, blank=True)
    sign_count = models.BigIntegerField(default=0)
    transports = models.JSONField(default=list, blank=True)
    name = models.CharField(max_length=100, blank=True, default='')                # proxy mặc định 'Passkey'
    rp_id = models.CharField(max_length=255, blank=True, null=True)                # tên miền (RP ID) nơi passkey được đăng ký; NULL/'' = bản cũ

    # ---- TFCONFIG (TwoFactorConfig) ----
    totp_secret_encrypted = models.CharField(max_length=255, blank=True, default='')
    totp_confirmed = models.BooleanField(default=False)
    totp_last_step = models.BigIntegerField(default=0)           # chống dùng lại mã TOTP (replay)
    email_otp_enabled = models.BooleanField(default=False)
    preferred_method = models.CharField(max_length=10, blank=True, default='', choices=TWO_FA_METHOD_CHOICES)
    enabled_at = models.DateTimeField(null=True, blank=True)

    # ---- Dùng chung ----
    expires_at = models.DateTimeField(null=True, blank=True)     # OTP, SESSION
    last_used_at = models.DateTimeField(null=True, blank=True)   # SESSION, PASSKEY
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)             # TFCONFIG dùng; các loại khác chỉ để tham khảo

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
            # OTP
            models.CheckConstraint(check=~models.Q(kind='OTP') | models.Q(attempts__gte=0),
                                   name='chk_secrec_otp_attempts'),
            # có used_at thì bắt buộc is_used=True (chiều ngược lại cho phép vì có chỗ chỉ .update(is_used=True)).
            models.CheckConstraint(
                check=~models.Q(kind='OTP') | models.Q(used_at__isnull=True) | models.Q(is_used=True),
                name='chk_secrec_otp_usedat'),
            models.CheckConstraint(
                check=~models.Q(kind='OTP') | (~models.Q(purpose='') & models.Q(expires_at__isnull=False)),
                name='chk_secrec_otp_required'),
            # SESSION
            models.UniqueConstraint(fields=['refresh_hash'], condition=models.Q(kind='SESSION'),
                                    name='uniq_secrec_refresh_hash'),
            models.CheckConstraint(
                check=~models.Q(kind='SESSION') |
                      (models.Q(refresh_hash__isnull=False) & models.Q(expires_at__gt=models.F('created_at'))),
                name='chk_secrec_session'),
            # PASSKEY
            models.UniqueConstraint(fields=['credential_id'], condition=models.Q(kind='PASSKEY'),
                                    name='uniq_secrec_credential_id'),
            models.CheckConstraint(
                check=~models.Q(kind='PASSKEY') |
                      (models.Q(credential_id__isnull=False) & models.Q(public_key__isnull=False)),
                name='chk_secrec_passkey'),
            # TFCONFIG: quan hệ 1-1 cũ (OneToOne user) -> mỗi user tối đa 1 dòng
            models.UniqueConstraint(fields=['user'], condition=models.Q(kind='TFCONFIG'),
                                    name='uniq_secrec_tfconfig_user'),
        ]


# ---- 4 PROXY của SecurityRecord ----
class OneTimeCode(SecurityRecord):
    """Mã/token dùng một lần có hạn (kind='OTP'). Gộp EmailVerificationToken + TwoFactorEmailCode cũ: chỉ khác
    nhau ở `purpose`. Chỉ lưu hash."""
    PURPOSE_CHOICES = OTP_PURPOSE_CHOICES
    KIND = SecurityRecord.KIND_OTP
    objects = KindManager(SecurityRecord.KIND_OTP)
    VISIBLE_FIELDS = ('id', 'user', 'purpose', 'token_hash', 'attempts', 'is_used', 'used_at', 'expires_at',
                      'created_at')

    class Meta:
        proxy = True


class MobileSession(SecurityRecord):
    """Phiên đăng nhập app di động (kind='SESSION')."""
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
    """Passkey / khóa bảo mật FIDO2 (WebAuthn) của user (kind='PASSKEY')."""
    KIND = SecurityRecord.KIND_PASSKEY
    KIND_DEFAULTS = {'name': 'Passkey'}
    objects = KindManager(SecurityRecord.KIND_PASSKEY)
    VISIBLE_FIELDS = ('id', 'user', 'credential_id', 'public_key', 'sign_count', 'transports', 'name', 'rp_id',
                      'created_at', 'last_used_at')

    class Meta:
        proxy = True


class TwoFactorConfig(SecurityRecord):
    """Cấu hình 2FA của 1 user (TOTP/Email), kind='TFCONFIG', đúng 1 dòng/user. Trạng thái bật/tắt tổng thể không
    lưu ở đây mà lấy từ User.two_fa_enabled, luôn được đồng bộ bởi sync_two_fa_flag()."""
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


# ==================== SIGNALS (giữ nguyên như bản gốc) ====================
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
