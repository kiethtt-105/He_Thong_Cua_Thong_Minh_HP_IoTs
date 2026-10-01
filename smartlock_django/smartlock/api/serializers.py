# smartlock/api/serializers.py
"""
Serializer cho REST API. QUY TẮC: không bao giờ đưa ra ngoài trường *_hash / *_encrypted / secret /
embedding khuôn mặt / PIN thô (PIN thô chỉ trả 1 lần ở phản hồi tạo, không qua serializer đọc).
"""
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError as DjangoValidationError
from rest_framework import serializers

from smartlock.models import (
    AccessCard, AccessEvent, Announcement, AuditLog, AutomationRule, Device, DeviceAccess,
    DeviceCommand, DeviceStatusLog, DoorPinCode, FaceProfile, MobileSession, NfcReader,
    Notification, Permission, ShareAccessCode, SupportRequest, User,
)


# ================================================================ người dùng
class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ('id', 'email', 'username', 'full_name', 'phone', 'avatar_url',
                  'email_verified', 'two_fa_enabled', 'created_at')
        read_only_fields = fields


class UserBriefSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ('id', 'username', 'email', 'full_name')
        read_only_fields = fields


class ProfileUpdateSerializer(serializers.Serializer):
    full_name = serializers.CharField(max_length=100, required=False, allow_blank=True, allow_null=True)
    phone = serializers.CharField(max_length=20, required=False, allow_blank=True, allow_null=True)


class ChangePasswordSerializer(serializers.Serializer):
    old_password = serializers.CharField(write_only=True)
    new_password1 = serializers.CharField(write_only=True)
    new_password2 = serializers.CharField(write_only=True)

    def validate(self, attrs):
        if attrs['new_password1'] != attrs['new_password2']:
            raise serializers.ValidationError('Mật khẩu mới không khớp.')
        user = self.context.get('user')
        try:
            validate_password(attrs['new_password1'], user)
        except DjangoValidationError as e:
            raise serializers.ValidationError(' '.join(e.messages))
        return attrs


# ================================================================ xác thực
class RegisterSerializer(serializers.Serializer):
    email = serializers.EmailField(max_length=254)
    username = serializers.CharField(max_length=50)
    full_name = serializers.CharField(max_length=100, required=False, allow_blank=True)
    password1 = serializers.CharField(write_only=True)
    password2 = serializers.CharField(write_only=True)

    def validate_username(self, value):
        value = value.strip()
        if '@' in value:
            raise serializers.ValidationError('Tên đăng nhập không được chứa ký tự @.')
        if not value:
            raise serializers.ValidationError('Vui lòng nhập tên đăng nhập.')
        return value

    def validate(self, attrs):
        if attrs['password1'] != attrs['password2']:
            raise serializers.ValidationError('Mật khẩu không khớp.')
        try:
            validate_password(attrs['password1'])
        except DjangoValidationError as e:
            raise serializers.ValidationError(' '.join(e.messages))
        return attrs


class _ClientInfoMixin(serializers.Serializer):
    device_name = serializers.CharField(max_length=100, required=False, allow_blank=True, default='')
    platform = serializers.ChoiceField(choices=['android', 'ios'], required=False, default='android')
    app_version = serializers.CharField(max_length=30, required=False, allow_blank=True, default='')
    fcm_token = serializers.CharField(max_length=512, required=False, allow_blank=True, default='')


class LoginSerializer(_ClientInfoMixin):
    identifier = serializers.CharField(max_length=254)
    password = serializers.CharField(write_only=True, max_length=256, trim_whitespace=False)


class TwoFactorVerifySerializer(_ClientInfoMixin):
    pending_token = serializers.CharField(max_length=512)
    method = serializers.ChoiceField(choices=['totp', 'email'])
    code = serializers.CharField(max_length=16)


class PendingTokenSerializer(serializers.Serializer):
    pending_token = serializers.CharField(max_length=512)


class PasskeyFinishSerializer(_ClientInfoMixin):
    pending_token = serializers.CharField(max_length=512)
    credential = serializers.DictField()


class RefreshSerializer(serializers.Serializer):
    refresh_token = serializers.CharField(max_length=200)


class EmailOnlySerializer(serializers.Serializer):
    email = serializers.EmailField(max_length=254)


class PushTokenSerializer(serializers.Serializer):
    fcm_token = serializers.CharField(max_length=512, required=False, allow_blank=True)
    push_enabled = serializers.BooleanField(required=False)


class MobileSessionSerializer(serializers.ModelSerializer):
    is_current = serializers.SerializerMethodField()

    class Meta:
        model = MobileSession
        fields = ('id', 'device_name', 'platform', 'app_version', 'ip_address', 'push_enabled',
                  'created_at', 'last_used_at', 'expires_at', 'is_current')
        read_only_fields = fields

    def get_is_current(self, obj):
        return str(obj.pk) == str(self.context.get('current_session_id'))


# ================================================================ thiết bị
class DeviceSerializer(serializers.ModelSerializer):
    is_owner = serializers.SerializerMethodField()
    lock_state = serializers.SerializerMethodField()
    my_permissions = serializers.SerializerMethodField()

    class Meta:
        model = Device
        fields = ('id', 'device_code', 'name', 'status', 'battery_level', 'location', 'firmware_version',
                  'last_seen_at', 'bluetooth_enabled', 'wifi_enabled', 'nfc_enabled', 'device_mode',
                  'is_owner', 'lock_state', 'my_permissions', 'created_at')
        read_only_fields = fields

    def get_is_owner(self, obj):
        return obj.owner_id == self.context['request'].user.id

    def get_lock_state(self, obj):
        return getattr(obj, 'last_lock_state', None) or 'unknown'

    def get_my_permissions(self, obj):
        codes = self.context.get('permission_codes')       # chỉ truyền ở màn chi tiết (tránh N+1 ở danh sách)
        return codes if codes is not None else None


class DeviceCreateSerializer(serializers.Serializer):
    name = serializers.CharField(max_length=100)
    location = serializers.CharField(max_length=255, required=False, allow_blank=True)

    def validate_name(self, value):
        value = value.strip()
        if not value:
            raise serializers.ValidationError('Tên thiết bị không được để trống.')
        return value


class DeviceUpdateSerializer(serializers.Serializer):
    name = serializers.CharField(max_length=100, required=False)
    location = serializers.CharField(max_length=255, required=False, allow_blank=True, allow_null=True)
    wifi_enabled = serializers.BooleanField(required=False)
    bluetooth_enabled = serializers.BooleanField(required=False)
    nfc_enabled = serializers.BooleanField(required=False)

    def validate_name(self, value):
        value = value.strip()
        if not value:
            raise serializers.ValidationError('Tên thiết bị không được để trống.')
        return value


class CommandCreateSerializer(serializers.Serializer):
    command = serializers.ChoiceField(choices=['LOCK', 'UNLOCK', 'REBOOT'])


class DeviceCommandSerializer(serializers.ModelSerializer):
    issued_by = serializers.CharField(source='issued_by.username', read_only=True)

    class Meta:
        model = DeviceCommand
        fields = ('id', 'device', 'command_type', 'status', 'issued_by', 'expires_at', 'created_at',
                  'acknowledged_at')
        read_only_fields = fields


class StatusLogSerializer(serializers.ModelSerializer):
    class Meta:
        model = DeviceStatusLog
        fields = ('id', 'battery_level', 'signal_strength', 'lock_state', 'tamper_detected',
                  'temperature', 'recorded_at')
        read_only_fields = fields


# ================================================================ quyền & chia sẻ
class PermissionSerializer(serializers.ModelSerializer):
    class Meta:
        model = Permission
        fields = ('code', 'name', 'description', 'is_sensitive')
        read_only_fields = fields


class AccessGrantSerializer(serializers.ModelSerializer):
    user = UserBriefSerializer(read_only=True)
    permissions = serializers.SlugRelatedField(many=True, read_only=True, slug_field='code')
    device_name = serializers.CharField(source='device.name', read_only=True)

    class Meta:
        model = DeviceAccess
        fields = ('id', 'device', 'device_name', 'user', 'permissions', 'source', 'valid_from',
                  'expires_at', 'is_active', 'accepted', 'created_at')
        read_only_fields = fields


class AccessGrantCreateSerializer(serializers.Serializer):
    identifier = serializers.CharField(max_length=254)
    permissions = serializers.ListField(child=serializers.CharField(max_length=50), required=False, default=list)
    expires_at = serializers.DateTimeField(required=False, allow_null=True, default=None)


class AccessGrantUpdateSerializer(serializers.Serializer):
    permissions = serializers.ListField(child=serializers.CharField(max_length=50))


class ShareCodeSerializer(serializers.ModelSerializer):
    permissions = serializers.SlugRelatedField(many=True, read_only=True, slug_field='code')
    device_name = serializers.CharField(source='device.name', read_only=True)
    is_expired = serializers.SerializerMethodField()

    class Meta:
        model = ShareAccessCode
        fields = ('id', 'device', 'device_name', 'permissions', 'expires_at', 'created_at', 'is_expired')
        read_only_fields = fields

    def get_is_expired(self, obj):
        from django.utils import timezone
        return obj.expires_at <= timezone.now()


class ShareCodeCreateSerializer(serializers.Serializer):
    device_id = serializers.UUIDField()
    minutes = serializers.IntegerField(min_value=1, max_value=1440, required=False)
    permissions = serializers.ListField(child=serializers.CharField(max_length=50), required=False, default=list)
    recipient = serializers.CharField(max_length=254, required=False, allow_blank=True)


class ShareRedeemSerializer(serializers.Serializer):
    code = serializers.CharField(max_length=20)
    device_code = serializers.CharField(max_length=50, required=False, allow_blank=True)


# ================================================================ PIN / khuôn mặt / thẻ
class DoorPinSerializer(serializers.ModelSerializer):
    created_by = serializers.CharField(source='created_by.username', read_only=True)
    is_valid_now = serializers.SerializerMethodField()

    class Meta:
        model = DoorPinCode
        fields = ('id', 'device', 'label', 'created_by', 'valid_from', 'expires_at', 'max_uses',
                  'use_count', 'is_revoked', 'is_valid_now', 'created_at')
        read_only_fields = fields

    def get_is_valid_now(self, obj):
        return obj.is_valid_now()


class DoorPinCreateSerializer(serializers.Serializer):
    device_id = serializers.UUIDField()
    ttl_minutes = serializers.IntegerField(min_value=1, max_value=43200, default=1440)   # tối đa 30 ngày
    max_uses = serializers.IntegerField(min_value=0, max_value=1000, default=1)           # 0 = không giới hạn
    label = serializers.CharField(max_length=100, required=False, allow_blank=True, default='')


class FaceProfileSerializer(serializers.ModelSerializer):
    user = UserBriefSerializer(read_only=True)

    class Meta:
        model = FaceProfile
        fields = ('id', 'device', 'user', 'name', 'consent_confirmed', 'is_active', 'created_at', 'updated_at')
        read_only_fields = fields


class FaceRegisterSerializer(serializers.Serializer):
    device_id = serializers.UUIDField()
    name = serializers.CharField(max_length=100, required=False, allow_blank=True)
    consent_confirmed = serializers.BooleanField()
    embedding = serializers.ListField(child=serializers.FloatField(), min_length=32, max_length=512)

    def validate_consent_confirmed(self, value):
        if not value:
            raise serializers.ValidationError(
                'Cần xác nhận người được đăng ký đã đồng ý thu thập dữ liệu khuôn mặt.')
        return value


class CardSerializer(serializers.ModelSerializer):
    devices = serializers.SerializerMethodField()

    class Meta:
        model = AccessCard
        fields = ('id', 'name', 'is_active', 'created_at', 'devices')
        read_only_fields = fields

    def get_devices(self, obj):
        return [str(a.device_id) for a in obj.carddeviceaccess_set.all() if a.is_active]


class CardRegisterSerializer(serializers.Serializer):
    device_id = serializers.UUIDField()
    uid = serializers.CharField(max_length=64)
    name = serializers.CharField(max_length=100, required=False, allow_blank=True)


class CardUpdateSerializer(serializers.Serializer):
    name = serializers.CharField(max_length=100, required=False, allow_blank=True, allow_null=True)
    is_active = serializers.BooleanField(required=False)


class ReaderSerializer(serializers.ModelSerializer):
    class Meta:
        model = NfcReader
        fields = ('id', 'device', 'reader_mode', 'name', 'is_active', 'last_seen_at')
        read_only_fields = fields


class AccessEventSerializer(serializers.ModelSerializer):
    user = UserBriefSerializer(read_only=True)
    device_name = serializers.CharField(source='device.name', read_only=True)

    class Meta:
        model = AccessEvent
        fields = ('id', 'device', 'device_name', 'method', 'success', 'reason', 'user', 'confidence',
                  'snapshot_url', 'created_at')
        read_only_fields = fields


# ================================================================ thông báo / luật / hỗ trợ / log
class NotificationSerializer(serializers.ModelSerializer):
    class Meta:
        model = Notification
        fields = ('id', 'device', 'type', 'title', 'message', 'severity', 'is_read', 'created_at', 'read_at')
        read_only_fields = fields


class RuleSerializer(serializers.ModelSerializer):
    device = serializers.PrimaryKeyRelatedField(queryset=Device.objects.none(), allow_null=True, required=False)

    class Meta:
        model = AutomationRule
        fields = ('id', 'device', 'name', 'trigger_type', 'threshold_value', 'action_type', 'notify_severity',
                  'cooldown_seconds', 'is_active', 'last_triggered_at', 'created_at')
        read_only_fields = ('id', 'last_triggered_at', 'created_at')

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        request = self.context.get('request')
        if request is not None and request.user.is_authenticated:
            self.fields['device'].queryset = Device.objects.filter(owner=request.user)   # chỉ thiết bị của mình

    def validate_name(self, value):
        value = value.strip()
        if not value:
            raise serializers.ValidationError('Vui lòng nhập tên luật.')
        return value

    def validate_cooldown_seconds(self, value):
        if value < 0:
            raise serializers.ValidationError('Thời gian cooldown không hợp lệ.')
        return value

    def validate(self, attrs):
        trigger = attrs.get('trigger_type', getattr(self.instance, 'trigger_type', None))
        threshold = attrs.get('threshold_value', getattr(self.instance, 'threshold_value', None))
        if trigger in (AutomationRule.TRIGGER_BATTERY_LOW, AutomationRule.TRIGGER_OFFLINE_TOO_LONG,
                       AutomationRule.TRIGGER_DOOR_OPEN_TOO_LONG) and threshold is None:
            raise serializers.ValidationError({'threshold_value': 'Điều kiện này cần một ngưỡng.'})
        if trigger == AutomationRule.TRIGGER_BATTERY_LOW and threshold is not None and not 0 < threshold <= 100:
            raise serializers.ValidationError({'threshold_value': 'Ngưỡng pin phải trong khoảng 1-100.'})
        return attrs


class SupportRequestSerializer(serializers.ModelSerializer):
    device_name = serializers.CharField(source='device.name', read_only=True)

    class Meta:
        model = SupportRequest
        fields = ('id', 'device', 'device_name', 'action', 'scope', 'status', 'expires_at', 'created_at',
                  'completed_at')
        read_only_fields = fields


class SupportRequestCreateSerializer(serializers.Serializer):
    device_id = serializers.UUIDField()
    action = serializers.ChoiceField(choices=[c for c, _ in SupportRequest._meta.get_field('action').choices])
    scope = serializers.CharField(max_length=100, required=False, allow_blank=True)


class AuditLogSerializer(serializers.ModelSerializer):
    actor = serializers.CharField(source='actor_user.username', default=None, read_only=True)
    target = serializers.CharField(source='target_user.username', default=None, read_only=True)
    device_name = serializers.CharField(source='device.name', default=None, read_only=True)

    class Meta:
        model = AuditLog
        fields = ('id', 'action', 'severity', 'success', 'actor', 'target', 'device', 'device_name',
                  'ip_address', 'created_at')
        read_only_fields = fields


class AnnouncementSerializer(serializers.ModelSerializer):
    class Meta:
        model = Announcement
        fields = ('id', 'title', 'body', 'level', 'created_at')
        read_only_fields = fields
