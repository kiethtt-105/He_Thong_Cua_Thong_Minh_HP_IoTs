# smartlock/api/serializers.py
import math

from rest_framework import serializers

from ..models import (
    AccessCard, AccessEvent, Announcement, AuditLog, AutomationRule, AutomationRuleLog,
    Device, DeviceAccess, DeviceCommand, DeviceStatusLog, DoorPinCode, FaceProfile,
    MobileSession, Notification, Permission, ShareAccessCode, User,
)
from ..utils import SmartlockUtils as U

PERMISSION_CODES = ('LOCK', 'UNLOCK', 'manage_pins', 'manage_face_profiles')


# ============================== AUTH ==============================
class DeviceInfoMixin(serializers.Serializer):
    device_name = serializers.CharField(max_length=100, required=False, allow_blank=True, default='')
    platform = serializers.CharField(max_length=20, required=False, default='android')
    app_version = serializers.CharField(max_length=30, required=False, allow_blank=True, default='')
    fcm_token = serializers.CharField(max_length=512, required=False, allow_blank=True, default='')


class RegisterSerializer(serializers.Serializer):
    email = serializers.EmailField()
    username = serializers.CharField(max_length=50, min_length=3)
    password = serializers.CharField(write_only=True, max_length=128)
    full_name = serializers.CharField(max_length=100, required=False, allow_blank=True, default='')

    def validate_username(self, v):
        v = v.strip()
        if '@' in v:
            raise serializers.ValidationError('Tên đăng nhập không được chứa ký tự @.')
        return v


class LoginSerializer(DeviceInfoMixin):
    identifier = serializers.CharField(max_length=150)   # email hoặc username
    password = serializers.CharField(max_length=128, trim_whitespace=False)


class TwoFactorVerifySerializer(serializers.Serializer):
    challenge_token = serializers.CharField()
    method = serializers.ChoiceField(choices=['totp', 'email'])
    code = serializers.CharField(max_length=12)


class ChallengeSerializer(serializers.Serializer):
    challenge_token = serializers.CharField()


class RefreshSerializer(serializers.Serializer):
    refresh_token = serializers.CharField()


class EmailSerializer(serializers.Serializer):
    email = serializers.EmailField()


class ChangePasswordSerializer(serializers.Serializer):
    old_password = serializers.CharField(max_length=128, trim_whitespace=False)
    new_password = serializers.CharField(max_length=128, trim_whitespace=False)


class PushTokenSerializer(serializers.Serializer):
    fcm_token = serializers.CharField(max_length=512, required=False, allow_blank=True)
    push_enabled = serializers.BooleanField(required=False)


# ============================== USER ==============================
class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ('id', 'email', 'username', 'full_name', 'phone', 'avatar_url',
                  'email_verified', 'two_fa_enabled', 'created_at')
        read_only_fields = fields


class ProfileUpdateSerializer(serializers.Serializer):
    full_name = serializers.CharField(max_length=100, required=False, allow_blank=True)
    phone = serializers.CharField(max_length=20, required=False, allow_blank=True)


class MobileSessionSerializer(serializers.ModelSerializer):
    is_current = serializers.SerializerMethodField()

    class Meta:
        model = MobileSession
        fields = ('id', 'device_name', 'platform', 'app_version', 'push_enabled', 'ip_address',
                  'created_at', 'last_used_at', 'expires_at', 'is_current')

    def get_is_current(self, obj):
        return str(obj.pk) == str(self.context.get('current_session_id'))


# ============================== DEVICE ==============================
class DeviceSerializer(serializers.ModelSerializer):
    lock_state = serializers.SerializerMethodField()
    last_status_at = serializers.SerializerMethodField()
    is_owner = serializers.SerializerMethodField()
    permissions = serializers.SerializerMethodField()

    class Meta:
        model = Device
        fields = ('id', 'name', 'device_code', 'status', 'battery_level', 'location', 'firmware_version',
                  'last_seen_at', 'wifi_enabled', 'bluetooth_enabled', 'nfc_enabled',
                  'lock_state', 'last_status_at', 'is_owner', 'permissions', 'updated_at')
        read_only_fields = fields

    def _log(self, obj):
        return self.context.get('last_logs', {}).get(obj.id)

    def get_lock_state(self, obj):
        log = self._log(obj)
        return log.lock_state if log else 'unknown'

    def get_last_status_at(self, obj):
        log = self._log(obj)
        return log.recorded_at if log else None

    def get_is_owner(self, obj):
        user = self.context.get('user')
        return bool(user and obj.owner_id == user.id)

    def get_permissions(self, obj):
        if self.get_is_owner(obj):
            return list(PERMISSION_CODES) + ['REBOOT', 'MANAGE_DEVICE']
        return sorted(self.context.get('perm_map', {}).get(obj.id, []))


class DeviceCreateSerializer(serializers.Serializer):
    name = serializers.CharField(max_length=100)


class DeviceUpdateSerializer(serializers.Serializer):
    name = serializers.CharField(max_length=100, required=False)
    location = serializers.CharField(max_length=255, required=False, allow_blank=True)
    wifi_enabled = serializers.BooleanField(required=False)
    bluetooth_enabled = serializers.BooleanField(required=False)
    nfc_enabled = serializers.BooleanField(required=False)

    def validate_name(self, v):
        v = v.strip()
        if not v:
            raise serializers.ValidationError('Tên thiết bị không được để trống.')
        return v


class CommandRequestSerializer(serializers.Serializer):
    command = serializers.ChoiceField(choices=list(U.ALLOWED_COMMANDS.keys()))

    def validate_command(self, v):
        return v.upper()


class DeviceCommandSerializer(serializers.ModelSerializer):
    issued_by = serializers.CharField(source='issued_by.username', read_only=True)

    class Meta:
        model = DeviceCommand
        fields = ('id', 'command_type', 'status', 'issued_by', 'created_at', 'expires_at', 'acknowledged_at')


class StatusLogSerializer(serializers.ModelSerializer):
    class Meta:
        model = DeviceStatusLog
        fields = ('id', 'battery_level', 'signal_strength', 'lock_state', 'tamper_detected',
                  'temperature', 'recorded_at')


# ============================== ACCESS / SHARE ==============================
class PermissionSerializer(serializers.ModelSerializer):
    class Meta:
        model = Permission
        fields = ('code', 'name', 'description', 'is_sensitive')


class DeviceAccessSerializer(serializers.ModelSerializer):
    user = serializers.CharField(source='user.username', read_only=True)
    user_email = serializers.CharField(source='user.email', read_only=True)
    device_name = serializers.CharField(source='device.name', read_only=True)
    permissions = serializers.SlugRelatedField(many=True, read_only=True, slug_field='code')

    class Meta:
        model = DeviceAccess
        fields = ('id', 'device', 'device_name', 'user', 'user_email', 'permissions', 'source',
                  'valid_from', 'expires_at', 'is_active', 'created_at')


class DeviceAccessUpdateSerializer(serializers.Serializer):
    permissions = serializers.ListField(child=serializers.ChoiceField(choices=PERMISSION_CODES),
                                        required=False)
    expires_at = serializers.DateTimeField(required=False, allow_null=True)


class ShareCodeCreateSerializer(serializers.Serializer):
    device_id = serializers.UUIDField()
    minutes = serializers.IntegerField(min_value=1, max_value=1440, required=False)
    permissions = serializers.ListField(child=serializers.ChoiceField(choices=PERMISSION_CODES),
                                        required=False, default=list)
    recipient = serializers.CharField(max_length=150, required=False, allow_blank=True, default='')


class ShareCodeSerializer(serializers.ModelSerializer):
    device_name = serializers.CharField(source='device.name', read_only=True)
    permissions = serializers.SlugRelatedField(many=True, read_only=True, slug_field='code')
    is_expired = serializers.SerializerMethodField()

    class Meta:
        model = ShareAccessCode
        fields = ('id', 'device', 'device_name', 'permissions', 'expires_at', 'created_at', 'is_expired')

    def get_is_expired(self, obj):
        from django.utils import timezone
        return obj.expires_at <= timezone.now()


class RedeemSerializer(serializers.Serializer):
    code = serializers.CharField(max_length=12)


# ============================== PIN / FACE / CARD ==============================
class DoorPinCreateSerializer(serializers.Serializer):
    ttl_minutes = serializers.IntegerField(min_value=1, max_value=43200, default=1440)   # tối đa 30 ngày
    max_uses = serializers.IntegerField(min_value=0, max_value=1000, default=1)           # 0 = không giới hạn
    label = serializers.CharField(max_length=100, required=False, allow_blank=True, default='')


class DoorPinSerializer(serializers.ModelSerializer):
    created_by = serializers.CharField(source='created_by.username', read_only=True)
    is_valid_now = serializers.SerializerMethodField()

    class Meta:
        model = DoorPinCode
        fields = ('id', 'label', 'created_by', 'valid_from', 'expires_at', 'max_uses', 'use_count',
                  'is_revoked', 'is_valid_now', 'created_at')

    def get_is_valid_now(self, obj):
        return obj.is_valid_now()


class FaceRegisterSerializer(serializers.Serializer):
    embedding = serializers.ListField(child=serializers.FloatField(), min_length=32, max_length=1024)
    name = serializers.CharField(max_length=100, required=False, allow_blank=True, default='')
    consent_confirmed = serializers.BooleanField()

    def validate_embedding(self, v):
        if not all(math.isfinite(x) for x in v):
            raise serializers.ValidationError('Vector chứa giá trị không hợp lệ.')
        return v

    def validate_consent_confirmed(self, v):
        if not v:
            raise serializers.ValidationError(
                'Cần xác nhận người được đăng ký đã đồng ý thu thập dữ liệu khuôn mặt.')
        return v


class FaceProfileSerializer(serializers.ModelSerializer):   # KHÔNG bao giờ trả embedding
    username = serializers.CharField(source='user.username', read_only=True)

    class Meta:
        model = FaceProfile
        fields = ('id', 'user', 'username', 'name', 'is_active', 'consent_confirmed', 'created_at')


class CardRegisterSerializer(serializers.Serializer):
    device_id = serializers.UUIDField()
    uid = serializers.CharField(max_length=40)
    name = serializers.CharField(max_length=100, required=False, allow_blank=True, default='')


class CardUpdateSerializer(serializers.Serializer):
    name = serializers.CharField(max_length=100, required=False, allow_blank=True)
    is_active = serializers.BooleanField(required=False)


class AccessCardSerializer(serializers.ModelSerializer):   # không trả card_uid_hash
    devices = serializers.SerializerMethodField()

    class Meta:
        model = AccessCard
        fields = ('id', 'name', 'is_active', 'devices', 'created_at')

    def get_devices(self, obj):
        return [str(c.device_id) for c in obj.carddeviceaccess_set.all()]


class AccessEventSerializer(serializers.ModelSerializer):
    device_name = serializers.CharField(source='device.name', read_only=True)
    username = serializers.SerializerMethodField()

    class Meta:
        model = AccessEvent
        fields = ('id', 'device', 'device_name', 'method', 'success', 'reason', 'username',
                  'confidence', 'snapshot_url', 'created_at')

    def get_username(self, obj):
        return obj.user.username if obj.user_id else None


# ============================== NOTIFICATION / AUDIT / RULES ==============================
class NotificationSerializer(serializers.ModelSerializer):
    class Meta:
        model = Notification
        fields = ('id', 'type', 'title', 'message', 'severity', 'device', 'is_read', 'created_at', 'read_at')


class AuditLogSerializer(serializers.ModelSerializer):
    actor = serializers.SerializerMethodField()
    device_name = serializers.SerializerMethodField()

    class Meta:
        model = AuditLog
        fields = ('id', 'action', 'actor', 'device', 'device_name', 'severity', 'success',
                  'ip_address', 'created_at')

    def get_actor(self, obj):
        return obj.actor_user.username if obj.actor_user_id else None

    def get_device_name(self, obj):
        return obj.device.name if obj.device_id else None


class AnnouncementSerializer(serializers.ModelSerializer):
    class Meta:
        model = Announcement
        fields = ('id', 'title', 'body', 'level', 'created_at')


class AutomationRuleSerializer(serializers.ModelSerializer):
    class Meta:
        model = AutomationRule
        fields = ('id', 'name', 'device', 'trigger_type', 'threshold_value', 'threshold_window_seconds',
                  'action_type', 'notify_severity', 'cooldown_seconds', 'is_active',
                  'last_triggered_at', 'created_at')
        read_only_fields = ('id', 'last_triggered_at', 'created_at')

    def validate_device(self, device):
        user = self.context['request'].user
        if device is not None and device.owner_id != user.id:
            raise serializers.ValidationError('Bạn không phải chủ thiết bị này.')
        return device

    def validate_cooldown_seconds(self, v):
        if v < 0 or v > 86400:
            raise serializers.ValidationError('Cooldown phải từ 0 đến 86400 giây.')
        return v

    def validate(self, attrs):
        inst = self.instance
        trigger = attrs.get('trigger_type', inst.trigger_type if inst else None)
        threshold = attrs.get('threshold_value', inst.threshold_value if inst else None)
        if trigger != AutomationRule.TRIGGER_TAMPER_DETECTED and threshold is None:
            raise serializers.ValidationError({'threshold_value': 'Luật này cần ngưỡng (threshold_value).'})
        if trigger == AutomationRule.TRIGGER_FAILED_ACCESS_BURST:
            window = attrs.get('threshold_window_seconds', inst.threshold_window_seconds if inst else None)
            if not window:
                raise serializers.ValidationError(
                    {'threshold_window_seconds': 'Luật "N lần thất bại" cần khoảng thời gian (giây).'})
        return attrs


class AutomationRuleLogSerializer(serializers.ModelSerializer):
    class Meta:
        model = AutomationRuleLog
        fields = ('id', 'device', 'measured_value', 'action_taken', 'notification', 'triggered_at')
