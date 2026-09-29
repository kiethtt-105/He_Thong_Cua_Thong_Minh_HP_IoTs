# smartlock/api/serializers.py
from django.utils import timezone
from rest_framework import serializers

from ..models import (
    AccessCard, AccessEvent, Announcement, AuditLog, AutomationRule, AutomationRuleLog, Device,
    DeviceAccess, DeviceCommand, DeviceStatusLog, DoorPinCode, FaceProfile, NfcLog, NfcReader,
    Notification, Permission, ShareAccessCode, SupportRequest, User,
)
from ..utils import SmartlockUtils as U


class PermissionCodesField(serializers.ListField):
    """Danh sách mã quyền, vd ["LOCK", "UNLOCK", "manage_pins"]."""
    def __init__(self, **kwargs):
        kwargs.setdefault('child', serializers.CharField(max_length=50))
        kwargs.setdefault('allow_empty', True)
        super().__init__(**kwargs)


def _user_brief(u):
    return None if u is None else {'id': str(u.id), 'username': u.username, 'full_name': u.full_name}


# ------------------------------------------------------------------ tài khoản
class MeSerializer(serializers.ModelSerializer):
    device_count = serializers.SerializerMethodField()
    card_count = serializers.SerializerMethodField()

    class Meta:
        model = User
        fields = ('id', 'email', 'username', 'full_name', 'phone', 'avatar_url', 'email_verified',
                  'two_fa_enabled', 'created_at', 'device_count', 'card_count')
        read_only_fields = fields

    def get_device_count(self, obj):
        return Device.objects.filter(owner=obj).count()

    def get_card_count(self, obj):
        return AccessCard.objects.filter(user=obj).count()


class ProfileUpdateSerializer(serializers.Serializer):
    full_name = serializers.CharField(max_length=100, required=False, allow_blank=True, allow_null=True)
    phone = serializers.CharField(max_length=20, required=False, allow_blank=True, allow_null=True)


class ChangePasswordSerializer(serializers.Serializer):
    old_password = serializers.CharField(write_only=True, trim_whitespace=False)
    new_password1 = serializers.CharField(write_only=True, trim_whitespace=False)
    new_password2 = serializers.CharField(write_only=True, trim_whitespace=False)


# ------------------------------------------------------------------ thiết bị
class DeviceSerializer(serializers.ModelSerializer):
    status_display = serializers.CharField(source='get_status_display', read_only=True)
    lock_state = serializers.SerializerMethodField()
    is_owner = serializers.SerializerMethodField()

    class Meta:
        model = Device
        fields = ('id', 'name', 'device_code', 'device_mode', 'status', 'status_display',
                  'battery_level', 'location', 'firmware_version', 'last_seen_at',
                  'wifi_enabled', 'bluetooth_enabled', 'nfc_enabled',
                  'lock_state', 'is_owner', 'created_at', 'updated_at')
        read_only_fields = fields

    def get_lock_state(self, obj):
        return getattr(obj, 'lock_state', None) or 'unknown'

    def get_is_owner(self, obj):
        return obj.owner_id == self.context['request'].user.id


class DeviceCreateSerializer(serializers.Serializer):
    name = serializers.CharField(max_length=100)


class DeviceUpdateSerializer(serializers.Serializer):
    name = serializers.CharField(max_length=100, required=False)
    location = serializers.CharField(max_length=255, required=False, allow_blank=True, allow_null=True)
    wifi_enabled = serializers.BooleanField(required=False)
    bluetooth_enabled = serializers.BooleanField(required=False)
    nfc_enabled = serializers.BooleanField(required=False)


class StatusLogSerializer(serializers.ModelSerializer):
    class Meta:
        model = DeviceStatusLog
        fields = ('id', 'battery_level', 'signal_strength', 'lock_state', 'tamper_detected',
                  'temperature', 'recorded_at')
        read_only_fields = fields


class DeviceCommandSerializer(serializers.ModelSerializer):
    issued_by = serializers.SerializerMethodField()

    class Meta:
        model = DeviceCommand
        fields = ('id', 'command_type', 'status', 'issued_by', 'created_at', 'expires_at', 'acknowledged_at')
        read_only_fields = fields

    def get_issued_by(self, obj):
        return obj.issued_by.username


# ------------------------------------------------------------------ quyền & chia sẻ
class PermissionSerializer(serializers.ModelSerializer):
    class Meta:
        model = Permission
        fields = ('code', 'name', 'description', 'is_sensitive')
        read_only_fields = fields


class DeviceAccessSerializer(serializers.ModelSerializer):
    """Quyền của NGƯỜI KHÁC trên thiết bị của mình (chủ thiết bị xem)."""
    user = serializers.SerializerMethodField()
    permissions = serializers.SerializerMethodField()

    class Meta:
        model = DeviceAccess
        fields = ('id', 'user', 'permissions', 'source', 'valid_from', 'expires_at',
                  'accepted', 'is_active', 'created_at')
        read_only_fields = fields

    def get_user(self, obj):
        return {**_user_brief(obj.user), 'email': obj.user.email}

    def get_permissions(self, obj):
        return sorted(p.code for p in obj.permissions.all())


class MyAccessSerializer(serializers.ModelSerializer):
    """Quyền MÌNH được người khác cấp."""
    device = serializers.SerializerMethodField()
    permissions = serializers.SerializerMethodField()

    class Meta:
        model = DeviceAccess
        fields = ('id', 'device', 'permissions', 'source', 'valid_from', 'expires_at', 'created_at')
        read_only_fields = fields

    def get_device(self, obj):
        return {'id': str(obj.device_id), 'name': obj.device.name}

    def get_permissions(self, obj):
        return sorted(p.code for p in obj.permissions.all())


class AccessGrantSerializer(serializers.Serializer):
    identifier = serializers.CharField(max_length=150)          # email hoặc username
    permissions = PermissionCodesField(required=False)
    expires_at = serializers.DateTimeField(required=False, allow_null=True)


class AccessUpdateSerializer(serializers.Serializer):
    permissions = PermissionCodesField(required=False)
    expires_at = serializers.DateTimeField(required=False, allow_null=True)


class ShareCodeSerializer(serializers.ModelSerializer):
    device = serializers.SerializerMethodField()
    permissions = serializers.SerializerMethodField()
    is_expired = serializers.SerializerMethodField()

    class Meta:
        model = ShareAccessCode
        fields = ('id', 'device', 'permissions', 'expires_at', 'created_at', 'is_expired')
        read_only_fields = fields

    def get_device(self, obj):
        return {'id': str(obj.device_id), 'name': obj.device.name}

    def get_permissions(self, obj):
        return sorted(p.code for p in obj.permissions.all())

    def get_is_expired(self, obj):
        return obj.expires_at <= timezone.now()


class ShareCodeCreateSerializer(serializers.Serializer):
    device_id = serializers.UUIDField()
    minutes = serializers.IntegerField(min_value=1, max_value=1440, required=False)
    permissions = PermissionCodesField(required=False)
    recipient = serializers.CharField(max_length=150, required=False, allow_blank=True)


class ShareCodeRedeemSerializer(serializers.Serializer):
    code = serializers.CharField(max_length=20)


# ------------------------------------------------------------------ NFC
class NfcReaderSerializer(serializers.ModelSerializer):
    class Meta:
        model = NfcReader
        fields = ('id', 'name', 'reader_mode', 'is_active', 'auto_register', 'last_seen_at', 'created_at')
        read_only_fields = fields


class NfcReaderCreateSerializer(serializers.Serializer):
    name = serializers.CharField(max_length=100, required=False, allow_blank=True)


class NfcReaderUpdateSerializer(serializers.Serializer):
    is_active = serializers.BooleanField(required=False)
    auto_register = serializers.BooleanField(required=False)


class NfcLogSerializer(serializers.ModelSerializer):
    card_name = serializers.SerializerMethodField()
    reader_name = serializers.SerializerMethodField()

    class Meta:
        model = NfcLog
        fields = ('id', 'event_type', 'success', 'card_name', 'reader_name', 'created_at')
        read_only_fields = fields

    def get_card_name(self, obj):
        return obj.nfc_tag.name if obj.nfc_tag_id else None

    def get_reader_name(self, obj):
        return obj.reader.name if obj.reader_id else None


class AccessCardSerializer(serializers.ModelSerializer):
    devices = serializers.SerializerMethodField()

    class Meta:
        model = AccessCard
        fields = ('id', 'name', 'is_active', 'devices', 'created_at')   # KHÔNG trả card_uid_hash
        read_only_fields = fields

    def get_devices(self, obj):
        return [{'id': str(a.device_id), 'name': a.device.name, 'is_active': a.is_active}
                for a in obj.carddeviceaccess_set.all()]


class CardRegisterSerializer(serializers.Serializer):
    uid = serializers.CharField(max_length=64)
    name = serializers.CharField(max_length=100, required=False, allow_blank=True)


class CardUpdateSerializer(serializers.Serializer):
    name = serializers.CharField(max_length=100, required=False, allow_blank=True, allow_null=True)
    is_active = serializers.BooleanField(required=False)


# ------------------------------------------------------------------ PIN / khuôn mặt / lịch sử ra vào
class DoorPinSerializer(serializers.ModelSerializer):
    created_by = serializers.SerializerMethodField()
    state = serializers.SerializerMethodField()

    class Meta:
        model = DoorPinCode
        fields = ('id', 'label', 'valid_from', 'expires_at', 'max_uses', 'use_count',
                  'is_revoked', 'revoked_at', 'state', 'created_by', 'created_at')   # KHÔNG trả pin_hash
        read_only_fields = fields

    def get_created_by(self, obj):
        return obj.created_by.username

    def get_state(self, obj):
        now = timezone.now()
        if obj.is_revoked:
            return 'revoked'
        if obj.expires_at <= now:
            return 'expired'
        if obj.valid_from > now:
            return 'scheduled'
        if obj.max_uses and obj.use_count >= obj.max_uses:
            return 'used_up'
        return 'active'


class DoorPinIssueSerializer(serializers.Serializer):
    ttl_minutes = serializers.IntegerField(min_value=1, max_value=43200, default=1440)   # tối đa 30 ngày
    max_uses = serializers.IntegerField(min_value=0, max_value=1000, default=1)          # 0 = không giới hạn
    label = serializers.CharField(max_length=100, required=False, allow_blank=True)


class FaceProfileSerializer(serializers.ModelSerializer):
    user = serializers.SerializerMethodField()

    class Meta:
        model = FaceProfile
        fields = ('id', 'user', 'name', 'is_active', 'consent_confirmed', 'created_at', 'updated_at')
        read_only_fields = fields      # KHÔNG bao giờ trả embedding (dữ liệu sinh trắc học)

    def get_user(self, obj):
        return _user_brief(obj.user)


class FaceRegisterSerializer(serializers.Serializer):
    name = serializers.CharField(max_length=100, required=False, allow_blank=True)
    embedding = serializers.ListField(child=serializers.FloatField(), min_length=32, max_length=2048)
    consent_confirmed = serializers.BooleanField()

    def validate_consent_confirmed(self, value):
        if not value:
            raise serializers.ValidationError(
                'Cần xác nhận người được đăng ký đã đồng ý thu thập dữ liệu khuôn mặt.')
        return value


class FaceProfileUpdateSerializer(serializers.Serializer):
    is_active = serializers.BooleanField()


class AccessEventSerializer(serializers.ModelSerializer):
    device = serializers.SerializerMethodField()
    user = serializers.SerializerMethodField()
    method_display = serializers.CharField(source='get_method_display', read_only=True)

    class Meta:
        model = AccessEvent
        fields = ('id', 'device', 'method', 'method_display', 'success', 'reason', 'user',
                  'confidence', 'snapshot_url', 'created_at')
        read_only_fields = fields

    def get_device(self, obj):
        return {'id': str(obj.device_id), 'name': obj.device.name}

    def get_user(self, obj):
        return _user_brief(obj.user) if obj.user_id else None


# ------------------------------------------------------------------ hỗ trợ
class SupportRequestSerializer(serializers.ModelSerializer):
    device = serializers.SerializerMethodField()
    action_display = serializers.CharField(source='get_action_display', read_only=True)
    status_display = serializers.CharField(source='get_status_display', read_only=True)

    class Meta:
        model = SupportRequest
        fields = ('id', 'device', 'action', 'action_display', 'scope', 'status', 'status_display',
                  'expires_at', 'created_at', 'completed_at')
        read_only_fields = fields    # KHÔNG trả authorization_code_hash / recovery_code_hash

    def get_device(self, obj):
        return {'id': str(obj.device_id), 'name': obj.device.name}


class SupportRequestCreateSerializer(serializers.Serializer):
    device_id = serializers.UUIDField()
    action = serializers.ChoiceField(choices=SupportRequest._meta.get_field('action').choices)
    scope = serializers.CharField(max_length=100, required=False, allow_blank=True)


# ------------------------------------------------------------------ thông báo / log / thông báo hệ thống
class NotificationSerializer(serializers.ModelSerializer):
    device = serializers.SerializerMethodField()

    class Meta:
        model = Notification
        fields = ('id', 'type', 'title', 'message', 'severity', 'is_read', 'device', 'created_at', 'read_at')
        read_only_fields = fields

    def get_device(self, obj):
        return {'id': str(obj.device_id), 'name': obj.device.name} if obj.device_id else None


class AuditLogSerializer(serializers.ModelSerializer):
    device = serializers.SerializerMethodField()
    actor = serializers.SerializerMethodField()
    target = serializers.SerializerMethodField()

    class Meta:
        model = AuditLog
        fields = ('id', 'action', 'severity', 'success', 'device', 'actor', 'target', 'created_at')
        read_only_fields = fields

    def get_device(self, obj):
        return {'id': str(obj.device_id), 'name': obj.device.name} if obj.device_id else None

    def get_actor(self, obj):
        return obj.actor_user.username if obj.actor_user_id else None

    def get_target(self, obj):
        return obj.target_user.username if obj.target_user_id else None


class AnnouncementSerializer(serializers.ModelSerializer):
    class Meta:
        model = Announcement
        fields = ('id', 'title', 'body', 'level', 'created_at')
        read_only_fields = fields


# ------------------------------------------------------------------ luật tự động hoá
class AutomationRuleSerializer(serializers.ModelSerializer):
    device = serializers.PrimaryKeyRelatedField(
        queryset=Device.objects.none(), required=False, allow_null=True)   # null = mọi thiết bị của mình
    device_name = serializers.SerializerMethodField()

    class Meta:
        model = AutomationRule
        fields = ('id', 'name', 'device', 'device_name', 'trigger_type', 'threshold_value',
                  'threshold_window_seconds', 'action_type', 'notify_severity', 'cooldown_seconds',
                  'is_active', 'last_triggered_at', 'created_at', 'updated_at')
        read_only_fields = ('id', 'last_triggered_at', 'created_at', 'updated_at')
        extra_kwargs = {
            'cooldown_seconds': {'min_value': 0, 'max_value': 7 * 24 * 3600},
            'threshold_window_seconds': {'min_value': 1, 'max_value': 86400},
        }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        request = self.context.get('request')
        if request is not None:     # chỉ cho chọn thiết bị của chính mình
            self.fields['device'].queryset = Device.objects.filter(owner=request.user)

    def get_device_name(self, obj):
        return obj.device.name if obj.device_id else None

    def validate(self, attrs):
        inst = self.instance
        trigger = attrs.get('trigger_type', inst.trigger_type if inst else None)
        threshold = attrs['threshold_value'] if 'threshold_value' in attrs else (
            inst.threshold_value if inst else None)
        if trigger != AutomationRule.TRIGGER_TAMPER_DETECTED and threshold is None:
            raise serializers.ValidationError(
                {'threshold_value': 'Bắt buộc với loại điều kiện này.'})
        if threshold is not None and threshold < 0:
            raise serializers.ValidationError({'threshold_value': 'Không được âm.'})
        if trigger == AutomationRule.TRIGGER_BATTERY_LOW and threshold is not None and threshold > 100:
            raise serializers.ValidationError({'threshold_value': 'Ngưỡng pin phải từ 0 đến 100.'})
        return attrs


class AutomationRuleLogSerializer(serializers.ModelSerializer):
    device = serializers.SerializerMethodField()

    class Meta:
        model = AutomationRuleLog
        fields = ('id', 'device', 'measured_value', 'action_taken', 'triggered_at')
        read_only_fields = fields

    def get_device(self, obj):
        return {'id': str(obj.device_id), 'name': obj.device.name} if obj.device_id else None