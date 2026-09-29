# smartlock/api/auth_serializers.py
from rest_framework import serializers


class ClientInfoMixin(serializers.Serializer):
    """Thông tin máy - app gửi kèm khi đăng nhập để hiển thị ở mục "Thiết bị đang đăng nhập"."""
    device_name = serializers.CharField(max_length=100, required=False, allow_blank=True, default='')
    platform = serializers.ChoiceField(choices=['android', 'ios', 'web'], required=False, default='android')
    app_version = serializers.CharField(max_length=30, required=False, allow_blank=True, default='')
    fcm_token = serializers.CharField(max_length=512, required=False, allow_blank=True, default='')


class LoginSerializer(ClientInfoMixin):
    identifier = serializers.CharField(max_length=150)              # email hoặc username
    password = serializers.CharField(trim_whitespace=False, max_length=256)


class TwoFactorVerifySerializer(ClientInfoMixin):
    pending_token = serializers.CharField()
    method = serializers.ChoiceField(choices=['totp', 'email'])
    code = serializers.CharField(max_length=16)


class PendingTokenSerializer(serializers.Serializer):
    pending_token = serializers.CharField()


class RefreshSerializer(serializers.Serializer):
    refresh_token = serializers.CharField()


class RegisterSerializer(serializers.Serializer):
    email = serializers.EmailField(max_length=254)
    username = serializers.CharField(max_length=50)
    full_name = serializers.CharField(max_length=100, required=False, allow_blank=True, default='')
    password1 = serializers.CharField(trim_whitespace=False, max_length=256)
    password2 = serializers.CharField(trim_whitespace=False, max_length=256)


class EmailOnlySerializer(serializers.Serializer):
    email = serializers.EmailField(max_length=254)


class PasswordResetConfirmSerializer(serializers.Serializer):
    uid = serializers.CharField()
    token = serializers.CharField()
    new_password1 = serializers.CharField(trim_whitespace=False, max_length=256)
    new_password2 = serializers.CharField(trim_whitespace=False, max_length=256)


class PushTokenSerializer(serializers.Serializer):
    fcm_token = serializers.CharField(max_length=512)
    enabled = serializers.BooleanField(required=False, default=True)


# ------------------------------------------------------------------ quản lý 2FA
class PasswordSerializer(serializers.Serializer):
    password = serializers.CharField(trim_whitespace=False, max_length=256)


class TotpConfirmSerializer(serializers.Serializer):
    setup_token = serializers.CharField()
    code = serializers.CharField(max_length=16)


class EmailSendSerializer(serializers.Serializer):
    purpose = serializers.ChoiceField(choices=['setup', 'verify'], required=False, default='setup')


class CodeSerializer(serializers.Serializer):
    code = serializers.CharField(max_length=16)


class RemoveMethodSerializer(serializers.Serializer):
    method = serializers.ChoiceField(choices=['totp', 'email'])
    password = serializers.CharField(trim_whitespace=False, max_length=256)


class DisableTwoFactorSerializer(serializers.Serializer):
    password = serializers.CharField(trim_whitespace=False, max_length=256)
    method = serializers.ChoiceField(choices=['totp', 'email'], required=False)
    code = serializers.CharField(max_length=16, required=False, allow_blank=True)