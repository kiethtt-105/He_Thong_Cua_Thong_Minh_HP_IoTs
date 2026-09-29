# smartlock/models_mobile.py
"""
Phiên đăng nhập của app di động (Android).

Mỗi lần cài app / đăng nhập = 1 MobileSession:
  - refresh token chỉ lưu HASH (SHA-256), xoay vòng mỗi lần refresh; giữ hash cũ để phát hiện
    dùng lại token cũ (dấu hiệu bị đánh cắp) -> huỷ cả phiên;
  - fcm_token: token push Firebase của máy đó;
  - thu hồi được từng phiên (đăng xuất từ xa) và bị thu hồi hàng loạt khi đổi/đặt lại mật khẩu.

CÁCH GẮN: cuối smartlock/models.py thêm đúng 1 dòng
    from .models_mobile import MobileSession  # noqa: E402,F401
rồi chạy: python manage.py makemigrations smartlock && python manage.py migrate
"""
import uuid

from django.db import models
from django.utils import timezone

from .models import User


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