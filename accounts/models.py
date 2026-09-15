import uuid

from django.contrib.auth.hashers import make_password
from django.contrib.auth.models import AbstractBaseUser, BaseUserManager
from django.db import models


class UserManager(BaseUserManager):
    def create_user(self, email, password=None, **extra_fields):
        if not email:
            raise ValueError('Email là bắt buộc')
        email = self.normalize_email(email)
        user = self.model(email=email, **extra_fields)
        user.password = make_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, email, password=None, **extra_fields):
        extra_fields.setdefault('is_admin', True)
        extra_fields.setdefault('is_active', True)
        extra_fields.setdefault('email_verified', True)
        return self.create_user(email, password, **extra_fields)


class User(AbstractBaseUser):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    last_login = None  # bảng "users" không có cột này, tắt tracking mặc định của Django
    email = models.EmailField(max_length=255, unique=True)
    # password_hash bên DB <-> field "password" chuẩn của AbstractBaseUser
    password = models.CharField(max_length=255, db_column='password_hash')
    full_name = models.CharField(max_length=100, blank=True, null=True)
    phone = models.CharField(max_length=20, blank=True, null=True)
    avatar_url = models.CharField(max_length=512, blank=True, null=True)
    is_admin = models.BooleanField(default=False)
    is_owner = models.BooleanField(default=False)
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

    objects = UserManager()

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = []

    class Meta:
        managed = False
        db_table = 'users'

    def __str__(self):
        return self.email

    
class PendingRegistration(models.Model):
    """
    Map vào "public"."pending_registrations".
    Lưu OTP + dữ liệu tạm trước khi user thật sự được tạo ở bảng users.
    """
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    email = models.EmailField(max_length=255, unique=True)
    otp_code_hash = models.CharField(max_length=64)
    temp_data = models.JSONField(default=dict)
    is_used = models.BooleanField(default=False)
    expires_at = models.DateTimeField()
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        managed = False
        db_table = 'pending_registrations'

    def __str__(self):
        return self.email
