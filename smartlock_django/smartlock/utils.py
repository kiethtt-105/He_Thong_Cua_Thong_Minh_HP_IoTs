import hashlib
import hmac
import logging
import math
import re
import secrets
import uuid
from datetime import datetime, timedelta
from typing import Optional

from django.conf import settings
from django.contrib import messages
from django.core.exceptions import ValidationError
from django.db.models import Q
from django.http import HttpRequest
from django.shortcuts import redirect, render
from django.urls import reverse
from django.utils import timezone

from .models import (
    AccessCard, AuditLog, Device, DeviceAccess, EmailVerificationToken,
    LoginAttemptLog, LoginLockout, NfcLog, NfcReader, Notification,
    Permission, ShareAccessCode, SupportRequest, SystemSettings, User,
    DeviceCommand, DeviceStatusLog, fernet,
)

logger = logging.getLogger('smartlock.utils')


class SmartlockUtils:
    MAX_FAILED_ATTEMPTS = 5
    SHARED_ACCESS_HOURS = 24
    SUPPORT_TTL_HOURS = 24
    PAGE_SIZE = 20
    COMMAND_TTL_SECONDS = 120
    ALLOWED_COMMANDS = {'LOCK': 'LOCK', 'UNLOCK': 'UNLOCK', 'REBOOT': None}
    RECOVERY_ACTIONS = ('RESET_REMOTE', 'RECOVERY', 'TRANSFER_OWNER')

    @staticmethod
    def send_mail(subject: str, plain: str, html: str, to: str) -> bool:
        logger.info("send_mail: to=%s subject=%r", to, subject)
        try:
            from django.core.mail import send_mail
            n = send_mail(subject, plain, settings.FROM_EMAIL, [to], html_message=html)
            logger.info("send_mail: OK (%s mail) -> %s", n, to)
            return True
        except Exception:
            logger.exception("send_mail: THẤT BẠI -> %s", to)
            return False

    @staticmethod
    def hash_token(token: str) -> str:
        return hashlib.sha256(str(token).encode()).hexdigest()

    @staticmethod
    def client_ip(request: HttpRequest) -> str:
        xff = request.META.get('HTTP_X_FORWARDED_FOR')
        return xff.split(',')[0].strip() if xff else request.META.get('REMOTE_ADDR') or '0.0.0.0'

    @staticmethod
    def user_agent(request: HttpRequest) -> str:
        return (request.META.get('HTTP_USER_AGENT') or '')[:500]

    @staticmethod
    def settings():
        return SystemSettings.objects.get_or_create(pk=1)[0]

    @staticmethod
    def is_admin(user: User) -> bool:
        return bool(user.is_staff or user.is_superuser or user.is_admin)

    @staticmethod
    def parse_uuid(value: str) -> Optional[uuid.UUID]:
        try:
            return uuid.UUID(str(value))
        except (ValueError, AttributeError, TypeError):
            return None

    @staticmethod
    def parse_dt(value: str) -> Optional[datetime]:
        if not value:
            return None
        try:
            return timezone.make_aware(datetime.strptime(value, '%Y-%m-%dT%H:%M'))
        except ValueError:
            return None

    @staticmethod
    def find_user(identifier: str) -> Optional[User]:
        identifier = (identifier or '').strip()
        if not identifier:
            return None
        return User.objects.filter(Q(email__iexact=identifier) | Q(username__iexact=identifier)).first()

    @staticmethod
    def audit(request: HttpRequest, action: str, *, device=None, target_user=None,
              success=True, severity='info', metadata=None, actor='auto', username_attempt=None):
        if actor == 'auto':
            actor = request.user if request.user.is_authenticated else None
        try:
            AuditLog.objects.create(
                actor_user=actor, target_user=target_user, device=device,
                action=action[:50], username_attempt=username_attempt,
                severity=severity, success=success,
                ip_address=SmartlockUtils.client_ip(request),
                user_agent=SmartlockUtils.user_agent(request),
                metadata=metadata,
            )
        except Exception:
            logger.exception("audit: không ghi được log %s", action)

    @staticmethod
    def notify(user: User, title: str, message: str, severity='info', device=None, type_='SYSTEM'):
        Notification.objects.create(user=user, device=device, type=type_, title=title[:150], message=message, severity=severity)

    @staticmethod
    def ip_blacklisted(ip: str) -> bool:
        st = SmartlockUtils.settings()
        lines = [l.strip() for l in (st.ip_blacklist or '').splitlines()]
        return ip in [l for l in lines if l]

    @staticmethod
    def accessible_devices(user: User):
        now = timezone.now()
        shared_ids = (
            DeviceAccess.objects.filter(user=user, is_active=True, accepted=True, valid_from__lte=now)
            .filter(Q(expires_at__isnull=True) | Q(expires_at__gt=now))
            .values('device_id')
        )
        return Device.objects.filter(Q(owner=user) | Q(id__in=shared_ids))

    @staticmethod
    def has_permission(user: User, device: Device, code: str) -> bool:
        if device.owner_id == user.id:
            return True
        now = timezone.now()
        return DeviceAccess.objects.filter(
            device=device, user=user, is_active=True, accepted=True,
            valid_from__lte=now, permissions__code=code
        ).filter(Q(expires_at__isnull=True) | Q(expires_at__gt=now)).exists()

    @staticmethod
    def pick_device(queryset, raw_id: str):
        dev_id = SmartlockUtils.parse_uuid(raw_id)
        device = queryset.filter(id=dev_id).first() if dev_id else None
        return device or queryset.first()

    @staticmethod
    def ensure_default_permissions():
        from .models import Permission
        if not Permission.objects.exists():
            for code, name, desc, sensitive in DEFAULT_PERMISSIONS:
                Permission.objects.get_or_create(
                    code=code, defaults={'name': name, 'description': desc, 'is_sensitive': sensitive}
                )

    @staticmethod
    def register_failure(user: User, ip: str):
        st = SmartlockUtils.settings()
        stages = st.login_lockout_stage_minutes or [5, 10, 30]
        now = timezone.now()
        lock, _ = LoginLockout.objects.get_or_create(user=user)
        lock.failed_attempts += 1
        lock.last_failed_at = now
        lock.last_failed_ip = ip
        if lock.failed_attempts >= MAX_FAILED_ATTEMPTS:
            minutes = stages[min(lock.stage, len(stages) - 1)]
            lock.locked_until = now + timedelta(minutes=minutes)
            lock.stage += 1
            lock.failed_attempts = 0
            SmartlockUtils.notify(user, 'Tài khoản bị khóa tạm thời',
                                  f'Đăng nhập sai nhiều lần từ IP {ip}. Tài khoản bị khóa {minutes} phút.',
                                  severity='critical', type_='LOGIN_LOCKOUT')
        lock.save()

    @staticmethod
    def reset_lockout(user: User):
        LoginLockout.objects.filter(user=user).update(
            failed_attempts=0, stage=0, locked_until=None,
        )

    @staticmethod
    def send_verification(request, user: User):
        st = SmartlockUtils.settings()
        minutes = st.verification_token_expiry_minutes
        EmailVerificationToken.objects.filter(
            user=user, purpose='EMAIL_VERIFY', is_used=False,
        ).update(is_used=True, used_at=timezone.now())

        token = uuid.uuid4()
        EmailVerificationToken.objects.create(
            user=user, purpose='EMAIL_VERIFY', token_hash=SmartlockUtils.hash_token(token),
            expires_at=timezone.now() + timedelta(minutes=minutes),
        )
        link = request.build_absolute_uri(reverse('smartlock:verify_email', args=[token]))
        context = {
            'full_name': user.full_name or user.username,
            'username': user.username,
            'verification_link': link,
            'expiry_minutes': minutes,
        }
        subject, html, plain = render_email('user_verification.html', context)
        return SmartlockUtils.send_mail(subject, plain, html, user.email)

    @staticmethod
    def page(request, queryset):
        from django.core.paginator import Paginator
        return Paginator(queryset, PAGE_SIZE).get_page(request.GET.get('page'))