"""2FA dùng chung cho web + app: hash OTP, TOTP, mã email, khoá tạm thời.

Tách ra từ views.py để API không phải import views (xoá view sau này không làm hỏng API).
"""
import hashlib
import hmac
import math
import re
import secrets
from datetime import timedelta

import pyotp
from django.conf import settings
from django.db import transaction
from django.utils import timezone

from .models import OneTimeCode, TwoFactorConfig, User
from .services import render_email, send_mail

EMAIL_CODE_TTL_MIN = 10
EMAIL_CODE_COOLDOWN = 60               # giây giữa 2 lần gửi mã
EMAIL_CODE_MAX_ATTEMPTS = 5


def pepper_hash(user, value: str) -> str:
    """HMAC-SHA256 gắn với SECRET_KEY + user để lưu hash của mã OTP."""
    msg = f'{user.pk}:{value}'.encode()
    return hmac.new(settings.SECRET_KEY.encode(), msg, hashlib.sha256).hexdigest()


def digits(value) -> str:
    return re.sub(r'\D', '', value or '')


def get_cfg(user) -> TwoFactorConfig:
    return TwoFactorConfig.objects.get_or_create(user=user)[0]


def verify_totp(cfg: TwoFactorConfig, code: str) -> bool:
    """Kiểm tra mã TOTP (±1 bước 30s) và chặn dùng lại cùng một mã (replay)."""
    code = digits(code)
    secret = cfg.get_totp_secret()
    if len(code) != 6 or not secret:
        return False
    totp = pyotp.TOTP(secret)
    step_now = int(timezone.now().timestamp() // totp.interval)
    with transaction.atomic():
        locked = TwoFactorConfig.objects.select_for_update().get(pk=cfg.pk)
        for offset in (-1, 0, 1):
            step = step_now + offset
            if step <= locked.totp_last_step:
                continue
            if hmac.compare_digest(totp.at(step * totp.interval), code):
                locked.totp_last_step = step
                locked.save(update_fields=['totp_last_step', 'updated_at'])
                return True
    return False


def send_email_code(user, purpose):
    """purpose: 'SETUP' (thiết lập Email OTP) hoặc 'VERIFY' (login/enable/disable).
    Trả về 'sent' | 'cooldown' | 'failed'."""
    now = timezone.now()
    if OneTimeCode.objects.filter(
            user=user, purpose__in=('TF_SETUP', 'TF_VERIFY'),
            created_at__gt=now - timedelta(seconds=EMAIL_CODE_COOLDOWN)).exists():
        return 'cooldown'
    code = f'{secrets.randbelow(10 ** 6):06d}'
    OneTimeCode.objects.filter(user=user, purpose__in=('TF_SETUP', 'TF_VERIFY'),
                               is_used=False).update(is_used=True)
    OneTimeCode.objects.create(
        user=user, purpose='TF_' + purpose, token_hash=pepper_hash(user, 'em:' + code),
        expires_at=now + timedelta(minutes=EMAIL_CODE_TTL_MIN),
    )
    subject, html, plain = render_email('two_factor_code', {
        'full_name': user.full_name or user.username,
        'otp_code': code,
        'expiry_minutes': EMAIL_CODE_TTL_MIN,
    })
    return 'sent' if send_mail(subject, plain, html, user.email, log_body=False) else 'failed'


def verify_email_code(user, code, purpose) -> bool:
    code = digits(code)
    if len(code) != 6:
        return False
    with transaction.atomic():
        rec = OneTimeCode.objects.select_for_update().filter(
            user=user, purpose='TF_' + purpose, is_used=False, expires_at__gt=timezone.now(),
        ).order_by('-created_at').first()
        if not rec:
            return False
        rec.attempts += 1
        if rec.attempts > EMAIL_CODE_MAX_ATTEMPTS:
            rec.is_used = True
            rec.save(update_fields=['attempts', 'is_used'])
            return False
        ok = hmac.compare_digest(rec.token_hash, pepper_hash(user, 'em:' + code))
        if ok:
            rec.is_used = True
        rec.save(update_fields=['attempts', 'is_used'])
        return ok


def lock_minutes(user) -> int:
    locked_until = User.objects.filter(pk=user.pk).values_list('login_locked_until', flat=True).first()
    now = timezone.now()
    if locked_until and locked_until > now:
        return math.ceil((locked_until - now).total_seconds() / 60)
    return 0
