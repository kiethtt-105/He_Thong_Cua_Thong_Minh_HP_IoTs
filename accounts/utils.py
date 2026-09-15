import hashlib
import secrets

from django.conf import settings
from django.core.mail import send_mail


def generate_otp() -> str:
    """OTP 6 chữ số, sinh bằng CSPRNG (secrets), không dùng random thường."""
    return f'{secrets.randbelow(1_000_000):06d}'


def hash_otp(otp: str) -> str:
    """Chỉ lưu SHA-256 hex của OTP xuống DB, đúng comment trong file SQL."""
    return hashlib.sha256(otp.encode('utf-8')).hexdigest()


def send_otp_email(email: str, otp: str) -> None:
    send_mail(
        subject='[Smart Lock IoT] Mã xác thực đăng ký',
        message=(
            f'Mã OTP của bạn là: {otp}\n'
            f'Mã có hiệu lực trong 10 phút. Không chia sẻ mã này cho bất kỳ ai.'
        ),
        from_email=settings.DEFAULT_FROM_EMAIL,
        recipient_list=[email],
        fail_silently=False,
    )
