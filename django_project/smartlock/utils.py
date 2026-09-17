"""
Các hàm tiện ích dùng cho luồng đăng ký + xác thực email bằng OTP.
"""
import hashlib
import secrets

from django.conf import settings
from django.core.mail import send_mail


def generate_otp(length: int = 6) -> str:
    """Sinh một mã OTP ngẫu nhiên gồm `length` chữ số (dùng secrets cho an toàn)."""
    return ''.join(str(secrets.randbelow(10)) for _ in range(length))


def hash_otp(code: str) -> str:
    """Băm mã OTP bằng SHA-256 trước khi lưu vào DB (không lưu OTP dạng plain-text)."""
    return hashlib.sha256(code.encode('utf-8')).hexdigest()


def send_otp_email(to_email: str, code: str, purpose: str = "xác thực tài khoản") -> None:
    """Gửi mã OTP tới email người dùng thông qua backend SMTP đã cấu hình trong settings.py."""
    subject = f"[SmartLock] Mã OTP {purpose}"
    message = (
        f"Xin chào,\n\n"
        f"Mã OTP của bạn là: {code}\n"
        f"Mã có hiệu lực trong {settings.OTP_EXPIRY_MINUTES} phút.\n\n"
        f"Vui lòng không chia sẻ mã này cho bất kỳ ai, kể cả nhân viên hỗ trợ.\n"
        f"Nếu bạn không thực hiện yêu cầu này, vui lòng bỏ qua email."
    )
    send_mail(
        subject=subject,
        message=message,
        from_email=settings.DEFAULT_FROM_EMAIL,
        recipient_list=[to_email],
        fail_silently=False,
    )


def mask_email(email: str) -> str:
    """Che bớt email để hiển thị trên UI, ví dụ: k***t@drive015.com"""
    try:
        name, domain = email.split('@', 1)
    except ValueError:
        return email
    if len(name) <= 2:
        masked = name[0] + '*'
    else:
        masked = name[0] + '*' * (len(name) - 2) + name[-1]
    return f"{masked}@{domain}"
