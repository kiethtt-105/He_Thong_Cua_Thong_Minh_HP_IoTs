#!/usr/bin/env python
"""
testmail.py - Gửi thử TẤT CẢ email template của dự án đến một hộp thư để xem thực tế.
Đặt cạnh manage.py.

    python testmail.py                     # chạy xong sẽ hỏi email nhận
    python testmail.py ban@gmail.com       # bỏ qua bước hỏi
    python testmail.py --base-url https://ten-mien.vercel.app

Lưu ý: link/mã trong email chỉ là DỮ LIỆU MẪU (token giả), bấm vào sẽ báo không hợp lệ.
"""
import logging
import os
import re
import sys
import time
from pathlib import Path

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")
    sys.stderr.reconfigure(encoding="utf-8")

BASE_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(BASE_DIR))
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "smartlock_django.settings")

EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
DELAY_SECONDS = 1.0  # nghỉ giữa các email để Gmail không coi là spam


def guess_base_url(settings):
    for host in getattr(settings, "ALLOWED_HOSTS", []):
        if host and host not in ("localhost", "127.0.0.1", "0.0.0.0", "*") and not host.startswith("."):
            return f"https://{host}"
    return "http://localhost:8000"


def sample_context(name, base, reset_minutes):
    base = base.rstrip("/")
    samples = {
        "user_verification.html": dict(
            full_name="Trần Tuấn Kiệt", username="kiethtt", expiry_minutes=30,
            verification_link=f"{base}/verify-email/3f2c9d1e-8a4b-4c1f-9e2a-7d5b6c0a1f34/"),
        # views.py truyền 'reset_link' -> giữ đúng key này để test luôn phần ánh xạ biến
        "password_reset.html": dict(
            full_name="Trần Tuấn Kiệt", expiry_minutes=reset_minutes,
            reset_link=f"{base}/reset-password/ZWYyNTgwMGQtOWFmNC00NDlm/df7bca-a4048054bf2b7caa6f54f89e9b60aa51/"),
        "device_added.html": dict(
            full_name="Nguyễn Văn A", device_name="Cửa chính - Tầng 1", device_code="SL-ESP32-0A41",
            action_url=f"{base}/dashboard/"),
        "share_code_notification.html": dict(
            full_name="Nguyễn Văn A", device_name="Cửa chính - Tầng 1", share_code="482951",
            expiry_minutes=10, action_url=f"{base}/dashboard/"),
        "admin_nfc_approval.html": dict(
            user_email="user@example.com", card_name="Thẻ nhân viên", card_uid="04:A2:3B:19:7C:80",
            action_url=f"{base}/admin-sys/"),
        "admin_device_approval.html": dict(
            user_email="user@example.com", device_code="SL-ESP32-0A41", action_url=f"{base}/admin-sys/"),
        "recovery_notification.html": dict(
            full_name="Nguyễn Văn A", device_name="Cửa chính - Tầng 1"),
        "system_announcement.html": dict(
            title="Bảo trì hệ thống",
            body="Hệ thống sẽ bảo trì từ 23:00 đến 23:30 ngày 25/09.\n\nTrong thời gian này bạn không thể điều khiển khóa từ xa.",
            action_url=base, action_label="Xem chi tiết"),
    }
    generic = dict(
        full_name="Người dùng mẫu", username="nguoidung", user_email="user@example.com",
        device_name="Cửa chính - Tầng 1", device_code="SL-ESP32-0A41", card_name="Thẻ mẫu",
        card_uid="04:A2:3B:19:7C:80", share_code="123456", expiry_minutes=10,
        body="Nội dung thông báo mẫu.", title="Thông báo mẫu", action_url=f"{base}/dashboard/",
    )
    return samples.get(name, generic)


def ask_email():
    while True:
        try:
            value = input("Nhập email nhận thư thử (Enter để thoát): ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            return None
        if not value:
            return None
        if EMAIL_RE.match(value):
            return value
        print("  Email không hợp lệ, thử lại.")


def main():
    args = [a for a in sys.argv[1:]]
    base_url = None
    if "--base-url" in args:
        i = args.index("--base-url")
        base_url = args[i + 1] if i + 1 < len(args) else None
        del args[i:i + 2]
    to_addr = args[0] if args else None

    try:
        import django
        django.setup()
        from django.conf import settings
        from django.core.mail import EmailMultiAlternatives
        from smartlock.email_templates import EMAIL_TEMPLATES, render_email
    except Exception as exc:  # noqa: BLE001
        print(f"[LỖI] Không khởi tạo được Django: {type(exc).__name__}: {exc}")
        print("      Kiểm tra: đã activate .venv chưa? file .env có DJANGO_SECRET_KEY chưa?")
        return 2

    logging.getLogger("smartlock.email").setLevel(logging.WARNING)  # bớt log INFO ồn ào

    print("=" * 60)
    print(" GỬI THỬ TẤT CẢ EMAIL TEMPLATE - SMART LOCK")
    print("=" * 60)
    print(f" Gửi từ : {settings.DEFAULT_FROM_EMAIL or '(chưa đặt DEFAULT_FROM_EMAIL!)'}")
    print(f" SMTP   : {settings.EMAIL_HOST}:{settings.EMAIL_PORT}")
    if "smtp" not in settings.EMAIL_BACKEND.lower():
        print(f" [!] EMAIL_BACKEND = {settings.EMAIL_BACKEND} (không phải SMTP, thư có thể không được gửi thật)")
    print()

    if not to_addr:
        to_addr = ask_email()
    elif not EMAIL_RE.match(to_addr):
        print(f"[LỖI] Email không hợp lệ: {to_addr}")
        return 2
    if not to_addr:
        print("Đã hủy.")
        return 0

    base_url = base_url or guess_base_url(settings)
    reset_minutes = getattr(settings, "PASSWORD_RESET_TIMEOUT", 259200) // 60
    names = list(EMAIL_TEMPLATES.keys())

    print(f"\nSẽ gửi {len(names)} email đến: {to_addr}")
    print(f"Domain trong link mẫu: {base_url}\n")

    ok = fail = 0
    for idx, name in enumerate(names, 1):
        label = f"[{idx}/{len(names)}] {name}"
        try:
            subject, html, plain = render_email(name, sample_context(name, base_url, reset_minutes))
            msg = EmailMultiAlternatives(f"[TEST {idx}/{len(names)}] {subject}", plain,
                                         settings.DEFAULT_FROM_EMAIL, [to_addr])
            msg.attach_alternative(html, "text/html")
            msg.send(fail_silently=False)
            print(f"  ✔ {label}")
            ok += 1
        except Exception as exc:  # noqa: BLE001
            print(f"  ✘ {label}\n      {type(exc).__name__}: {exc}")
            fail += 1
            if "auth" in str(exc).lower() or "535" in str(exc):
                print("      Gợi ý: Gmail cần App Password 16 ký tự (bật xác minh 2 bước), không dùng mật khẩu thường.")
                break  
        if idx < len(names):
            time.sleep(DELAY_SECONDS)

    print("\n" + "-" * 60)
    print(f" Kết quả: {ok} thành công, {fail} thất bại")
    if ok:
        print(f" Mở hộp thư {to_addr} để xem (Kiểm tra mục Spam).")
    print("-" * 60)
    return 0 if fail == 0 else 1


if __name__ == "__main__":
    sys.exit(main())