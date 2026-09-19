import os
import django
from django.db import transaction
from django.utils import timezone
import uuid
import secrets
from cryptography.fernet import Fernet

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'smartlock.settings')
from smartlock.s
from django import setup
setup()


from smartlock.models import (
    User, Device, AccessCard, CardDeviceAccess, NfcReader, NfcReaderConfig,
    ShareAccessCode, DeviceAccess, Permission, SupportRequest, Notification,
    DeviceStatusLog, AuditLog, SystemSettings
)
from smartlock.views import _hash_token

# ====================== CONFIG ======================
FERNET_KEY = os.environ.get("FERNET_KEY")
if not FERNET_KEY:
    raise RuntimeError("FERNET_KEY không tồn tại trong .env")
fernet = Fernet(FERNET_KEY.encode())

# ====================== TẠO DATA MẪU ======================
def create_demo_data():
    print("🚀 Đang tạo data mẫu demo...")

    # 1. System Settings (không ai can thiệp được)
    SystemSettings.objects.update_or_create(pk=1, defaults={
        'registration_enabled': True,
        'verification_token_expiry_minutes': 30,
        'share_code_expiry_minutes': 15,
        'login_lockout_stage_minutes': [5, 10, 30],
        'session_timeout_hours': 24,
        'ip_whitelist': '',
        'ip_blacklist': '',
    })
    print("✅ SystemSettings")

    # 2. Tạo Permissions (rất quan trọng - hệ thống dùng)
    default_perms = [
        ('UNLOCK', 'Mở khóa', 'Mở khóa từ xa', False),
        ('LOCK', 'Khóa', 'Khóa từ xa', False),
        ('ADD_CARD', 'Thêm thẻ NFC', 'Thêm thẻ NFC mới', True),
        ('REMOVE_CARD', 'Xóa thẻ NFC', 'Xóa thẻ NFC', True),
        ('RESET', 'Reset', 'Reset thiết bị', True),
        ('OTA_UPDATE', 'OTA Update', 'Cập nhật firmware', True),
    ]
    for code, name, desc, sensitive in default_perms:
        Permission.objects.get_or_create(code=code, defaults={'name': name, 'description': desc, 'is_sensitive': sensitive})
    print("✅ Permissions")

    # 3. Tạo 2 User (chủ + người dùng chung)
    owner = User.objects.create_user(email="owner@smartlock.com", username="owner", password="Demo123@",
                                     full_name="Chủ Smart Lock", is_admin=True, is_active=True, email_verified=True)
    demo_user = User.objects.create_user(email="demo@smartlock.com", username="demo_user", password="Demo123@",
                                         full_name="Người dùng demo", is_active=True, email_verified=True)
    print("✅ Users")

    # 4. Tạo thiết bị mẫu (khóa)
    device = Device.objects.create(
        device_code="SMARTLOCK-001",
        provisioning_secret_hash=_hash_token("secret1234567890"),
        owner=owner,
        is_purchased=True,
        name="Cửa thông minh phòng khách",
        status="online",
        battery_level=92,
        location="Phòng khách - Tầng 1",
        bluetooth_enabled=True,
        wifi_enabled=True,
        nfc_enabled=True
    )
    print("✅ Device")

    # 5. Tạo thẻ NFC mẫu
    card = AccessCard.objects.create(
        card_uid_hash=_hash_token("abc123456789abcdef"),
        user=demo_user,
        name="Thẻ VIP",
        is_active=True
    )
    CardDeviceAccess.objects.create(access_card=card, device=device)
    print("✅ AccessCard + CardDeviceAccess")

    # 6. Ghi dữ liệu thiết bị (giống cách views ghi)
    DeviceStatusLog.objects.create(
        device=device,
        battery_level=92,
        lock_state="locked",
        signal_strength=88,
        temperature=28.5,
        raw_payload={"battery": 92, "lock": "locked", "temp": 28.5}
    )
    print("✅ DeviceStatusLog")

    # 7. Ghi dữ liệu NFC
    reader = NfcReader.objects.create(device=device, reader_mode="simulated", name="Đầu đọc NFC", is_active=True)
    NfcReaderConfig.objects.create(reader=reader, auto_register=True, grant_permission=["UNLOCK", "LOCK"])
    print("✅ NfcReader + NfcReaderConfig")

    # 8. Tạo mã chia sẻ (chỉ chủ được tạo - user chỉ được nhận)
    share_code = ShareAccessCode.objects.create(
        device=device,
        created_by=owner,
        expires_at=timezone.now() + timedelta(hours=24)
    )
    plain = f"{secrets.randbelow(10**6):06d}"
    share_code.set_code(plain)
    share_code.permissions.set(Permission.objects.filter(code__in=["UNLOCK", "LOCK"]))
    share_code.save()
    print("✅ ShareAccessCode")

    # 9. Ghi dữ liệu quyền chia sẻ
    DeviceAccess.objects.create(
        device=device, user=demo_user, source="SHARE_CODE",
        valid_from=timezone.now(), expires_at=timezone.now() + timedelta(hours=24),
        accepted=True, created_by=owner
    )
    print("✅ DeviceAccess")

    # 10. Ghi dữ liệu hỗ trợ
    SupportRequest.objects.create(
        device=device, requested_by=owner, action="RESET_REMOTE",
        authorization_code_hash=_hash_token("auth123"),
        recovery_code_hash=_hash_token("rec123"),
        expires_at=timezone.now() + timedelta(hours=24),
        status="pending"
    )
    print("✅ SupportRequest")

    # 11. Ghi dữ liệu hệ thống
    Notification.objects.create(user=owner, device=device, type="SYSTEM", title="Demo đã sẵn sàng", message="Tất cả đã được tạo")
    AuditLog.objects.create(actor_user=owner, device=device, action="DEVICE_CLAIMED", success=True)
    print("✅ Notification + AuditLog")

    print("\n🎉 DATA MẪU ĐÃ TẠO HOÀN TẤT!")
    print("   Chủ: owner@smartlock.com | Mật khẩu: Demo123@")
    print("   Người dùng: demo@smartlock.com | Mật khẩu: Demo123@")
    print("   Thiết bị: SMARTLOCK-001 (cửa phòng khách)")
    print("   Thẻ NFC: abc123456789abcdef (gán vào thiết bị)")
    print("   Mã chia sẻ: [sẽ chạy được khi test]")

if __name__ == "__main__":
    create_demo_data()