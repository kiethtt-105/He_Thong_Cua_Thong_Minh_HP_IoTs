import os
import sys
import django
from django.utils import timezone
from datetime import timedelta
from cryptography.fernet import Fernet

# ====================== KHỞI TẠO DJANGO ĐÚNG CÁCH ======================
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, BASE_DIR)

# Set environment variable theo đúng thư mục dự án của bạn
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'smartlock_django.settings')

# Khởi tạo Django
django.setup()

from smartlock.models import (
    User, Device, AccessCard, CardDeviceAccess, DeviceAccess, Permission
)
from smartlock.views import _hash_token

# ====================== KEY FERNET ======================
FERNET_KEY = os.environ.get("FERNET_KEY")
if not FERNET_KEY:
    raise RuntimeError("FERNET_KEY không tồn tại trong .env")
fernet = Fernet(FERNET_KEY.encode())

# ====================== TẠO DATA MẪU CHỈ KHÓA + THẺ ======================
def create_demo_data():
    print("🚀 Đang tạo data mẫu chỉ khóa + thẻ...")

    # 1. Tạo Permissions 
    default_perms = [
        ('UNLOCK', 'Mở khóa', 'Mở khóa từ xa', False),
        ('LOCK', 'Khóa', 'Khóa từ xa', False),
    ]
    for code, name, desc, sensitive in default_perms:
        Permission.objects.get_or_create(code=code, defaults={'name': name, 'description': desc, 'is_sensitive': sensitive})
    print("✅ Permissions")

    # 2. Tạo Admin Superuser 
    admin_superuser = User.objects.create_superuser(
        email="admin@smartlock.com",
        username="admin_superuser",
        password="Admin123@",
        full_name="Admin Superuser",
        is_admin=True,
        is_active=True,
        email_verified=True
    )
    print("✅ Admin Superuser")

    # 3. Tạo 2 User 
    owner = User.objects.create_user(email="mowner@smartlock.co", username="owner", password="Demo123@",
                                     full_name="Chủ Smart Lock", is_active=True, email_verified=True)
    demo_user = User.objects.create_user(email="demo@smartlock.com", username="demo_user", password="Demo123@",
                                         full_name="Người dùng demo", is_active=True, email_verified=True)
    print("✅ Users")

    # 4. Tạo thiết bị mẫu 
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

    # 5. Tạo thẻ NFC
    card = AccessCard.objects.create(
        card_uid_hash=_hash_token("abc123456789abcdef"),
        user=demo_user,
        name="Thẻ VIP",
        is_active=True
    )
    CardDeviceAccess.objects.create(access_card=card, device=device)
    print("✅ AccessCard + CardDeviceAccess")

    # 6. Ghi dữ liệu quyền chia sẻ (DeviceAccess) 
    DeviceAccess.objects.create(
        device=device,
        user=demo_user,
        source="DIRECT",
        valid_from=timezone.now(),
        expires_at=timezone.now() + timedelta(hours=24),
        accepted=True,
        created_by=admin_superuser
    )
    DeviceAccess.objects.last().permissions.set(Permission.objects.filter(code__in=["UNLOCK", "LOCK"]))
    print("✅ DeviceAccess (quyền chia sẻ)")

    print("\n🎉 DATA MẪU ĐÃ TẠO HOÀN TẤT!")
    print("   • Admin Superuser: admin@smartlock.com | Mật khẩu: Admin123@")
    print("   • Chủ: owner@smartlock.com | Mật khẩu: Demo123@")
    print("   • Thiết bị: SMARTLOCK-001")
    print("   • Thẻ NFC: abc123456789abcdef")
    print("   • Quyền chia sẻ cho demo_user đã được ghi (chỉ admin_superuser có thể tạo quyền)")

if __name__ == "__main__":
    create_demo_data()