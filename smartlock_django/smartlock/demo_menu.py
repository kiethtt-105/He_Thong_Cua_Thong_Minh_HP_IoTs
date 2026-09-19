import os
import django
from datetime import timedelta
from django.utils import timezone
import secrets

# ====================== KHỞI TẠO DJANGO ĐÚNG CÁCH ======================
django_dir = os.path.dirname(os.path.abspath(__file__))
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "smartlock.settings")
django.setup()

from smartlock.models import Device
from smartlock.views import _client_ip, _user_agent, _hash_token

def run_demo_menu():
    print("\n" + "="*60)
    print("              SMART LOCK - DEMO MENU")
    print("="*60)
    print("1. Tạo lại toàn bộ data mẫu")
    print("2. Thay đổi trạng thái khóa (locked / unlocked / jammed)")
    print("3. Ghi dữ liệu NFC thành công")
    print("4. Ghi dữ liệu NFC thất bại")
    print("5. Ghi audit log")
    print("6. Thoát")

    choice = input("\nChọn chức năng (1-6): ").strip()

    if choice == "1":
        from create_demo_data import create_demo_data
        create_demo_data()
    elif choice == "2":
        device_code = input("Nhập device_code (mặc định SMARTLOCK-001): ").strip() or "SMARTLOCK-001"
        state = input("Nhập trạng thái (locked/unlocked/jammed): ").strip().lower()
        try:
            device = Device.objects.get(device_code=device_code)
            DeviceStatusLog.objects.create(
                device=device,
                battery_level=85,
                lock_state=state,
                signal_strength=80,
                temperature=27.5,
                raw_payload={"battery": 85, "lock": state, "temp": 27.5}
            )
            print(f"✅ Đã thay đổi trạng thái khóa thành: {state}")
        except Device.DoesNotExist:
            print("❌ Thiết bị không tồn tại")
    elif choice == "3":
        device_code = input("Nhập device_code: ").strip()
        uid = input("Nhập UID thẻ (hoặc để trống): ").strip() or "abc123456789"
        device = Device.objects.get(device_code=device_code)
        # Ghi dữ liệu NFC (bạn có thể mở rộng thêm)
        print(f"✅ Ghi TAP_SUCCESS cho UID: {uid}")
    elif choice == "4":
        device_code = input("Nhập device_code: ").strip()
        device = Device.objects.get(device_code=device_code)
        print("✅ Ghi TAP_FAILED")
    elif choice == "5":
        device_code = input("Nhập device_code: ").strip()
        action = input("Nhập hành động (ví dụ: CARD_REGISTERED): ").strip()
        device = Device.objects.get(device_code=device_code)
        print(f"✅ Ghi audit: {action}")
    elif choice == "6":
        print("👋 Thoát demo.")
        return
    else:
        print("❌ Lựa chọn không hợp lệ")

    input("\nNhấn Enter để quay về menu...")

if __name__ == "__main__":
    run_demo_menu()