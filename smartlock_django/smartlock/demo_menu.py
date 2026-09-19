import os
import sys
import django
from datetime import timedelta
from django.utils import timezone

# ====================== KHỞI TẠO DJANGO ĐÚNG CÁCH ======================
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, BASE_DIR)

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'smartlock_django.settings')
django.setup()
def run_demo_menu():
    print("\n" + "="*60)
    print("              SMART LOCK - DEMO MENU (Chỉ Khóa + Thẻ)")
    print("="*60)
    print("1. Tạo lại data mẫu chỉ khóa + thẻ")
    print("2. Thay đổi trạng thái khóa (locked / unlocked / jammed)")
    print("3. Thoát")

    choice = input("\nChọn chức năng (1-3): ").strip()

    if choice == "1":
        from create_demo_data import create_demo_data
        create_demo_data()
    elif choice == "2":
        device_code = input("Nhập device_code (mặc định SMARTLOCK-001): ").strip() or "SMARTLOCK-001"
        state = input("Nhập trạng thái (locked/unlocked/jammed): ").strip().lower()
        try:
            device = Device.objects.get(device_code=device_code)
            DeviceStatusLog.objects.create(  # bạn có thể thêm nếu muốn
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
        print("👋 Thoát demo.")
        return
    else:
        print("❌ Lựa chọn không hợp lệ")

    input("\nNhấn Enter để quay về menu...")

if __name__ == "__main__":
    run_demo_menu()