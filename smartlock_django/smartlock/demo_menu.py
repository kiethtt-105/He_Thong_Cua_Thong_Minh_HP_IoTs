import os
import django
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'smartlock.settings')
django.setup()

from create_demo_data import create_demo_data
from smartlock.models import Device, AccessCard, CardDeviceAccess, DeviceStatusLog, NfcLog, AuditLog
from smartlock.views import _client_ip, _user_agent, _hash_token
from datetime import timedelta
import secrets

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
            AuditLog.objects.create(
                actor_user=None, device=device, action=f"STATUS_CHANGE_{state.upper()}",
                success=True, ip_address=_client_ip(None), user_agent=_user_agent(None)
            )
            print(f"✅ Đã thay đổi trạng thái khóa thành: {state}")
        except Device.DoesNotExist:
            print("❌ Thiết bị không tồn tại")
    elif choice == "3":
        device_code = input("Nhập device_code: ").strip()
        uid = input("Nhập UID thẻ (hoặc để trống): ").strip()
        if not uid:
            uid = "abc123456789"
        device = Device.objects.get(device_code=device_code)
        NfcLog.objects.create(
            device=device,
            event_type="TAP_SUCCESS",
            success=True,
            metadata={"card_uid": uid, "timestamp": timezone.now().isoformat()}
        )
        print("✅ Ghi TAP_SUCCESS")
    elif choice == "4":
        device_code = input("Nhập device_code: ").strip()
        device = Device.objects.get(device_code=device_code)
        NfcLog.objects.create(
            device=device,
            event_type="TAP_FAILED",
            success=False,
            metadata={"reason": "tamper"}
        )
        print("✅ Ghi TAP_FAILED")
    elif choice == "5":
        device_code = input("Nhập device_code: ").strip()
        action = input("Nhập hành động (ví dụ: CARD_REGISTERED): ").strip()
        device = Device.objects.get(device_code=device_code)
        AuditLog.objects.create(
            actor_user=None, device=device, action=action,
            success=True, ip_address=_client_ip(None), user_agent=_user_agent(None)
        )
        print("✅ Ghi audit log")
    elif choice == "6":
        print("👋 Thoát demo. Sau này kết nối real device.")
        return
    else:
        print("❌ Lựa chọn không hợp lệ")

    input("\nNhấn Enter để quay về menu...")

if __name__ == "__main__":
    run_demo_menu()