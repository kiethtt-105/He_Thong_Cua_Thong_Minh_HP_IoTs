#!/usr/init/env python
"""
Script giả lập hệ thống thiết bị Smart Lock & Nhập thủ công dữ liệu mẫu.
Đặt file này cùng cấp với manage.py và chạy bằng lệnh: python menu.py
"""
import os
import sys
import django
from datetime import timedelta
from django.utils import timezone

# 1. Thiết lập môi trường Django
def setup_django():
    os.environ.setdefault('DJANGO_SETTINGS_MODULE','smartlock_django.settings')  
    try:
        django.setup()
    except Exception:
        sys.path.append(os.path.dirname(os.path.abspath(__file__)))
        django.setup()

setup_django()

from smartlock.models import Device, DeviceStatusLog, AccessCard, User

def print_header(title):
    print("\n" + "=" * 50)
    print(f"   {title}")
    print("=" * 50)

def create_provisioning_device_manual():
    print_header("TẠO THIẾT BỊ MẪU (NHẬP THỦ CÔNG) ĐỂ CLAIM")
    print("Lưu ý: Thiết bị ở trạng thái chờ nhận (provisioning) sẽ có chủ sở hữu (owner) là Trống (None).")

    # Nhập các thông tin thủ công từ người dùng
    name = input("1. Nhập tên thiết bị (ví dụ: Khóa cửa phòng khách): ").strip()
    if not name:
        print("[LỖI] Tên thiết bị không được để trống!")
        return

    device_code = input("2. Nhập mã thiết bị - Device Code (ví dụ: DEV-ABC1234): ").strip()
    if not device_code:
        print("[LỖI] Device Code không được để trống!")
        return

    # Kiểm tra xem device_code đã tồn tại chưa để tránh lỗi unique
    if Device.objects.filter(device_code=device_code).exists():
        print(f"[LỖI] Device Code '{device_code}' đã tồn tại trong hệ thống. Vui lòng dùng mã khác.")
        return

    location = input("3. Nhập vị trí lắp đặt (có thể bỏ trống): ").strip()
    if not location:
        location = None

    try:
        battery_input = input("4. Nhập mức pin ban đầu (0-100, mặc định 100): ").strip()
        battery_level = int(battery_input) if battery_input else 100
        if not (0 <= battery_level <= 100):
            raise ValueError
    except ValueError:
        print("[CẢNH BÁO] Mức pin không hợp lệ, hệ thống sẽ tự đặt mặc định là 100%.")
        battery_level = 100

    try:
        # Tạo thiết bị tuân thủ tuyệt đối CheckConstraint của DB: status='provisioning' thì owner phải là None
        device = Device.objects.create(
            name=name,
            device_code=device_code,
            provisioning_secret_hash="manual_created_secret_hash_sample",
            status='provisioning',
            owner=None,  # Bắt buộc None khi đang ở trạng thái provisioning[cite: 9]
            battery_level=battery_level,
            wifi_enabled=True,
            bluetooth_enabled=True,
            nfc_enabled=True,
            location=location
        )
        print(f"\n[THÀNH CÔNG] Đã tạo thiết bị chờ claim thành công!")
        print(f" - Tên thiết bị: {device.name}")
        print(f" - Device Code: {device.device_code}")
        print(f" - Trạng thái: {device.status}")
        print(f" - Vị trí: {device.location or 'Không có'}")
    except Exception as e:
        print(f"\n[LỖI] Không thể tạo thiết bị do lỗi cơ sở dữ liệu: {e}")

def list_all_devices():
    print_header("DANH SÁCH TẤT CẢ THIẾT BỊ TRONG HỆ THỐNG")
    devices = Device.objects.all().order_by('-created_at')
    if not devices.exists():
        print("Chưa có thiết bị nào trong cơ sở dữ liệu.")
        return

    for idx, d in enumerate(devices, 1):
        owner_str = d.owner.email if d.owner else "Chưa có (Chờ Claim)"
        print(f"{idx}. [{d.device_code}] {d.name} — Status: {d.status} — Chủ sở hữu: {owner_str}")

def simulate_device_telemetry_manual():
    print_header("GIẢ LẬP GỬI STATUS LOG TỪ THIẾT BỊ (NHẬP THỦ CÔNG)")
    devices = Device.objects.exclude(status='provisioning')
    if not devices.exists():
        print("Không có thiết bị nào đang hoạt động (Online/Offline) để gửi log.")
        print("Lưu ý: Thiết bị ở trạng thái 'provisioning' chưa có chủ sở hữu và chưa thể gửi telemetry log.")
        return

    print("Chọn thiết bị để giả lập gửi log:")
    dev_list = list(devices)
    for idx, d in enumerate(dev_list, 1):
        print(f"{idx}. {d.name} ({d.device_code})")

    choice = input("Nhập số thứ tự thiết bị: ").strip()
    try:
        idx = int(choice) - 1
        if idx < 0 or idx >= len(dev_list):
            print("Lựa chọn không hợp lệ.")
            return
        target_dev = dev_list[idx]
    except ValueError:
        print("Vui lòng nhập số hợp lệ.")
        return

    print("\nChọn trạng thái khóa (Lock State):")
    print("1. locked (Đã khóa)")
    print("2. unlocked (Đã mở khóa)")
    print("3. jammed (Kẹt khóa)")
    lock_choice = input("Lựa chọn (1-3, mặc định 1): ").strip()
    
    state_map = {'1': 'locked', '2': 'unlocked', '3': 'jammed'}
    lock_state = state_map.get(lock_choice, 'locked')

    try:
        battery = int(input("Nhập mức pin hiện tại (0-100): ") or target_dev.battery_level)
    except ValueError:
        battery = target_dev.battery_level

    try:
        signal_strength = int(input("Nhập cường độ tín hiệu sóng WiFi/Signal (ví dụ: -65): ") or "-65")
    except ValueError:
        signal_strength = -65

    try:
        temperature = float(input("Nhập nhiệt độ thiết bị (ví dụ: 27.5): ") or "26.5")
    except ValueError:
        temperature = 26.5

    # Ghi log trạng thái thiết bị thủ công
    log = DeviceStatusLog.objects.create(
        device=target_dev,
        battery_level=battery,
        signal_strength=signal_strength,
        lock_state=lock_state,
        tamper_detected=False,
        temperature=temperature,
        raw_payload={"source": "manual_menu_simulation_script"}
    )
    
    # Cập nhật trạng thái thiết bị sang online và lưu thời gian hoạt động mới nhất
    target_dev.status = 'online'
    target_dev.battery_level = battery
    target_dev.last_seen_at = timezone.now()
    target_dev.save()

    print(f"\n[THÀNH CÔNG] Đã ghi log thủ công cho thiết bị {target_dev.name}!")
    print(f" - Trạng thái khóa: {lock_state}")
    print(f" - Mức pin: {battery}%")
    print(f" - Tín hiệu: {signal_strength} dBm")
    print(f" - Nhiệt độ: {temperature}°C")

def main_menu():
    while True:
        print_header("QUẢN LÝ THIẾT BỊ SMART LOCK (NHẬP THỦ CÔNG)")
        print("1. Tạo thiết bị mẫu để claim (Nhập tay thông tin)")
        print("2. Xem danh sách tất cả thiết bị")
        print("3. Giả lập gửi Device Status Log thủ công")
        print("0. Thoát")
        
        choice = input("\nChọn chức năng (0-3): ").strip()
        if choice == '1':
            create_provisioning_device_manual()
        elif choice == '2':
            list_all_devices()
        elif choice == '3':
            simulate_device_telemetry_manual()
        elif choice == '0':
            print("Tạm biệt!")
            sys.exit(0)
        else:
            print("Lựa chọn không hợp lệ, vui lòng chọn lại.")

if __name__ == '__main__':
    main_menu()