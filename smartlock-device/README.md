# SmartLock Lab

## 1. Chạy phòng lab (giả lập bằng Python)
```
cd firmware
python -m smartlock_fw run          # hoặc run.bat / run.sh ở thư mục gốc
```
Mở http://127.0.0.1:8765/ — 5 tab (kéo thả để đổi thứ tự, thẻ có tay nắm ⠿ để kéo):
Tạo khoá · Thông tin khoá · Giả lập thiết bị · Xem 3D · Nhật ký.
Muốn chạy không cần server: đặt `[server] mode = standalone` trong device.conf.

## 2. Thiết bị "thật" bằng Wokwi (ESP32 + keypad + servo + LED + còi)
1. VS Code: cài tiện ích **Wokwi Simulator** và **PlatformIO IDE** (đã gợi ý sẵn trong .vscode/extensions.json).
2. Mở thư mục `wokwi/`, sửa `LOCK_CODE`, `LOCK_SECRET` trong `src/main.cpp` cho khớp khoá đã tạo ở tab "Tạo khoá".
3. PlatformIO: Build (tạo `.pio/build/esp32/firmware.bin`), rồi F1 → "Wokwi: Start Simulator" (lần đầu cần kích hoạt license Wokwi).
4. Gõ PIN trên keypad trong Wokwi, # để gửi. Màn hình LCD hiện trạng thái khoá, mạng và số `*` đang gõ.

**Chạy trên web wokwi.com (không cần cài gì):** tạo project ESP32 mới, dán `src/main.cpp` vào tab sketch.ino,
`diagram.json` vào tab diagram.json, `libraries.txt` vào tab libraries.txt, rồi bấm ▶.

Lưu ý: Wokwi bản miễn phí không nối được `localhost`; mặc định code dùng broker công khai test.mosquitto.org (chỉ để thử,
không có xác thực nên KHÔNG khớp với broker mosquitto-go-auth của bạn). Muốn nối broker thật ở máy bạn: dùng
private gateway của Wokwi (gói trả phí) và đổi `MQTT_HOST` thành `host.wokwi.internal`.

## 3. Đã sửa so với bản cũ
- Sự kiện BLE/NFC-điện thoại gửi sai tên (`ble_unlock`, `nfc_phone_unlock`) → server bỏ qua. Nay là `ble`, `nfc_phone` (khớp mqtt_subscriber.py).
- Thêm LWT + gửi `{"state":"offline"}` khi tắt khoá, gửi sự kiện `boot` khi kết nối.
- Mã đăng ký Django có `status='provisioning'`; mỗi khoá mới có MAC riêng.
- Bảo mật cho thiết bị thật: `[ui] allow_admin = auto` (tắt API/tab Tạo-Sửa khoá khi `mode = physical`), tab Giả lập tự ẩn khi `allow_sim_input = false`,
  và khoá từ chối chạy nếu `[ui] host` mở ra ngoài mà chưa đặt `token`.
