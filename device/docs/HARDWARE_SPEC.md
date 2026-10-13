# Đặc tả phần cứng (rút ra từ bộ giả lập)

Mỗi dòng: linh kiện thật ↔ hàm/callback trong `lockcore/hal.py` ↔ cách SimHAL đang giả lập.
Các model linh kiện là **đề xuất**, hãy kiểm tra tương thích (điện áp, thư viện Python, hàng có sẵn) trước khi mua.

| Chức năng | Linh kiện đề xuất | Giao tiếp | HAL | SimHAL đang mô phỏng |
|---|---|---|---|---|
| Bo mạch chính | Raspberry Pi 4B (≥2GB) hoặc Pi 5 | – | – | Chạy nguyên `controller.py`. **Không dùng ESP32**: code dùng threading/paho/ssl, và dlib không chạy nổi |
| Chốt khoá | Servo công suất lớn hoặc motor + 2 công tắc hành trình (đầu/cuối) | PWM / GPIO | `unlock()`, `lock()`, `lock_state` | Mất `servo_seconds`, thử lại 2 lần, kẹt (`jam_chance`), tốn pin, nóng lên, hết pin thì không quay |
| Cửa đóng/mở | Công tắc từ (reed) | GPIO | `door_open`, `on_door_change` | `sim_door()`; mở khi đang khoá → `FORCED_OPEN` |
| Va đập | MPU6050 (I2C) hoặc SW-420 | I2C / GPIO | `tamper`, `on_shock` | `sim_shock()`, tự nhả sau `tamper_clear_seconds` |
| Thẻ RFID/NFC | PN532 (đọc cả điện thoại NFC), RC522 nếu chỉ đọc thẻ | I2C/SPI | `on_card(uid_hex)` | `sim_tap_card()` (UID chữ HOA, không dấu) |
| Bàn phím PIN | Keypad ma trận 4x4 | GPIO | `on_pin("123456")` | `sim_keypad()` (driver gom số rồi gửi cả chuỗi khi bấm `#`) |
| Quét mặt | Pi Camera Module 3 + nút/PIR kích hoạt | CSI / GPIO | `on_face_trigger`, `capture_embedding()` | `sim_press_face()`, ~0.8s; embedding do trình duyệt (webcam + face-api.js) trích rồi gửi xuống |
| Mở bằng điện thoại | BLE của Pi (BlueZ GATT) | BLE | `on_phone(kind, ticket)` | `sim_phone()`; vé kiểm offline bằng `tickets.verify` |
| Núm xoay trong nhà | Công tắc/encoder | GPIO | `on_knob` | `sim_knob()` |
| Pin + đo pin | Pin 18650 + mạch sạc/UPS HAT + INA219 | I2C | `battery` (0–100) | Tụt theo thời gian + mỗi lần quay servo; lưu qua "mất điện" |
| Nhiệt độ | Cảm biến CPU hoặc DS18B20 | – | `temperature` | Môi trường + nhiệt servo + nhiễu |
| Còi + LED | Còi chủ động 5V (qua transistor) + LED xanh/đỏ | GPIO | `beep('ok'/'deny'/'alarm')`, `led` | Ghi log còi, LED tự tắt sau 2s |
| Wi-Fi | Wi-Fi của Pi | – | `signal` (RSSI) | RSSI thật của máy host ±1 dBm |

## Khi đã có linh kiện
1. Viết `lockcore/hal_pi.py` với lớp `PiHAL(BaseHAL)`: cùng thuộc tính/hàm/callback như bảng trên.
2. Đặt `hardware.hal = "auto"` (hoặc `"real"`) trong `config.json` → controller, api, mqtt, UI **không phải sửa**.
3. Việc cần làm lúc đó: chọn chân GPIO, đọc vị trí chốt từ công tắc hành trình trong `on_boot()`, chống rung (debounce) cho reed/keypad.

## Những thứ giả lập CHƯA thay thế được thật
Nhiễu điện/EMI của servo, độ ồn của camera, tuổi thọ pin thực tế, tải CPU khi trích embedding trên Pi.

## Rủi ro lớn nhất cần thử SỚM: embedding mặt
Hiện embedding do **trình duyệt** (face-api.js) trích, cả lúc đăng ký trên server lẫn lúc quét. Thiết bị thật sẽ phải tự trích bằng Python
(vd. thư viện `face_recognition`/dlib, hoặc chạy lại đúng mô hình face-api). Ngưỡng server là khoảng cách Euclid <= 0.5, nên **hai bộ trích khác nhau
có thể lệch nhau**. Trước khi mua camera: đăng ký 1 khuôn mặt bằng trình duyệt, rồi trích cùng khuôn mặt đó bằng Python trên PC và so khoảng cách.
Nếu > 0.5, hãy đăng ký mặt bằng chính thiết bị (không đăng ký bằng trình duyệt).
