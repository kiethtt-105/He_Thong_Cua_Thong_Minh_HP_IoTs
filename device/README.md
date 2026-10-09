# SmartLock · Khoá giả lập (ESP32 simulator)

Mô phỏng đầy đủ firmware khoá theo đúng `smartlock/api/device.py`. Chỉ cần Python 3.9+, không cần cài thêm gì. Giao tiếp qua HTTP API (bắt buộc), MQTT là tuỳ chọn; trạng thái lưu trong bộ nhớ flash (`state/`).

## Chạy nhanh với VS Code Dev Tunnel (https)
1. Django chạy cổng 8000 → VS Code tab **Ports** → forward `8000` → **Port Visibility: Public** (Private sẽ trả trang đăng nhập, khoá báo "không phải JSON").
2. Mở `config.json`, điền `server.urls.tunnel` (địa chỉ https vừa chép), `device_code`, `secret` (lấy ở trang admin "Thông tin kết nối", lần đầu hiển thị).
3. `python run.py` → vào trang chi tiết thiết bị, trong ≤ 2 phút báo **đã kết nối**.
(Chưa điền `secret` thì khoá vào chế độ SETUP trên UI `http://127.0.0.1:8080`, các ô đã điền sẵn từ `config.json`, chỉ cần dán secret.)
Giao diện giả lập `:8080` chỉ để cục bộ - **đừng forward ra tunnel** (không có đăng nhập, mở khoá được).

```
python run.py                              # đọc ./config.json
python run.py --config khac.json           # file cấu hình khác
python run.py --server https://xxx-8000.asse.devtunnels.ms   # ép server (không sửa file)
python run.py --heartbeat 10 --poll 2      # chu kỳ nhanh để demo
python tools/fake_server.py                # server giả :8000 (DEV-TEST0001 / testsecret) khi chưa chạy Django
python tools/mqtt_probe.py                 # chẩn đoán đường MQTT (xem docs/MQTT.md)
```

## config.json - toàn bộ thông số khoá + kết nối
Ưu tiên: **tham số dòng lệnh > biến môi trường (`DEVICE_CODE`, `DEVICE_SECRET`, `SERVER_URL`) > state/config.json (do trang SETUP ghi) > config.json > mặc định**.
Khoá bắt đầu bằng `_` là ghi chú. `config.json` không bao giờ bị khoá tự xoá (Factory reset chỉ xoá `state/`).

| Khoá | Mặc định | Ý nghĩa |
|---|---|---|
| `device_code`, `secret` | – | Thông tin trang admin cấp. Header `X-Device-Code` / `X-Device-Secret`; secret cũng dùng kiểm chữ ký vé BLE/NFC offline. |
| `server.active`, `server.urls` | `tunnel` | Tên → URL (không kèm `/api/device`). Đổi nhanh trên UI. |
| `wifi.source` | `host` | `host` = dùng Wi-Fi **thật** của máy chạy giả lập (đọc SSID + RSSI thật, không cần mật khẩu, không đổi Wi-Fi của máy); `simulated` = mạng ảo như trước. |
| `wifi.ssid`, `wifi.password` | – | Chỉ dùng khi `source: simulated` (hoặc máy không đọc được Wi-Fi). |
| `network.http_timeout_seconds` | 10 | Timeout mỗi request. |
| `network.heartbeat_seconds` | `null` | Chu kỳ heartbeat; `null` = theo server (60). Trang admin cần heartbeat < 2 phút. |
| `network.poll_seconds` | `null` | Chu kỳ hỏi lệnh qua HTTP; `null` = theo server (3). |
| `network.offline_queue_max` | 200 | Số sự kiện tối đa giữ khi mất mạng. |
| `mqtt.*` | tắt | Xem `docs/MQTT.md` (bật bằng `enabled` + `url: wss://...`). |
| `hardware.firmware`, `mac` | 1.0.0 / tự sinh | `mac` rỗng → tự sinh 1 lần và lưu cố định. |
| `hardware.battery`, `signal`, `temperature` | 100 / -55 / 27 | Giá trị ban đầu pin %, RSSI dBm, nhiệt độ °C. |
| `hardware.auto_lock_seconds` | 5 | Tự khoá lại sau khi mở (khi cửa đã đóng). |
| `hardware.door_left_open_seconds` | 60 | Cửa mở quá lâu → sự kiện DOOR_LEFT_OPEN. |
| `hardware.battery_drain_minutes` | 5 | Cứ N phút tụt 1% pin (0 = không tụt). |
| `hardware.servo_seconds`, `jam_chance` | 0.6 / 0 | Thời gian chốt chạy; xác suất kẹt chốt (0..1). |
| `hardware.auto_ota` | false | Tự cập nhật khi server báo có bản mới. |

## Bộ nhớ (giống NVS/flash ESP32) - thư mục `state/`, khoá tự ghi
| File | Nội dung |
|---|---|
| `config.json` | Phần SETUP trên UI ghi (wifi/server/mã/secret) + `mac` + firmware sau OTA; đè lên `config.json` gốc |
| `runtime.json` | Cấu hình server gửi về lần cuối (cờ BLE/NFC/Wi-Fi, chu kỳ, `locked_out`) + 100 `command_id` đã xử lý → reboot/mất mạng không chạy lại lệnh cũ |
| `queue.json` | Sự kiện + vé điện thoại chờ gửi bù khi có mạng |
| `face.json` | Vector khuôn mặt mẫu (chỉ để demo) |

Offline vẫn mở được bằng **vé BLE/NFC điện thoại** (kiểm HMAC tại chỗ). RFID / PIN / khuôn mặt luôn cần server phán quyết.

## Module demo: cái nào thật, cái nào giả lập
| Module | Trong giả lập | Ghi chú |
|---|---|---|
| Wi-Fi | **Thật**: SSID + RSSI của máy, gửi vào heartbeat | Windows 11 cần bật quyền Vị trí để `netsh` đọc được SSID; máy cắm LAN → nhập tay |
| Mạng / server | **Thật**: HTTPS qua dev tunnel | |
| Camera + khuôn mặt | **Thật**: camera trình duyệt → embedding 128 số (face-api.js) | Cần Internet lần đầu để tải mô hình; khuôn mặt phải được **đăng ký lên server cùng loại embedding** (face-api.js tương thích dlib/`face_recognition`) |
| Thẻ NFC/RFID | **Thật nếu có đầu đọc USB kiểu bàn phím**: bấm ô UID rồi quẹt; còn lại gõ UID | Giả lập không đọc NFC của điện thoại |
| Bluetooth / NFC điện thoại | Vé được **kiểm chữ ký offline thật**; vé lấy từ app hoặc nút "🧪 Tạo vé thử" | Giả lập không phát sóng BLE thật (đó là việc của firmware ESP32) |
| PIN, cửa, chốt, tamper, pin, kẹt chốt | Mô phỏng bằng nút trên UI | |

## Đã mô phỏng
| Chức năng | Endpoint / cơ chế |
|---|---|
| Boot → sự kiện BOOT, heartbeat 60s (pin, RSSI, lock_state, tamper, nhiệt độ, fw, MAC) | `POST /device/events/`, `/heartbeat/` |
| Nhận lệnh UNLOCK/LOCK/REBOOT/PING/OTA/RESET: HTTP poll 3s, khử trùng `command_id`, bỏ lệnh `expires_in=0`, ack kèm `token` | `GET /commands/`, `POST /ack/` |
| Quẹt thẻ / PIN / khuôn mặt: server phán quyết, khoá chỉ mở khi `granted=true`, tôn trọng `locked_out` | `/access/rfid|pin|face/` |
| Vé BLE / NFC điện thoại: **tự kiểm chữ ký offline** (HMAC khớp `_ticket_sig`), báo log về sau | `/access/phone/` |
| Mất mạng: hàng đợi sự kiện + vé điện thoại lưu file, gửi bù ≤50/lô khi có mạng | `events`, `access/phone` |
| TAMPER, FORCED_OPEN (mở cửa khi đang khoá), DOOR_LEFT_OPEN, pin yếu (qua heartbeat) | `/events/` |
| Tự khoá lại sau khi cửa đóng, núm xoay trong nhà, kẹt chốt (jammed) | — |
| OTA (started/success/failed), cờ wifi/bluetooth/nfc từ server, đồng bộ giờ | `/ota/`, `/config/` |
| Sai secret (401) → báo rõ; 429 → lùi theo `retry_after_seconds` | — |

## ⚠ Phía Django: nên sửa 2 chỗ để lệnh không bị đánh dấu failed khi broker không tới được
Hiện `dispatch_command` đặt lệnh `failed` khi publish MQTT lỗi, và `pending_commands` chỉ trả lệnh `pending/sent`
→ lệnh bị bỏ rơi, web báo 502 "PUBLISH_FAILED". Broker `localhost:8883` thì Vercel không với tới.

```python
# services.py
MQTT_ENABLED = os.environ.get('MQTT_ENABLED', '1').lower() not in ('0', 'false', 'no')   # Vercel: đặt MQTT_ENABLED=0

def dispatch_command(...):
    ...
    try:
        if not MQTT_ENABLED:
            raise MqttPublishError('MQTT tắt')
        publish_command(...)
        cmd.status = 'sent'
    except MqttPublishError as e:
        cmd.status = 'pending'          # khoá sẽ kéo qua HTTP /device/commands/ (<=3s) thay vì coi là lỗi
        cmd.publish_error = str(e)[:200]

def _push_unlock(...):
    return dispatch_command(...).status in ('sent', 'pending')

# api/locks.py  device_command
if cmd.status not in ('sent', 'pending'):
```

## Lên ESP32 thật
`lockcore/hal.py` là lớp phần cứng duy nhất (servo, cảm biến cửa, pin, RSSI). Logic `controller.py` / `api.py` /
`tickets.py` chỉ dùng thư viện chuẩn → port sang MicroPython bằng cách viết `hal_esp32.py` cùng giao diện và thay
`urllib` bằng `urequests`. Chưa có quét mặt thật: embedding 128 số do camera/module AI của khoá tính ra.
