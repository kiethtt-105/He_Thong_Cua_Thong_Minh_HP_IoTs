# SmartLock · Khoá giả lập (ESP32 simulator)

Mô phỏng đầy đủ firmware khoá theo đúng `smartlock/api/device.py`. Chỉ cần Python 3.9+ (HTTP không cần cài thêm gì).

```
python run.py                 # mở UI http://127.0.0.1:8080
python run.py --server http://127.0.0.1:8000     # ép dùng Django local
python run.py --heartbeat 10 --poll 2            # chu kỳ nhanh để demo
python tools/fake_server.py   # server giả :8000 (code DEV-TEST0001 / secret testsecret) để test khi chưa chạy Django
```

## Cấu hình khoá (giống nạp config vào ESP32)
Lần đầu chạy, UI hiện trang **SETUP** (như AP "SmartLock-Setup"): chọn Wi-Fi + dán thông tin trang admin
(Server, Mã thiết bị, Secret, MQTT) → Lưu. Cấu hình nằm ở `state/config.json` (giống NVS của ESP32).
Trên UI có ô **Đổi server** để chuyển nhanh local ↔ vercel ↔ tunnel mà không phải cấu hình lại.

## Đã mô phỏng
| Chức năng | Endpoint / cơ chế |
|---|---|
| Boot → sự kiện BOOT, heartbeat 60s (pin, RSSI, lock_state, tamper, nhiệt độ, fw, MAC) | `POST /device/events/`, `/heartbeat/` |
| Nhận lệnh UNLOCK/LOCK/REBOOT/PING/OTA/RESET: HTTP poll 3s (+ MQTT nếu bật), khử trùng `command_id`, bỏ lệnh `expires_in=0`, ack kèm `token` | `GET /commands/`, `POST /ack/` |
| Quẹt thẻ / PIN / khuôn mặt: server phán quyết, khoá chỉ mở khi `granted=true`, tôn trọng `locked_out` | `/access/rfid|pin|face/` |
| Vé BLE / NFC điện thoại: **tự kiểm chữ ký offline** (HMAC khớp `_ticket_sig`), báo log về sau | `/access/phone/` |
| Mất mạng: hàng đợi sự kiện + vé điện thoại lưu file, gửi bù ≤50/lô khi có mạng | `events`, `access/phone` |
| TAMPER, FORCED_OPEN (mở cửa khi đang khoá), DOOR_LEFT_OPEN, pin yếu (qua heartbeat) | `/events/` |
| Tự khoá lại sau khi cửa đóng, núm xoay trong nhà, kẹt chốt (jammed) | — |
| OTA (started/success/failed), cờ wifi/bluetooth/nfc từ server, đồng bộ giờ | `/ota/`, `/config/` |
| Sai secret (401) → báo rõ; 429 → lùi theo `retry_after_seconds` | — |

## MQTT: có cần không?
**Không bắt buộc.** Khoá dùng HTTP polling (≤3s) là chạy được cả local lẫn Vercel, không cần broker.
MQTT chỉ để lệnh tới nhanh hơn. Bật bằng ô "Dùng MQTT" ở trang setup (username = mã thiết bị, password = secret).

## ⚠ Cần sửa 2 chỗ phía Django để lệnh từ web hoạt động khi broker không tới được (đặc biệt trên Vercel)
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
