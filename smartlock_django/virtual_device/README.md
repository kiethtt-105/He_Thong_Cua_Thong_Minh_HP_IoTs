# Thiết bị khoá ảo (virtual_device)

Giả lập đầy đủ 1 khoá thật: MQTT (status/event/ack/cmd), bàn phím PIN, RFID, camera khuôn mặt,
Bluetooth + NFC điện thoại (xác thực vé HMAC tại chỗ, offline được), còi, đèn, servo, pin, Wi-Fi, tamper.
Firmware ESP32 trong `firmware_wokwi/` nói **cùng giao thức** → đổi sang khoá thật chỉ cần nạp lại `config.h`.

## Cài đặt (1 lần)
```
pip install "paho-mqtt<2"
```
Copy `register_virtual_device.py` vào `smartlock/management/commands/`.
Vá `mqtt_subscriber.py` (xem `mqtt_subscriber.patch.txt`) để nhận sự kiện `nfc_unlock`.

## Quy trình tạo khoá → claim
1. `cd virtual_device && python virtual_device.py --new`
   → tạo `devices/<code>/` gồm `device_info.txt` (code, secret, MAC, MQTT, hướng dẫn), `identity.json`,
   `activity.log`, `messages.jsonl`, `state.json`, `wallet.json`.
2. `python manage.py register_virtual_device virtual_device/devices/<code>/identity.json`
   (hoặc `--all`, hoặc bấm “Đăng ký vào DB” trong giao diện) → khoá ở trạng thái `provisioning`, chưa có chủ.
3. Chạy broker (mosquitto + auth webhook) và `python manage.py mqtt_subscriber`. Khoá ảo hiện **MQTT: connected**.
4. Web `/devices/claim/` → nhập Device code + Secret trong `device_info.txt` → khoá online, có chủ.

Mở UI: http://localhost:8765/  ·  JSON live: http://localhost:8765/json
(VS Code: mở `devices/<code>/state.json` hoặc `messages.jsonl` bằng Live Server / JSON viewer cũng cập nhật live.)

## Thử từng kênh
| Kênh | Cách thử |
|---|---|
| PIN | Cấp PIN trong `/access/door-pins/`, gõ số + `#` trên bàn phím ảo |
| Thẻ RFID | Bật cửa sổ đăng ký thẻ ở `/nfc/reader/` rồi bấm thẻ ảo; sau đó thẻ mở được cửa. Thẻ lạ ×3 → khoá tạm + còi |
| Khuôn mặt | Đăng ký mặt ở `/access/face-profiles/`, bật camera ở thiết bị ảo, “Quét & gửi” |
| Bluetooth / NFC | Lấy vé ở `devices/<id>/ble-ticket/` và `nfc-ticket/`, dán vào tab “Bluetooth & NFC” |
| Từ xa | Nút Mở/Khoá trên web → khoá ảo nhận cmd, ack, tự khoá lại sau 5s |
| Offline | Tắt Wi-Fi: BLE/NFC vẫn mở cửa, log gửi bù khi bật lại |

## Sang khoá thật / Wokwi
`firmware_wokwi/`: dán code/secret vào `config.h`. Wokwi chạy trên cloud nên cần broker có địa chỉ tới được
(Private Gateway của Wokwi VS Code, hoặc VPS). RFID/BLE/NFC/mặt trong Wokwi nhập qua Serial (`help`);
phần cứng thật bật `USE_RC522`, `USE_BLE`.
