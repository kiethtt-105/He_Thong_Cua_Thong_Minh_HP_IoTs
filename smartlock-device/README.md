# SmartLock Device – khoá thông minh giả lập + thiết bị thật


```
smartlock-device/
├─ firmware/                  # Python, chạy trên PC / Raspberry Pi
│  ├─ smartlock_fw/           # protocol · core · link(MQTT) · webui · drivers/
│  ├─ smartlock_fw/device.conf.example     # mẫu cấu hình (đầy đủ chú thích)
│  └─ faces/                  # embedding khuôn mặt mẫu
├─ vscode-extension/          # giao diện trong VS Code (sidebar, status bar, Live View, lệnh mô phỏng)
├─ broker/                    # mosquitto dev + ACL khớp mqtt_acl_webhook
└─ tests/                     # 15 test (python) + smoke test extension (node)
```

## 1. Chạy thử trong 2 phút (độc lập, chưa cần hệ thống)

```bash
cd firmware
python -m smartlock_fw init                 # sinh device.conf + secret, in lệnh đăng ký lên server
# mở device.conf, đặt:  [server] mode = standalone
python -m smartlock_fw run                  # hoặc ./run.sh  /  run.bat
```
Mở **http://127.0.0.1:8765/** → trang Live View: trạng thái khoá, pin, Wi-Fi/RSSI, MQTT, BLE, NFC, nhật ký thời gian thực, và bảng
**mô phỏng đầu vào** (bàn phím 4×4, quẹt thẻ, quét mặt, vé Bluetooth/NFC, cạy phá, kẹt chốt, bật/tắt radio).
Mẫu thẻ/PIN để thử nằm ở `[standalone.cards]` / `[standalone.pins]` (PIN `654321` chỉ dùng được 1 lần).

## 2. Dùng trong VS Code

1. Mở thư mục `smartlock-device` (hoặc file `.code-workspace`).
2. Cài extension: mở `vscode-extension/` rồi nhấn **F5** (Extension Development Host), hoặc đóng gói
   `cd vscode-extension && npx @vscode/vsce package` rồi *Install from VSIX*.
3. Icon khoá ở thanh bên: **▶ chạy khoá**, xem trạng thái, bấm các mục "Quẹt thẻ / Nhập PIN / Quét khuôn mặt / Vé điện thoại / Bật-tắt radio / Cạy phá / Kẹt chốt".
   Thanh trạng thái hiển thị `ĐÃ KHOÁ · pin · ☁`; bấm để mở **Live View ngay trong VS Code** (hoặc trình duyệt).
   Extension chỉ là lớp mỏng trên API cục bộ của firmware nên chạy được cả khi khoá nằm trên máy khác (đổi `smartlock.host`).

## 3. Nối với hệ thống Django

1. **Đăng ký khoá**: chạy đoạn `Device.objects.create(...)` mà `init` in ra (trong `manage.py shell`).
   Server chỉ lưu `sha256(secret)`; khoá giữ secret gốc.
2. **Broker MQTT**: `broker/docker-compose.yml` (dev). Thêm tài khoản:
   `./broker/add_user.sh django <MQTT_PUBLISHER_PASSWORD>` và `./broker/add_user.sh <device_code> <secret>`.
   Biến môi trường Django: `MQTT_HOST`, `MQTT_PUBLISHER_USERNAME=django`, `MQTT_PUBLISHER_PASSWORD`,
   và `MQTT_TRUSTED_USERNAMES=['django']`. Production: dùng plugin HTTP-auth (vd mosquitto-go-auth) gọi
   `/api/mqtt/auth/` và `/api/mqtt/acl/` (xem `views.py`).
3. `device.conf`: `[server] mode = online`, `mqtt_host`, `mqtt_port`. Chạy khoá → trạng thái **Online · MQTT**.
4. Trên web: **Thiết bị → Thêm khoá (claim)** bằng `device_code` + `secret`. (Server yêu cầu khoá đang kết nối thật – `link_status`.)
5. Thử: bấm Mở/Khoá trên web → khoá nhận lệnh `UNLOCK/LOCK`, ack lại; quẹt thẻ/PIN/mặt trên Live View → server xác thực → gửi `UNLOCK`;
   quẹt sai 3 lần → khoá tạm + còi (`BUZZER_ALERT`) + thông báo cho chủ.

### Kênh nào cần mạng?
| Kênh | Ai quyết định | Offline? |
|---|---|---|
| Thẻ RFID, PIN, khuôn mặt | **Server** (UID/PIN đã băm HMAC với pepper, so khớp ở server) → khoá chỉ nhận lệnh `UNLOCK` | Không – bị từ chối khi mất mạng |
| Vé Bluetooth / NFC điện thoại | **Khoá tự kiểm tra** chữ ký HMAC + hạn vé | **Có** – sự kiện được xếp hàng, gửi lại kèm giờ thật khi có mạng |
| Lệnh từ web/app | Server qua MQTT | Cần Wi-Fi |

## 4. Chuyển sang thiết bị thật – chỉ sửa `device.conf`

| Phần | Giả lập | Thật |
|---|---|---|
| Wi-Fi | `driver=sim` | `driver=system` đọc SSID/RSSI thật của máy (Windows `netsh`, Linux `nmcli`, macOS `airport`); `connect=true` tự nối trên Linux |
| Bluetooth | `sim` | `bless` – GATT server BLE thật (`pip install bless`); app ghi vé vào `ticket_char_uuid`, đọc kết quả ở `result_char_uuid` |
| NFC | `sim` | `pcsc` (ACR122U… `pip install pyscard`): đọc UID thẻ **và** `SELECT AID` để nhận vé từ điện thoại HCE · `rc522` trên Raspberry Pi |
| Bàn phím | `sim` | `gpio` – ma trận 4×4 qua `rows/cols` |
| Camera | `sim` | `opencv` + `face_recognition` (128-d) |
| Chốt khoá | `sim` | `relay` / `servo` (GPIO Raspberry Pi) |
| Pin/nhiệt | `sim` | `source=system` (pin laptop qua `psutil`) |

Chạy `python -m smartlock_fw doctor` để xem thư viện nào còn thiếu và broker có truy cập được không.
Cấp vé test: `python -m smartlock_fw ticket ble --user <uuid>`.

## 5. Điều cần biết (đọc trước khi tin kết quả)

- **Chưa thử với server/broker thật.** Mình chỉ có 6 file bạn gửi; không có file *subscriber MQTT* (management command nhận `status/event/ack`).
  Phần server→khoá (topic `cmd`, payload lệnh, thuật toán vé, hash secret) lấy nguyên từ `services.py` và đã đối chiếu bằng test.
  Phần **khoá→server** (tên trường trong `status`/`event`/`ack`) là quy ước suy ra từ chữ ký hàm
  (`verify_rfid_tap(uid)`, `verify_door_pin(pin)`, `verify_face(embedding)`, `record_ble_unlock(ticket, ok, reason, at)`…).
  **Hãy đối chiếu với subscriber của bạn**; nếu khác, chỉ sửa 3 hàm `build_status/build_event/build_ack` trong `smartlock_fw/protocol.py`.
- Chưa thử trên phần cứng thật (BLE bless, pyscard, RC522, GPIO, camera): driver viết theo API thư viện nhưng chưa chạy với thiết bị.
  Đã chạy thật: firmware, web live view, API, SSE, extension (với `vscode` giả), 15 test.
- **Khuôn mặt**: server đăng ký bằng face-api.js trên trình duyệt, khoá trích bằng dlib – cùng 128-d nhưng không đồng nhất tuyệt đối.
  Muốn chính xác, đăng ký và nhận diện bằng cùng một mô hình. Để thử `FACE` với server ở chế độ giả lập, nạp embedding mẫu bằng
  `services.register_face(device, user, embedding, consent_confirmed=True)` trong `manage.py shell`.
- **NFC điện thoại (HCE)** cần app Android phát AID `F0534D4C4F434B01` và trả vé ASCII + `9000`. Android dùng UID ngẫu nhiên nên khoá không nhận nhầm thành thẻ.
- Vé có hiệu lực đến khi hết hạn (mặc định 1 giờ) kể cả khi quyền bị thu hồi lúc khoá offline; thu hồi = đợi hết hạn hoặc `rotate_secret`. Đây là thiết kế của server, firmware không đổi.
- `device.conf` chứa secret và PIN thử (standalone) ở dạng rõ – coi như file bí mật của thiết bị. `[ui] host=0.0.0.0` chỉ nên bật kèm `token`.
- Route `demo/system-logs/` trong `urls.py` không cần đăng nhập – nhớ gỡ trước khi deploy thật (chính bạn đã ghi chú trong file).

## 6. Chạy test
```bash
cd firmware && python -m unittest discover -s ../tests -v      # 15 test: giao thức, lõi, MQTT (paho giả)
# smoke test extension: chạy khoá ở cổng 8799 rồi:  node tests/ext_smoke.js
```
