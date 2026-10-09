# Triển khai MQTT cho SmartLock qua VS Code Dev Tunnel

MQTT là **tuỳ chọn**: bật thì lệnh từ web tới khoá trong < 1 giây thay vì tối đa 3 giây (HTTP polling).
HTTP polling vẫn chạy song song làm đường dự phòng; cùng một `command_id` đến cả hai đường vẫn chỉ chạy **một lần**.

## 1. Kiến trúc

```
Web admin ─► Django (:8000) ──publish──► Mosquitto 127.0.0.1:1883 (hoặc :8883 TLS như trang admin ghi)
                                              │ listener WebSocket 127.0.0.1:9001
Khoá (simulator / ESP32) ◄── wss://<id>-9001.<region>.devtunnels.ms ◄── Dev Tunnel (cổng 9001, Public)
```

**Vì sao WebSocket?** Dev tunnel của VS Code chỉ chuyển tiếp **HTTP/HTTPS**, không chuyển TCP thô. Cổng MQTT 1883/8883 không đi qua tunnel
được, nhưng MQTT đóng gói trong WebSocket (`wss://`) thì đi qua bình thường, và TLS do tunnel lo.
Phía Django vẫn publish trực tiếp vào broker cục bộ như cũ - **không phải đổi gì ở Django** cho đường này.

## 2. Cài và chạy broker (Mosquitto 2.x)
```bash
# Ubuntu/Debian: sudo apt install mosquitto mosquitto-clients      Windows: cài từ mosquitto.org      Docker: image eclipse-mosquitto:2
cd docs/mosquitto
mosquitto_passwd -c -b ./passwd django  '<mật-khẩu-server>'          # user cho Django
mosquitto_passwd    -b ./passwd DEV-4940959A '<secret của khoá>'     # username = mã thiết bị, password = secret
mosquitto -c ./mosquitto.conf -v
```
- `acl` mẫu giới hạn: khoá chỉ đọc `smartlock/<mã>/cmd` và ghi `status|ack|event` của chính nó.
- Nếu hệ thống của bạn **đã có** cơ chế cấp user cho broker (plugin/dynamic-security/auth qua HTTP) thì dùng lại, miễn là
  username = mã thiết bị, password = secret (đúng như trang admin ghi). Thêm listener `9001 ... protocol websockets` cạnh listener cũ là đủ.
- Thêm/xoá khoá thủ công: chạy lại `mosquitto_passwd -b ...` rồi `kill -HUP <pid mosquitto>` (hoặc restart).

## 3. Forward cổng 9001 bằng dev tunnel
1. VS Code → tab **Ports** → **Forward a Port** → `9001`.
2. Chuột phải dòng cổng 9001 → **Port Visibility → Public** (nếu Private, tunnel đòi đăng nhập và khoá không nối được).
3. Giao thức để **HTTPS** (mặc định). Chép địa chỉ, ví dụ `https://d81h6zk7-9001.asse.devtunnels.ms` → đổi `https` thành **`wss`**.

## 4. Cấu hình khoá (`config.json`)
```json
"mqtt": {
  "enabled": true,
  "url": "wss://d81h6zk7-9001.asse.devtunnels.ms",
  "publish_telemetry": false
}
```
```bash
pip install paho-mqtt
python tools/mqtt_probe.py        # chẩn đoán từng bước: DNS → TCP → TLS → WebSocket 101 → đăng nhập → nghe lệnh
python run.py
```
Log mong đợi: `MQTT đã kết nối, subscribe smartlock/DEV-.../cmd`, giao diện hiện huy hiệu **MQTT ✔**.
Bấm "Mở khoá" trên web admin → log khoá ghi `LỆNH UNLOCK qua MQTT`.

Server gửi lệnh vào `smartlock/<mã>/cmd` (QoS 1), payload JSON giống hệt lệnh của `/commands/`:
`{"command_id": "...", "command": "UNLOCK", "token": "...", "expires_in": 30, "source": "web"}`. Khoá ack qua **HTTP** `/ack/`.

`publish_telemetry: true` → khoá đẩy `status` (mỗi heartbeat), `ack`, `event` lên `smartlock/<mã>/status|ack|event`
(chỉ có ích khi phía server có subscriber đọc các topic này).

## 5. Các trường `mqtt` trong config.json
| Trường | Ý nghĩa |
|---|---|
| `enabled` | Bật/tắt kênh MQTT. |
| `url` | Cách ngắn gọn: `wss://host[:port][/path]`, `ws://`, `mqtts://`, `mqtt://`. Có `url` thì nó **đè** `transport/host/port/path/tls`. Không ghi port: wss→443, ws→80, mqtts→8883, mqtt→1883. |
| `transport` | `websockets` (qua tunnel) hoặc `tcp` (nối thẳng broker, dùng khi cùng LAN/triển khai thật). |
| `host`, `port`, `path`, `tls` | Dùng khi không đặt `url`. `path` mặc định `/`. |
| `tls_insecure`, `ca_file` | Broker TCP+TLS dùng chứng chỉ tự ký: trỏ `ca_file` tới CA, hoặc (chỉ để thử) `tls_insecure: true`. |
| `keepalive` | Giây; mặc định 30 (giữ kết nối sống qua tunnel). |
| `headers` | Header HTTP bổ sung cho WebSocket. `X-Tunnel-Skip-AntiPhishing-Page` đã tự thêm. |
| `publish_telemetry` | Xem trên. |

## 6. Xử lý sự cố
| Triệu chứng | Nguyên nhân thường gặp |
|---|---|
| Probe: `Connection refused` / DNS lỗi | Sai host trong `url`, tunnel đã tắt, cổng 9001 chưa forward. |
| Probe: upgrade trả `404` / `502` | Mosquitto chưa chạy hoặc listener 9001 thiếu `protocol websockets`; forward nhầm cổng. |
| Probe: `302` / `401` / `403` hoặc trả HTML | Tunnel đang **Private** → đặt Public. |
| WebSocket 101 nhưng `rc=4/5` | Sai username/secret hoặc ACL từ chối (kiểm `passwd`, `acl`, và `per_listener_settings true` đã áp cho listener 9001). |
| Nối được nhưng không nhận lệnh | Django publish sai topic (đúng: `smartlock/<mã in HOA>/cmd`) hoặc user `django` thiếu quyền `write` trong ACL. Lệnh vẫn tới qua HTTP trong ≤ 3s nên khoá vẫn hoạt động. |
| Rớt kết nối định kỳ | Tunnel/proxy cắt kết nối rảnh → giảm `keepalive` (vd 15). Khoá tự nối lại (2–30 s). |

## 7. Lên ESP32 thật
- `umqtt.simple` (MicroPython) **không hỗ trợ WebSocket**. Qua dev tunnel nên dùng ESP-IDF/Arduino-ESP32 với thư viện MQTT hỗ trợ `wss`
  (ví dụ `esp-mqtt` của ESP-IDF có transport WS/WSS).
- Khi triển khai thật (không qua tunnel), cho khoá nối thẳng broker **TCP + TLS** (`transport: "tcp"`, `mqtts://host:8883`) - nhẹ hơn WebSocket.
- Nhớ: lệnh quan trọng vẫn có HTTP polling làm dự phòng, nên MQTT hỏng không làm khoá mất điều khiển từ xa.

## 8. Bảo mật
- Cổng tunnel **Public** nghĩa là ai có URL đều chạm được broker → bắt buộc `allow_anonymous false`, mật khẩu mạnh, ACL như mẫu.
- Chỉ forward **9001** (WebSocket có xác thực). Không forward 1883 và không forward giao diện giả lập (`:8080`, không có đăng nhập, mở khoá được).
- Tắt forward khi không dùng. Secret đã lộ (ảnh chụp, chat) thì **Xoay secret** trên trang admin rồi cập nhật `passwd`.
