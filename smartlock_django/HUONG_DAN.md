# HƯỚNG DẪN DÁN ĐÈ FILE (Windows, thư mục dự án `D:\.GitHub\He_Thong_Cua_Thong_Minh_HP_IoTs\smartlock_django`)

Gọi thư mục dự án là `PROJ`. **Sao lưu trước** (copy `smartlock\` ra chỗ khác), vì có 1 file bị ghi đè.

## 1. Chép file

| File trong gói | Chép tới | Ghi chú |
|---|---|---|
| `smartlock/management/commands/mqtt_subscriber.py` | `PROJ\smartlock\management\commands\mqtt_subscriber.py` | **GHI ĐÈ** file cũ cùng tên |
| `smartlock/live.py` | `PROJ\smartlock\live.py` | file mới |
| `templates/account/live.html` | `PROJ\templates\account\live.html` | file mới |
| `virtual_device/virtual_lock_3d.html` | `PROJ\virtual_device\` | thư mục đang trống của bạn |
| `tools/virtual_lock.py` | `PROJ\virtual_device\virtual_lock.py` | khoá ảo dòng lệnh (tuỳ chọn) |
| `firmware/smartlock_esp32/` | để riêng, mở bằng Arduino IDE | khoá thật |
| `deploy/` | `PROJ\deploy\` | broker Mosquitto + nginx |

`register_virtual_device.py` và các file khác của bạn: **không đụng**.

## 2. Sửa tay 3 chỗ

**a) `PROJ\smartlock\urls.py`** — thêm dòng import ở đầu và 2 route trong `urlpatterns`:
```python
from . import live
...
    path('devices/<uuid:device_id>/live/', live.live_page, name='device-live'),
    path('devices/<uuid:device_id>/live/data/', live.live_data, name='device-live-data'),
```
(đặt cạnh các route `devices/...` khác.)

**b) `PROJ\smartlock\views.py`** — làm theo `deploy/views_patch.md` (cho tài khoản server đăng nhập broker).

**c) `PROJ\.env`** — thêm:
```
MQTT_PUBLISHER_USERNAME=django-server
MQTT_PUBLISHER_PASSWORD=<mật khẩu dài ngẫu nhiên>
MQTT_TRUSTED_USERNAMES=django-server
MQTT_WEBHOOK_SECRET=<chuỗi dài ngẫu nhiên>
```
Rồi `pip install "paho-mqtt<2"` và thêm `paho-mqtt<2` vào `requirements.txt`.

## 3. Chạy

1. `cd PROJ\deploy`, tạo `.env` từ `.env.example` (`DJANGO_UPSTREAM=http://host.docker.internal:8000`, `DJANGO_HOST=localhost`, `MQTT_WEBHOOK_SECRET` giống bên trên), rồi
   `docker compose -f docker-compose.mqtt.yml --env-file .env up -d`
2. Terminal 1: `python manage.py runserver`
3. Terminal 2: `python manage.py mqtt_subscriber`
4. Lấy `device_code` + secret gốc của thiết bị (admin / `register_virtual_device`; bạn đang có `VDEV_CODE`/`VDEV_SECRET`).
5. **Khoá ảo 3D**: mở `virtual_device\virtual_lock_3d.html` bằng Chrome (hoặc thêm `?code=SL-DEMO-DEV-001&secret=...&auto=1` vào đường dẫn), broker `ws://localhost:9001`, bấm *Kết nối*.
6. **Live view**: đăng nhập web, vào `http://localhost:8000/devices/<id thiết bị>/live/`. Bấm Mở khoá ở trang thiết bị, quẹt thẻ / nhập PIN ở khoá 3D và xem trang live đổi trạng thái trong ≤2 giây.

## 4. Khoá thật (ESP32)
Mở `firmware/smartlock_esp32/smartlock_esp32.ino`, sửa Wi‑Fi, `MQTT_HOST` (IP LAN máy chạy Docker, mở cổng 1883 trên tường lửa Windows), `DEVICE_CODE`, `DEVICE_SECRET`, chân GPIO theo mạch. Cùng giao thức với khoá ảo nên không phải sửa server.

## Chưa làm / chưa kiểm thử
- Chưa chạy thử trên broker, trình duyệt hay phần cứng thật.
- Chưa có: khuôn mặt (camera), BLE/NFC điện thoại trong firmware, đồ hoạ 3D chi tiết hơn, push realtime bằng WebSocket (live view đang poll 2 giây).
