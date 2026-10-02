# Thiết bị ảo Smartlock – Hướng dẫn

## 1. Đặt file
Giải nén zip **vào thư mục `smartlock_django\`** (cùng cấp `smartlock\`), kết quả:
```
smartlock_django\
├── manage.py                  (mới)
├── check_project.py           (mới)
└── virtual_device\
    ├── virtual_lock.py        khoá ảo (MQTT)
    ├── create_virtual_device.py   tạo thiết bị + in thông tin
    ├── make_ticket.py         sinh vé BLE/NFC
    ├── requirements.txt, mosquitto.dev.conf, .env.example
    └── vscode-extension\      giao diện khoá trong VS Code
```
File `.env.example` là file ẩn (bật *View → Show → Hidden items*).

## 2. Cài đặt (1 lần)
```powershell
cd D:\.GitHub\He_Thong_Cua_Thong_Minh_HP_IoTs\smartlock_django
.\.venv\Scripts\activate
pip install -r virtual_device\requirements.txt
python manage.py check            # hoặc: python check_project.py
```
**Dùng chung 1 file `.env`**: `D:\.GitHub\He_Thong_Cua_Thong_Minh_HP_IoTs\.env` (file server đang dùng).
Khoá ảo đọc `MQTT_HOST`, `MQTT_PORT` từ đó; `VDEV_CODE`, `VDEV_SECRET` được script tạo thiết bị tự thêm vào cuối file
(giữ nguyên các dòng khác). `virtual_device\.env` không bắt buộc, chỉ dùng nếu muốn ghi đè riêng cho khoá ảo.

## 3. Tạo thiết bị ảo
```powershell
python virtual_device\create_virtual_device.py --code SL-DEMO-001 --name "Cửa demo"
```
In ra mã, tên, loại, MAC, trạng thái và **SECRET** (chỉ hiện 1 lần); tự ghi `VDEV_CODE`/`VDEV_SECRET`
vào `.env` chung. Thiết bị đã tạo ở web (Loại = *Thiết bị ảo*) thì thêm `--rotate` để lấy secret.

## 4. Chạy hệ thống (mỗi cửa sổ terminal riêng)
1. Broker: `mosquitto -c virtual_device\mosquitto.dev.conf`
2. Server: `python manage.py runserver`
3. Subscriber MQTT của dự án (như bạn vẫn chạy)
4. Khoá ảo – chọn 1:
   - **VS Code (có giao diện):** mục 5
   - **Terminal:** `python virtual_device\virtual_lock.py` (đọc code/secret/MQTT từ `.env` chung)

## 5. Giao diện trong VS Code
1. Mở thư mục `virtual_device\vscode-extension` bằng VS Code → **F5** → cửa sổ mới → *Open Folder* `smartlock_django`.
   (Cài thường trực: chép thư mục `vscode-extension` vào `%USERPROFILE%\.vscode\extensions\smartlock-virtual-lock-0.2.0\`, restart VS Code.)
2. Settings → `smartlockVirtual.pythonPath` = `...\smartlock_django\.venv\Scripts\python.exe`.
3. Biểu tượng ổ khoá ở thanh trái → **▶ Khởi động**.
   Có: Khoá/Mở, cạy phá, ngắt mạng, pin, bàn phím PIN, quẹt thẻ, vé BLE/NFC, nhật ký.

## 6. Admin thao tác trên web
1. `/manage-sys/devices/` → mở thiết bị → **Gán chủ**.
   - Chủ phải là **user thường** (tài khoản admin không được làm chủ khoá).
   - Chỉ gán được khi khoá ảo đang chạy và đã kết nối (nếu không: `NOT_CONNECTED`).
2. Hoặc user tự thêm khoá: *Thiết bị → Thêm khoá* bằng mã + secret.
3. Bấm Mở/Khoá trên web → khoá ảo đổi trạng thái và ack.

## 7. Test nhanh
| Muốn test | Làm |
|---|---|
| Mở bằng thẻ | Đăng ký thẻ trên web → ô *Thẻ RFID* nhập UID → Quẹt |
| Khoá tạm | Quẹt 3 thẻ lạ liên tiếp |
| PIN | Tạo PIN trên web → bấm trên bàn phím → OK |
| BLE/NFC | `python virtual_device\make_ticket.py --code SL-DEMO-001 --user-email a@b.com --kind ble` → dán vé → BLE/NFC (thêm `--expired` để thử vé hết hạn) |
| Mất mạng | Nút 📴 Mạng → thao tác → nối lại (sự kiện gửi bù) |

## 8. Lỗi thường gặp
| Lỗi | Cách xử lý |
|---|---|
| `ModuleNotFoundError: smartlock_django` | Đặt sai chỗ: file phải nằm trong `smartlock_django\virtual_device\` cạnh `manage.py` |
| `Thiếu paho-mqtt` | `pythonPath` không phải Python của venv |
| `Broker từ chối (rc=5)` | Sai code/secret, hoặc broker bật auth mà Django chưa chạy (dev dùng `mosquitto.dev.conf`) |
| Không thấy `virtual_lock.py` trong VS Code | Chưa mở thư mục `smartlock_django`, hoặc đặt `smartlockVirtual.deviceDir` |
| Không thấy biểu tượng ổ khoá | F5 sai thư mục: phải mở đúng thư mục có `package.json` |

## 9. Lưu ý
Định dạng JSON của `status` / `ack` / `event` là **suy đoán** (chưa có file subscriber MQTT). Nếu server không phản ứng
với sự kiện (vd quẹt thẻ nhưng không thấy UNLOCK), sửa `EVENT_TYPE`, `snapshot()`, `handle_command()` trong
`virtual_lock.py` cho khớp subscriber, hoặc gửi file subscriber để chỉnh.
