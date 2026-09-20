# 🔐 HP IoTs – Smart Door Lock System

> **Hệ thống cửa thông minh IoT – Quản lý thiết bị, kiểm soát truy cập và giám sát hoạt động**

[![Python](https://img.shields.io/badge/Python-3.x-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![Django](https://img.shields.io/badge/Django-5.2-092E20?logo=django&logoColor=white)](https://www.djangoproject.com/)
[![PostgreSQL](https://img.shields.io/badge/PostgreSQL-Supabase-4169E1?logo=postgresql&logoColor=white)](https://www.postgresql.org/)
[![MQTT](https://img.shields.io/badge/IoT-MQTT-660066?logo=mqtt&logoColor=white)](https://mqtt.org/)
[![REST](https://img.shields.io/badge/API-Django%20REST%20Framework-red)](https://www.django-rest-framework.org/)

---

## 📌 Giới thiệu

**HP IoTs Smart Door Lock** là hệ thống quản lý và kiểm soát cửa thông minh được xây dựng theo mô hình **IoT + Web Application + Backend**.

Hệ thống tập trung vào việc quản lý:

- 👤 Người dùng
- 🔐 Thiết bị khóa cửa
- 🪪 Thẻ NFC
- 👥 Quyền truy cập thiết bị
- 🔗 Chia sẻ quyền truy cập
- ⚙️ Lệnh điều khiển thiết bị
- 📡 Trạng thái thiết bị
- 📝 Audit Log
- 🔔 Notification
- 🛠️ Hỗ trợ và khôi phục thiết bị
- 🔒 Xác thực và các cơ chế bảo mật

Backend được xây dựng bằng **Django 5.2**, sử dụng **PostgreSQL thông qua Supabase Transaction Pooler** làm cơ sở dữ liệu và được thiết kế để có thể kết nối với thiết bị IoT thông qua **MQTT**.

---

# 🎯 Mục tiêu

Dự án được xây dựng nhằm tạo ra một nền tảng quản lý Smart Lock có khả năng:

1. Quản lý người dùng và tài khoản.
2. Quản lý nhiều thiết bị Smart Lock.
3. Phân quyền người dùng trên từng thiết bị.
4. Cho phép chia sẻ quyền truy cập thông qua mã chia sẻ.
5. Quản lý thẻ NFC.
6. Gửi lệnh điều khiển đến thiết bị.
7. Theo dõi trạng thái thiết bị.
8. Ghi nhận lịch sử và hoạt động bảo mật.
9. Hỗ trợ cơ chế khóa tài khoản khi đăng nhập sai nhiều lần.
10. Hỗ trợ xác thực email và khôi phục mật khẩu.
11. Quản lý yêu cầu hỗ trợ và khôi phục thiết bị.
12. Chuẩn bị nền tảng giao tiếp IoT thông qua MQTT.

---

# 🏗️ Kiến trúc hệ thống

```text
                         ┌──────────────────────┐
                         │        USER          │
                         │  Web / SmartLockApp  │
                         └──────────┬───────────┘
                                    │
                                    │ HTTP / HTTPS
                                    ▼
                    ┌───────────────────────────────┐
                    │        DJANGO BACKEND         │
                    │                               │
                    │          smartlock            │
                    │                               │
                    │  Authentication               │
                    │  Device Management            │
                    │  Permission Management        │
                    │  NFC Management               │
                    │  Command Management           │
                    │  Audit / Notification         │
                    │  Support / Recovery           │
                    └──────────────┬────────────────┘
                                   │
                    ┌──────────────┼──────────────┐
                    │              │              │
                    ▼              ▼              ▼
             ┌───────────┐   ┌───────────┐   ┌────────────┐
             │ PostgreSQL│   │   MQTT    │   │   Email    │
             │  Supabase │   │  Broker   │   │   SMTP     │
             └───────────┘   └─────┬─────┘   └────────────┘
                                   │
                                   │ IoT Communication
                                   ▼
                          ┌──────────────────┐
                          │   SMART LOCK     │
                          │      DEVICE      │
                          ├──────────────────┤
                          │ Lock / Unlock    │
                          │ NFC Reader       │
                          │ WiFi             │
                          │ Bluetooth        │
                          │ Device Status    │
                          └──────────────────┘
```

---

# 🧩 Thành phần chính

```text
He_Thong_Cua_Thong_Minh_HP_IoTs/
│
├── SmartLockApp/
│
├── dtb/
│
├── smartlock_django/
│
├── .gitignore
│
└── Huong Dan Triển Khai.txt
```

### `SmartLockApp`

Thành phần ứng dụng của hệ thống Smart Lock.

### `smartlock_django`

Backend trung tâm của hệ thống.

### `dtb`

Thành phần dữ liệu/cơ sở dữ liệu của dự án.

### `Huong Dan Triển Khai.txt`

Tài liệu hướng dẫn thiết lập môi trường và chạy hệ thống.

---

# ⚙️ Tech Stack

## Backend

| Công nghệ | Vai trò |
|---|---|
| Python | Ngôn ngữ lập trình |
| Django 5.2 | Web Framework |
| Django REST Framework | REST API |
| Django Allauth | Authentication support |
| Django OTP | OTP/TOTP support |
| Django Extensions | Development utilities |

## Database

- PostgreSQL
- Supabase
- Supabase Transaction Pooler

## IoT

- MQTT
- Device Management
- Device Status
- Device Command
- NFC Reader
- NFC Access Card

## Security

- Django Authentication
- Password Hashing
- Email Verification
- Password Reset
- Fernet Encryption
- SHA-256 Token Hashing
- Login Attempt Logging
- Login Lockout
- IP Blacklist
- Permission System
- Audit Logging

---

# 🔐 1. User & Authentication

Hệ thống sử dụng **Custom User Model** thay cho Django User mặc định.

User được quản lý bằng:

```text
User
├── UUID
├── Email
├── Username
├── Full Name
├── Phone
├── Avatar
├── Admin status
├── Active status
├── Email verification
├── Created At
└── Updated At
```

User sử dụng:

```python
USERNAME_FIELD = 'email'
```

### Authentication Features

- Login bằng Email / Username
- Logout
- Register
- Email Verification
- Resend Verification Email
- Password Reset
- Session Timeout
- Login Attempt Logging
- Login Lockout
- IP Blacklist

---

# 🛡️ 2. Login Security

Hệ thống theo dõi các lần đăng nhập thông qua `LoginAttemptLog`.

Mỗi attempt có thể lưu:

```text
Identifier
User
IP Address
User Agent
Success
Created At
```

Nếu đăng nhập thất bại nhiều lần, hệ thống sử dụng `LoginLockout` để khóa tài khoản tạm thời.

Mặc định:

```text
Maximum failed attempts: 5
Lockout stages: 5 / 10 / 30 minutes
```

---

# 🔒 3. Device Management

Mỗi Smart Lock được biểu diễn bằng model `Device`.

Một thiết bị có:

```text
Device
├── UUID
├── Device Code
├── Name
├── Owner
├── MAC Address
├── Firmware Version
├── Status
├── Battery Level
├── Location
├── Last Seen
├── Bluetooth
├── WiFi
└── NFC
```

Các trạng thái thiết bị:

```text
provisioning
online
offline
maintenance
```

---

# 🎛️ 4. Device Command

Backend hỗ trợ quản lý command gửi tới thiết bị.

Các command:

```text
LOCK
UNLOCK
REBOOT
```

Model `DeviceCommand` lưu:

```text
Device
Issued By
Command Type
Payload
Status
Command Token Hash
Expires At
Created At
Acknowledged At
```

Trạng thái command:

```text
pending
sent
acknowledged
failed
expired
```

Command có TTL mặc định:

```text
120 seconds
```

---

# 📡 5. Device Status

Hệ thống lưu lịch sử trạng thái thiết bị thông qua `DeviceStatusLog`.

Thông tin bao gồm:

```text
Battery Level
Signal Strength
Lock State
Tamper Detection
Temperature
Raw Payload
Recorded At
```

Lock state hỗ trợ:

```text
locked
unlocked
jammed
unknown
```

---

# 👥 6. Permission & Device Access

Mỗi thiết bị có thể được cấp quyền cho nhiều người dùng.

```text
User
  │
  ▼
DeviceAccess
  │
  ├── Device
  ├── User
  ├── Permissions
  ├── Valid From
  ├── Expires At
  ├── Accepted
  └── Active
```

Nguồn cấp quyền:

```text
DIRECT
SHARE_CODE
```

---

# 🔗 7. Share Access Code

Hệ thống hỗ trợ chia sẻ quyền truy cập thiết bị bằng **mã 6 chữ số**.

Mã được lưu dưới dạng encrypted data bằng **Fernet**.

```text
Owner
  │
  │ Generate Share Code
  ▼
ShareAccessCode
  │
  ├── Device
  ├── Permissions
  ├── Encrypted Code
  └── Expiry
       │
       ▼
   Guest User
```

Thời gian chia sẻ mặc định:

```text
24 hours
```

---

# 🪪 8. NFC Access Control

Hệ thống có module quản lý NFC:

```text
NfcReader
NfcReaderConfig
NfcSession
AccessCard
CardDeviceAccess
NfcLog
```

### Access Card

Mỗi thẻ có:

```text
Card UID Hash
User
Name
Active Status
Created At
Updated At
```

UID của thẻ được lưu dưới dạng hash thay vì lưu trực tiếp UID gốc.

### Card → Device

Một Access Card có thể được cấp quyền trên thiết bị thông qua:

```text
CardDeviceAccess
```

---

# 📋 9. NFC Logging

Các sự kiện NFC được lưu trong `NfcLog`.

Các event:

```text
TAP_SUCCESS
TAP_FAILED
CARD_REGISTER
READER_CONNECTED
READER_DISCONNECTED
CONFIG_UPDATED
SESSION_TIMEOUT
```

Log có thể chứa:

```text
Reader
NFC Tag
Device
User
Event Type
Success
IP Address
User Agent
Metadata
Created At
```

---

# 🛠️ 10. Support & Recovery

Hệ thống có module `SupportRequest` dành cho các thao tác hỗ trợ và khôi phục.

Các action:

```text
ADD_CARD
REMOVE_CARD
CHANGE_PERMISSION
RESET_REMOTE
RECOVERY
TRANSFER_OWNER
OTA_SENSITIVE
OTHER
```

Trạng thái:

```text
pending
approved
executed
expired
rejected
cancelled
```

Một số thao tác nhạy cảm yêu cầu thêm recovery code.

---

# 🔔 11. Notification

Người dùng có hệ thống notification riêng.

Notification chứa:

```text
User
Device
Type
Title
Message
Severity
Read Status
Created At
Read At
```

Severity:

```text
info
warning
critical
```

Ví dụ notification:

```text
LOGIN_LOCKOUT
SECURITY
WELCOME
SYSTEM
```

---

# 📝 12. Audit Log

`AuditLog` ghi nhận các hành động liên quan tới:

- User
- Device
- Security
- Authentication
- Permission
- Support
- System

Thông tin log:

```text
Actor User
Target User
Device
Action
Username Attempt
Severity
Success
IP Address
User Agent
Metadata
Created At
```

---

# ⚙️ 13. System Settings

Hệ thống có model `SystemSettings` để quản lý cấu hình runtime.

Bao gồm:

```text
Registration Enabled
Verification Token Expiry
Share Code Expiry
Login Lockout Stages
Session Timeout
IP Whitelist
IP Blacklist
Updated By
```

---

# 🔐 14. Encryption

Project sử dụng **Fernet** để mã hóa dữ liệu nhạy cảm.

`FERNET_KEY` được lấy từ biến môi trường:

```env
FERNET_KEY=...
```

Token trong một số workflow cũng được hash bằng SHA-256 trước khi lưu database.

> **Không commit secret hoặc file `.env` lên GitHub.**

---

# 📧 15. Email System

Email được sử dụng cho:

- Email Verification
- Resend Verification
- Password Reset
- Security Notification

Cấu hình SMTP:

```env
EMAIL_HOST=
EMAIL_PORT=
EMAIL_USE_TLS=
EMAIL_USE_SSL=
EMAIL_HOST_USER=
EMAIL_HOST_PASSWORD=
DEFAULT_FROM_EMAIL=
```

---

# 📡 16. MQTT

Backend có cấu hình dành cho MQTT:

```env
MQTT_HOST=
MQTT_PORT=1883
MQTT_TOPIC_PREFIX=
```

Kiến trúc:

```text
Django
   │
   │ MQTT
   ▼
MQTT Broker
   │
   ▼
Smart Lock Device
```

Các chức năng Device Command và Device Status được thiết kế để phục vụ giao tiếp giữa backend và thiết bị IoT.

---

# 🖥️ 17. Dashboard

Dashboard người dùng cung cấp thông tin tổng quan:

```text
Total Devices
Online Devices
Access Card Status
Unread Notifications
Active Share Code
Recent Notifications
Recent Audit Logs
Announcements
Activity Chart
```

Dashboard cũng lựa chọn thiết bị hiện tại và hiển thị trạng thái khóa gần nhất.

---

# 👨‍💼 18. Admin System

Khu vực quản trị riêng:

```text
/admin-sys/login/
/admin-sys/logout/
/admin-sys/dashboard/
/admin-sys/users/
/admin-sys/users/<id>/
/admin-sys/devices/
/admin-sys/devices/<id>/
/admin-sys/support/
/admin-sys/support/<id>/
/admin-sys/logs/
/admin-sys/settings/
```

Admin có thể quản lý:

- Users
- Devices
- Support Requests
- Audit Logs
- System Settings

---

# 🌐 19. User Routes

Các route chính:

```text
/
├── /login/
├── /logout/
├── /register/
├── /verify-email/
├── /password-reset/
├── /devices/
├── /devices/add/
├── /devices/<id>/
├── /devices/<id>/command/
├── /nfc/tags/
├── /nfc/reader/
├── /share/codes/
├── /share/request/
├── /support/requests/
├── /permissions/manage/
├── /settings/system/
├── /notifications/
├── /profile/
└── /audit/logs/
```

---

# 📂 Django Structure

```text
smartlock_django/
│
├── manage.py
├── requirements.txt
│
├── smartlock_django/
│   ├── settings.py
│   ├── urls.py
│   ├── asgi.py
│   └── wsgi.py
│
├── smartlock/
│   ├── models.py
│   ├── views.py
│   ├── urls.py
│   ├── utils.py
│   ├── admin.py
│   ├── email_templates.py
│   └── ...
│
├── templates/
│
└── ...
```

---

# 🗄️ Database Model Overview

```text
                         ┌────────────┐
                         │    User    │
                         └─────┬──────┘
                               │
             ┌─────────────────┼──────────────────┐
             │                 │                  │
             ▼                 ▼                  ▼
       DeviceAccess       AccessCard       AuditLog
             │                 │
             ▼                 ▼
          Device        CardDeviceAccess
             │
       ┌─────┼──────────────┐
       │     │              │
       ▼     ▼              ▼
 DeviceLog  Command      NfcReader
                           │
                           ▼
                       NfcSession
                           │
                           ▼
                         NfcLog
```

---

# 🚀 Installation

## 1. Clone repository

```bash
git clone https://github.com/kiethtt-105/He_Thong_Cua_Thong_Minh_HP_IoTs.git
cd He_Thong_Cua_Thong_Minh_HP_IoTs
```

---

# 🐍 2. Create Virtual Environment

Windows:

```powershell
python -m venv .venv
```

Activate:

```powershell
.venv\Scripts\activate
```

---

# 📦 3. Install Dependencies

```powershell
cd smartlock_django
pip install -r requirements.txt
```

---

# 🔑 4. Environment Variables

Tạo file:

```text
.env
```

Các biến quan trọng:

```env
DJANGO_SECRET_KEY=
FERNET_KEY=

DEBUG=False

ALLOWED_HOSTS=localhost,127.0.0.1

DB_NAME=
DB_USER=
DB_PASSWORD=
DB_HOST=
DB_PORT=6543
DB_SSLMODE=require

MQTT_HOST=
MQTT_PORT=1883
MQTT_TOPIC_PREFIX=

EMAIL_HOST=
EMAIL_PORT=465
EMAIL_USE_SSL=True
EMAIL_HOST_USER=
EMAIL_HOST_PASSWORD=
DEFAULT_FROM_EMAIL=

PASSWORD_RESET_TIMEOUT_MINUTES=5
OTP_EXPIRY_MINUTES=5
OTP_MAX_ATTEMPTS=5
```

> Các giá trị thực tế phải được cấu hình theo môi trường triển khai.

---

# 🗄️ 5. Database Migration

Từ thư mục `smartlock_django/`:

```powershell
python manage.py makemigrations smartlock
python manage.py migrate
```

---

# 👤 6. Create Superuser

```powershell
python manage.py createsuperuser
```

Nhập:

```text
Email
Username
Password
```

---

# ▶️ 7. Run Development Server

```powershell
python manage.py runserver
```

Truy cập:

```text
http://127.0.0.1:8000/
```

---

# 📧 8. Test Email

Repository có các script kiểm thử email:

```text
smartlock_django/
├── test_email.py
└── test_send_mail.py
```

Có thể sử dụng để kiểm tra cấu hình SMTP trong môi trường local.

---

# 🌍 Deployment

Backend được cấu hình để chạy trong môi trường serverless như Vercel.

Các thành phần liên quan:

```text
HTTPS
Secure Cookies
CSRF Trusted Origins
WhiteNoise
PostgreSQL Transaction Pooler
Environment Variables
```

Database sử dụng connection configuration phù hợp với Supabase Transaction Pooler:

```text
CONN_MAX_AGE = 0
DISABLE_SERVER_SIDE_CURSORS = True
SSL = require
```

---

# 📡 Environment Architecture

```text
                    GitHub
                       │
                       ▼
                  Deployment
                       │
                       ▼
                  Django App
                       │
          ┌────────────┼─────────────┐
          │            │             │
          ▼            ▼             ▼
      Supabase       MQTT           SMTP
      PostgreSQL     Broker          Email
          │            │
          │            ▼
          │       Smart Lock
          │          Device
          │
          ▼
       Application Data
```

---

# 🔒 Security Design

## Authentication

```text
Email / Username
       │
       ▼
Password
       │
       ▼
Django Authentication
```

## Email Verification

```text
Register
   │
   ▼
Verification Token
   │
   ▼
Email
   │
   ▼
Verify
   │
   ▼
Activate Account
```

## Login Protection

```text
Login Failed
     │
     ▼
LoginAttemptLog
     │
     ▼
Failed Attempts
     │
     ▼
Threshold
     │
     ▼
Temporary Lockout
```

## Device Permission

```text
User
 │
 ├── Owner
 │
 └── Shared Access
       │
       ▼
   Permission
       │
       ▼
   Device Action
```

---

# 📊 Project Features

| Module | Status |
|---|---|
| User Authentication | ✅ |
| User Registration | ✅ |
| Email Verification | ✅ |
| Password Reset | ✅ |
| Login Attempt Logging | ✅ |
| Login Lockout | ✅ |
| Device Management | ✅ |
| Device Status | ✅ |
| Device Command | ✅ |
| Permission Management | ✅ |
| Device Sharing | ✅ |
| Share Code | ✅ |
| NFC Reader | ✅ |
| NFC Access Card | ✅ |
| NFC Logging | ✅ |
| Notification | ✅ |
| Audit Logging | ✅ |
| Support Request | ✅ |
| Recovery Workflow | ✅ |
| System Settings | ✅ |
| Fernet Encryption | ✅ |
| MQTT Configuration | ✅ |
| PostgreSQL / Supabase | ✅ |
| Django REST Framework | ✅ |

---

# 🛠️ Development Roadmap

- [ ] Hoàn thiện giao tiếp MQTT giữa Backend và Hardware
- [ ] Đồng bộ Device Status theo thời gian thực
- [ ] Hoàn thiện firmware Smart Lock
- [ ] Real-time notification
- [ ] Push notification
- [ ] OTA firmware update
- [ ] Device health monitoring
- [ ] Tamper detection
- [ ] Rate limiting cho API
- [ ] Automated testing
- [ ] CI/CD
- [ ] Docker deployment
- [ ] Monitoring và observability

---

# 📚 Documentation

Tài liệu triển khai gốc:

```text
Huong Dan Triển Khai.txt
```

Nội dung:

```text
1. Tạo Virtual Environment
2. Cài requirements
3. Cấu hình .env
4. Tạo database
5. Migration
6. Tạo Admin
7. Run Server
8. Test Email
```

---

# 👨‍💻 Author

**Huỳnh Trần Tuấn Kiệt**

> HP IoTs – Smart Door Lock System

Vietnam 🇻🇳

---

# 📄 License

This project is developed for **educational, research and project development purposes**.

---

## ⭐ Repository

**GitHub:**

https://github.com/kiethtt-105/He_Thong_Cua_Thong_Minh_HP_IoTs

**Project:**

> 🔐 **HP IoTs – Smart Door Lock System**

> *IoT-based access control, device management and smart security platform.*
