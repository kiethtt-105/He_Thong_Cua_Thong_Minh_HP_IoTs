# Smart Lock API v1 — tài liệu cho lập trình app

Base URL: `https://<domain>/api/v1/` · JSON · Thời gian ISO‑8601 (UTC).

## 1. Cài đặt (3 bước)

1. **Chép đè** 6 file trong thư mục `smartlock/api/` (`common.py, mobile_auth.py, serializers.py, auth_views.py, views.py, urls.py`).
   Nếu bạn đã có `extra_views.py`, `auth_serializers.py`: không còn được dùng, có thể xoá sau khi kiểm tra.
2. **Sửa `settings.py`** — thêm 2 dòng vào khối `REST_FRAMEWORK`:
   ```python
   'EXCEPTION_HANDLER': 'smartlock.api.common.api_exception_handler',
   'DEFAULT_PAGINATION_CLASS': 'smartlock.api.common.StandardPagination',  # tuỳ chọn
   ```
3. **Thu hồi phiên app khi đặt lại mật khẩu trên web** — trong `views.reset_password`, sau `user.save()` thêm:
   ```python
   from .api.mobile_auth import revoke_all_sessions
   revoke_all_sessions(user)
   ```
   (đổi mật khẩu qua API đã tự làm việc này).

Không cần migration mới (dùng lại `MobileSession`).

## 2. Quy ước chung

**Xác thực:** `Authorization: Bearer <access_token>` (sống 15 phút).
**Lỗi** luôn có dạng:
```json
{"error": {"code": "DEVICE_OFFLINE", "message": "Thiết bị đang không online.", "details": null}}
```
| HTTP | Ý nghĩa thường gặp |
|---|---|
| 400 | dữ liệu sai (`VALIDATION_ERROR`, `details` theo từng trường) |
| 401 | `TOKEN_EXPIRED` → gọi refresh; `SESSION_REVOKED` / `INVALID_TOKEN` → về màn đăng nhập |
| 403 | thiếu quyền · 404 không thấy (kể cả thiết bị của người khác) |
| 409 | xung đột (offline, trùng) · 423 tài khoản bị khoá tạm · 429 quá tốc độ/quá số lần sai · 502 không tới được thiết bị |

**Phân trang** (`?page=1&page_size=20`, tối đa 100): `{"count","next","previous","results":[...]}`.

## 3. Luồng xác thực của app

```
Login ──► (không 2FA) ──► {access_token, refresh_token, user}
   └────► requires_2fa ──► [email? POST 2fa/send-email] ──► POST 2fa/verify ──► tokens
Mọi request: Bearer access ──401 TOKEN_EXPIRED──► POST auth/refresh ──► tokens mới (xoay vòng) ──► thử lại
```
- **Lưu refresh_token trong Android Keystore / EncryptedSharedPreferences.**
- Mỗi lần refresh trả refresh_token **mới**; token cũ vô hiệu. Dùng lại token cũ (sau 10 giây) ⇒ server huỷ cả phiên.
- Chỉ **một** request refresh tại một thời điểm (dùng mutex/Authenticator của OkHttp).
- Quản trị viên **không** đăng nhập được ở app (như web). Passkey chưa hỗ trợ trên app (dùng TOTP/Email OTP).

## 4. Danh sách endpoint

### Công khai
| | | |
|---|---|---|
| GET | `app/config/?version=1.0.0` | `force_update`, `min_app_version`, `registration_enabled` — gọi khi mở app |

### Xác thực (`auth/…`, không cần token)
| | | Body → kết quả |
|---|---|---|
| POST | `auth/register/` | `email, username, password, full_name?` → 201, gửi email xác thực (mở link trên trình duyệt) |
| POST | `auth/resend-verification/` | `email` → 200 (luôn giống nhau) |
| POST | `auth/login/` | `identifier, password, device_name?, platform?, app_version?, fcm_token?` → tokens **hoặc** `{requires_2fa, challenge_token, methods:["totp","email"]}` |
| POST | `auth/2fa/send-email/` | `challenge_token` → gửi OTP email (cooldown 60s) |
| POST | `auth/2fa/verify/` | `challenge_token, method("totp"\|"email"), code` → tokens (challenge sống 5 phút) |
| POST | `auth/refresh/` | `refresh_token` → tokens mới |
| POST | `auth/password/forgot/` | `email` → 200 (email chứa link đặt lại trên web) |
| POST | `auth/logout/` · `auth/logout-all/` | (cần token) |
| POST | `auth/password/change/` | `old_password, new_password` → thu hồi các phiên khác |

Phản hồi đăng nhập thành công:
```json
{"user": {...}, "session_id": "…", "token_type": "Bearer",
 "access_token": "…", "expires_in": 900, "refresh_token": "…"}
```
Mã lỗi đăng nhập: `INVALID_CREDENTIALS` 401 · `EMAIL_NOT_VERIFIED` 403 · `ACCOUNT_LOCKED` 423 (`details.retry_after_minutes`) · `IP_BLOCKED` 403 · `INVALID_CODE` 401 · `TOO_MANY_ATTEMPTS` 429.

### Tài khoản & phiên
| | | |
|---|---|---|
| GET/PATCH | `me/` | hồ sơ (`full_name`, `phone`) |
| GET | `me/sessions/` | các máy đang đăng nhập (`is_current`) |
| DELETE | `me/sessions/{id}/` | đăng xuất từ xa |
| PUT | `me/push-token/` | `{fcm_token?, push_enabled?}` — gọi lại mỗi khi FCM cấp token mới (`onNewToken`) |
| GET | `sync/` | devices + 20 thông báo + unread_count — 1 request cho màn hình chính |

### Thiết bị
| | | |
|---|---|---|
| GET/POST | `devices/` | danh sách (kèm `lock_state`, `is_owner`, `permissions`) / tạo (trả `provisioning_secret` **một lần**) |
| GET/PATCH | `devices/{id}/` | PATCH chỉ chủ: `name, location, wifi_enabled, bluetooth_enabled, nfc_enabled` |
| POST | `devices/{id}/command/` | `{"command":"LOCK\|UNLOCK\|REBOOT"}` → **202** `{id,status}`; REBOOT chỉ chủ |
| GET | `devices/{id}/command/` | lịch sử lệnh (phân trang) |
| GET | `commands/{id}/` | poll trạng thái: `pending → sent → acknowledged` (hoặc `failed/expired`). Poll mỗi ~1s, tối đa ~15s |
| GET | `devices/{id}/status-history/?limit=100` | log pin/khoá/nhiệt độ |
| GET | `devices/{id}/access-events/?method=RFID\|PIN\|FACE&success=true` | lịch sử ra vào |

Lệnh: cần quyền `LOCK`/`UNLOCK` (chủ luôn có); thiết bị phải `online` (409 `DEVICE_OFFLINE`); throttle 30/phút.

### Chia sẻ & quyền
| | | |
|---|---|---|
| GET | `permissions/` | danh mục quyền |
| GET/POST | `share/codes/` | POST: `device_id, minutes?(1‑1440), permissions[], recipient?` → trả `code` (6 số) **một lần** |
| DELETE | `share/codes/{id}/` | huỷ mã |
| POST | `share/redeem/` | `{"code":"123456"}` → nhận quyền 24h (10/phút; sai 5 lần/15 phút bị chặn) |
| GET | `share/my-accesses/` · DELETE `share/my-accesses/{id}/` | quyền tôi được chia sẻ / tự rời |
| GET | `devices/{id}/accesses/` | (chủ) ai đang được chia sẻ |
| PATCH/DELETE | `devices/{id}/accesses/{access_id}/` | (chủ) sửa `permissions`, `expires_at` / thu hồi |

Mã quyền: `LOCK, UNLOCK, manage_pins, manage_face_profiles`.

### PIN khách · khuôn mặt · thẻ
| | | |
|---|---|---|
| GET/POST | `devices/{id}/door-pins/` | cần `manage_pins`. POST: `ttl_minutes(≤43200), max_uses(0=∞), label` → trả `pin` **một lần** |
| POST | `devices/{id}/door-pins/{pin_id}/revoke/` | thu hồi |
| GET/POST | `devices/{id}/face-profiles/` | POST: `embedding[32..1024 float], name?, consent_confirmed:true` (cần `manage_face_profiles`). Không bao giờ trả embedding |
| PATCH/DELETE | `devices/{id}/face-profiles/{pid}/` | PATCH `{is_active}` (bỏ trống = đảo) |
| GET/POST | `cards/` | POST: `device_id, uid, name?` (chỉ chủ thiết bị) |
| PATCH/DELETE | `cards/{id}/` | `name`, `is_active` |

### Tự động hoá · thông báo · nhật ký
| | | |
|---|---|---|
| GET | `automation-rules/meta/` | danh sách trigger/action để dựng form |
| GET/POST | `automation-rules/` | `name, device?, trigger_type, threshold_value, threshold_window_seconds?, action_type, notify_severity, cooldown_seconds, is_active` |
| GET/PATCH/DELETE | `automation-rules/{id}/` · GET `…/logs/` | |
| GET | `notifications/?unread=1` | DELETE `notifications/` xoá hết thông báo đã đọc |
| GET | `notifications/unread-count/` · POST `notifications/read-all/` | |
| POST/DELETE | `notifications/{id}/` | POST = đánh dấu đã đọc |
| GET | `announcements/` · `audit-logs/?status=ok\|fail&q=&device=` | |

## 5. Push (FCM)

Server tự gửi push mỗi khi có `Notification` mới (đã có `push.py`). Data payload: `notification_id, type, severity, device_id`.
Android phải tạo 3 channel: `smartlock_info`, `smartlock_warning`, `smartlock_critical`.
Gửi `fcm_token` lúc login hoặc qua `PUT me/push-token/`.

## 6. Kiểm thử nhanh

```bash
curl -X POST $BASE/api/v1/auth/login/ -H 'Content-Type: application/json' \
  -d '{"identifier":"user@example.com","password":"…","device_name":"Pixel 8"}'

curl $BASE/api/v1/devices/ -H "Authorization: Bearer $ACCESS"

curl -X POST $BASE/api/v1/devices/$ID/command/ -H "Authorization: Bearer $ACCESS" \
  -H 'Content-Type: application/json' -d '{"command":"UNLOCK"}'
```
