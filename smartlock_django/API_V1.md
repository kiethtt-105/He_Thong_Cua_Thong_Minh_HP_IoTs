# API v1 - dùng chung cho App (Android/iOS) và Web

Mọi endpoint nằm dưới `/api/v1/`. Một bộ API duy nhất; chỉ khác **cách xác thực**:

| Client | Xác thực | Ghi dữ liệu (POST/PUT/PATCH/DELETE) |
|---|---|---|
| App Android / iOS | `Authorization: Bearer <access_token>` | không cần CSRF |
| Web (trình duyệt) | session cookie của Django | thêm header `X-CSRFToken` |

Server tự nhận biết: có header `Authorization: Bearer` => app; không có => web (cookie).
Header Bearer đã gửi mà sai/hết hạn thì trả 401 (không rơi về cookie).

## Định dạng phản hồi

```json
{ "ok": true, ...dữ liệu... }
{ "ok": false, "error": { "code": "MA_LOI", "message": "Thông báo tiếng Việt", ... } }
```

Danh sách trả về có phân trang: `?page=1&page_size=20` => `{items, page, page_size, total, has_next}`.
Thời gian dùng ISO-8601. Body gửi lên là JSON UTF-8 (tối đa 256 KB).

## Đăng nhập

### App
```http
POST /api/v1/auth/login/
{"identifier": "email hoặc username", "password": "...", "platform": "android|ios",
  "device_name": "Pixel 8", "app_version": "1.0.0", "fcm_token": "..."}
```
=> `{ok, user, access_token, refresh_token, expires_in, ...}`. Access token sống 15 phút; đổi bằng
`POST /auth/refresh/ {"refresh_token": "..."}` (refresh token xoay vòng, mỗi lần dùng cho token mới).

### Web
1. `GET /api/v1/auth/csrf/` => nhận cookie `csrftoken` + `{csrf_token}` (gọi 1 lần khi mở trang).
2. `POST /api/v1/auth/login/` với header `X-CSRFToken` và thêm `"client": "web"`
   => server set session cookie, trả `{ok, user, client: "web", csrf_token, session_expires_in}`.
   **Dùng `csrf_token` mới này** cho các request sau (Django xoay token khi đăng nhập).
3. Các request tiếp theo: `fetch(url, {credentials: "same-origin", headers: {"X-CSRFToken": token}})`.

```js
async function api(method, url, body) {
  const r = await fetch(url, {
    method, credentials: 'same-origin',
    headers: {'X-CSRFToken': CSRF, 'Accept': 'application/json',
              ...(body !== undefined ? {'Content-Type': 'application/json'} : {})},
    body: body !== undefined ? JSON.stringify(body) : undefined,
  });
  return r.json();           // {ok: true, ...} hoặc {ok: false, error: {code, message}}
}
```

### Xác thực 2 lớp (cả hai client)
Nếu tài khoản bật 2FA, `login` trả `{two_factor_required: true, challenge_token, methods}`.
Gọi `POST /auth/2fa/verify/ {"challenge_token", "method": "totp|email", "code"}`
(email: gửi mã trước bằng `POST /auth/2fa/email/send/ {"challenge_token"}`).
Kết quả giống `login` thành công (app: token; web: cookie). Challenge nhớ loại client đã chọn ở bước 1.
Passkey chỉ dùng ở trang đăng nhập HTML của web; tài khoản chỉ có Passkey sẽ nhận lỗi `TWO_FACTOR_UNSUPPORTED`.

## Danh sách endpoint

### Xác thực

| Method | Đường dẫn | Dùng cho | Ghi chú |
|---|---|---|---|
| GET | `/api/v1/auth/csrf/` | Công khai | Web: gọi 1 lần khi mở trang để nhận CSRF cookie + token (gửi lại ở header X-CSRFToken). App không cần. |
| POST | `/api/v1/auth/register/` | Công khai |  |
| POST | `/api/v1/auth/login/` | Công khai |  |
| POST | `/api/v1/auth/2fa/verify/` | Công khai |  |
| POST | `/api/v1/auth/2fa/email/send/` | Công khai |  |
| POST | `/api/v1/auth/refresh/` | Công khai |  |
| POST | `/api/v1/auth/logout/` | App + Web | App: thu hồi phiên token hiện tại (all=true: mọi phiên app). Web: đăng xuất session cookie (all=true: đồng thời thu hồi mọi phiên app của tài khoản). |
| POST | `/api/v1/auth/resend-verification/` | Công khai |  |
| POST | `/api/v1/auth/password-reset/` | Công khai |  |
| POST | `/api/v1/auth/password-reset/confirm/` | Công khai | Đặt mật khẩu mới từ link trong email: {uid, token, new_password}. Dùng cho cả web lẫn app. |
| POST | `/api/v1/auth/verify-email/` | Công khai | Xác thực email bằng token trong link (UUID). Dùng cho cả web lẫn app (deep link). |

### Tài khoản

| Method | Đường dẫn | Dùng cho | Ghi chú |
|---|---|---|---|
| GET / PATCH | `/api/v1/me/` | App + Web |  |
| POST | `/api/v1/me/password/` | App + Web |  |
| GET | `/api/v1/me/sessions/` | App + Web | Danh sách phiên đăng nhập trên app. Web gọi cũng được (để xem/đăng xuất các thiết bị di động); phiên web là cookie của Django nên không nằm trong danh sách này. |
| DELETE | `/api/v1/me/sessions/{session_id}/` | App + Web |  |
| PUT / DELETE | `/api/v1/me/push-token/` | App + Web |  |
| GET | `/api/v1/me/two-factor/` | App + Web |  |
| GET | `/api/v1/bootstrap/` | App + Web |  |

### Khoá

| Method | Đường dẫn | Dùng cho | Ghi chú |
|---|---|---|---|
| GET | `/api/v1/devices/` | App + Web |  |
| POST | `/api/v1/devices/claim/` | App + Web |  |
| GET / PATCH | `/api/v1/devices/{device_id}/` | App + Web |  |
| GET | `/api/v1/devices/{device_id}/live/` | App + Web | Trạng thái trực tiếp - app poll 2-3 giây/lần khi đang mở màn hình điều khiển. |
| POST | `/api/v1/devices/{device_id}/commands/` | App + Web |  |
| GET | `/api/v1/devices/{device_id}/commands/history/` | App + Web |  |
| GET | `/api/v1/commands/{command_id}/` | App + Web | App poll tới khi status = acknowledged / failed / expired. |
| POST | `/api/v1/devices/{device_id}/ble-ticket/` | App + Web |  |
| POST | `/api/v1/devices/{device_id}/nfc-ticket/` | App + Web |  |

### Mã PIN khách

| Method | Đường dẫn | Dùng cho | Ghi chú |
|---|---|---|---|
| GET / POST | `/api/v1/devices/{device_id}/pins/` | App + Web |  |
| DELETE | `/api/v1/pins/{pin_id}/` | App + Web |  |

### Thẻ NFC

| Method | Đường dẫn | Dùng cho | Ghi chú |
|---|---|---|---|
| GET | `/api/v1/cards/` | App + Web |  |
| PATCH / DELETE | `/api/v1/cards/{card_id}/` | App + Web |  |
| PATCH | `/api/v1/cards/{card_id}/devices/{device_id}/` | App + Web | Bật/tắt thẻ trên MỘT khoá. Chủ khoá: thẻ của bất kỳ ai; người khác: chỉ thẻ của mình (cần manage_nfc). |
| POST | `/api/v1/devices/{device_id}/cards/` | App + Web | Đăng ký thẻ bằng UID (app đọc UID qua NFC của điện thoại hoặc người dùng nhập). |

### Đầu đọc NFC

| Method | Đường dẫn | Dùng cho | Ghi chú |
|---|---|---|---|
| GET / POST | `/api/v1/devices/{device_id}/nfc-readers/` | App + Web |  |
| PATCH | `/api/v1/nfc-readers/{reader_id}/` | App + Web |  |

### Khuôn mặt

| Method | Đường dẫn | Dùng cho | Ghi chú |
|---|---|---|---|
| GET / POST | `/api/v1/devices/{device_id}/faces/` | App + Web |  |
| PATCH / DELETE | `/api/v1/faces/{profile_id}/` | App + Web | DELETE: xoá hẳn hồ sơ (dữ liệu sinh trắc). PATCH {"is_active": bool}: bật/tắt hồ sơ. |

### Chia sẻ khoá

| Method | Đường dẫn | Dùng cho | Ghi chú |
|---|---|---|---|
| GET | `/api/v1/permissions/` | App + Web |  |
| GET / POST | `/api/v1/devices/{device_id}/shares/` | App + Web |  |
| GET | `/api/v1/shares/incoming/` | App + Web |  |
| PATCH / DELETE | `/api/v1/shares/{share_id}/` | App + Web |  |
| POST | `/api/v1/shares/{share_id}/leave/` | App + Web |  |

### Lịch sử / nhật ký

| Method | Đường dẫn | Dùng cho | Ghi chú |
|---|---|---|---|
| GET | `/api/v1/history/` | App + Web |  |
| GET | `/api/v1/audit/` | App + Web |  |

### Thông báo

| Method | Đường dẫn | Dùng cho | Ghi chú |
|---|---|---|---|
| GET / DELETE | `/api/v1/notifications/` | App + Web |  |
| POST | `/api/v1/notifications/read/` | App + Web |  |
| DELETE | `/api/v1/notifications/{notification_id}/` | App + Web |  |
| GET | `/api/v1/events/` | App + Web | Poll nhẹ khi app đang mở (khi nền thì dùng push FCM). ?cursor=<iso> (lần đầu bỏ trống). |

## Mã lỗi thường gặp

`UNAUTHENTICATED` 401 (chưa đăng nhập) · `TOKEN_EXPIRED` 401 (app: làm mới token) · `SESSION_REVOKED` 401 ·
`CSRF_FAILED` 403 (web: thiếu/sai `X-CSRFToken`) · `FORBIDDEN` / `OWNER_ONLY` 403 · `NOT_FOUND` 404 ·
`MISSING_FIELD` / `BAD_FIELD` 400 · `RATE_LIMITED` 429 · `ACCOUNT_LOCKED` 423 · `APP_ONLY` 400 (push token trên web).

## Ghi chú về phạm vi

* `me/push-token/` chỉ có nghĩa với app (FCM); web gọi sẽ nhận `APP_ONLY`.
* `me/sessions/` liệt kê phiên **app**; phiên web là cookie Django nên không nằm trong danh sách.
* `auth/logout/` với `"all": true`: app thu hồi mọi phiên app; web đăng xuất cookie hiện tại và thu hồi mọi phiên app.
* Quản lý 2FA (bật/tắt TOTP, Email OTP, Passkey) vẫn thao tác trên trang profile của web (`manage_on_web`).
* Cổng quản trị `/manage-sys/` có phiên riêng (cookie riêng, tách khỏi user) và giữ nguyên dạng trang HTML.
* `/api/v1/device/...` là API cho firmware khoá (xác thực bằng `X-Device-Code` + `X-Device-Secret`), không đổi.
