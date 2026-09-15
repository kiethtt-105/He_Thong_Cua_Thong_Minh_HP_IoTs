# Smart Lock IoT — Đăng ký / Đăng nhập (Django + Vercel)

Flow: **Đăng ký → nhận OTP qua email → verify OTP → tạo user thật → đăng nhập.**

Bảng `users` và `pending_registrations` đã có sẵn trên Supabase (từ file SQL bạn chạy),
Django chỉ map vào (`managed=False`) chứ không tự tạo/sửa 2 bảng này.

## Cấu trúc repo (đúng như deploy lên Vercel cần)

```
api/
  index.py           <- entrypoint Vercel Python runtime gọi vào
smart_lock/          <- Django project settings/urls/wsgi
accounts/
  models.py           User, PendingRegistration (map bảng có sẵn)
  forms.py             RegisterForm, OTPForm, LoginForm
  views.py             register / verify_otp / login / logout / dashboard
  utils.py             sinh OTP (CSPRNG), hash SHA-256, gửi email
  templates/accounts/  UI thuần Django template
manage.py
requirements.txt
vercel.json          <- route toàn bộ request về api/index.py
.env.example
.gitignore
```

## Chạy LOCAL trước khi deploy

```bash
python -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate
pip install -r requirements.txt

cp .env.example .env
# điền DB_HOST / DB_USER / DB_PASSWORD lấy từ Supabase Dashboard
# > Project Settings > Database > Connection Pooling (cổng 6543)

python manage.py makemigrations accounts
python manage.py migrate     # chỉ tạo bảng django_session, KHÔNG đụng users/pending_registrations
python manage.py collectstatic --noinput
python manage.py runserver
```

Mở `http://127.0.0.1:8000/register/`. Lúc dev, OTP in ra terminal (console email backend).

## Deploy lên Vercel

1. Push repo này lên GitHub, import project vào Vercel.
2. Ở Vercel Dashboard > Settings > Environment Variables, khai báo (KHÔNG
   commit `.env` lên git — Vercel không đọc file `.env`, phải set trực tiếp
   trên dashboard):
   - `DJANGO_SECRET_KEY`
   - `DEBUG=False`
   - `DB_NAME`, `DB_USER`, `DB_PASSWORD`, `DB_HOST`, `DB_PORT=6543` (connection pooler Supabase)
   - `EMAIL_BACKEND`, `EMAIL_HOST`, `EMAIL_PORT`, `EMAIL_USE_TLS`, `EMAIL_HOST_USER`, `EMAIL_HOST_PASSWORD`, `DEFAULT_FROM_EMAIL` (SMTP thật, ví dụ Gmail App Password hoặc Resend/SendGrid — console backend không hoạt động trên serverless vì không ai đọc log đó)
3. Trước khi deploy (hoặc trong 1 bước build riêng), chạy
   `python manage.py collectstatic --noinput` để tạo thư mục `staticfiles/`
   — WhiteNoise sẽ serve static từ đó vì Vercel không có disk ghi được lúc
   runtime.
4. Deploy. Vercel build `api/index.py` bằng `@vercel/python`, mọi request
   được `vercel.json` route hết về đó → Django tự xử lý routing nội bộ.

## Lưu ý quan trọng cho môi trường serverless

- **Bắt buộc dùng Supabase Connection Pooler (cổng 6543, Transaction mode)**,
  không dùng cổng 5432 trực tiếp — mỗi request trên Vercel có thể là 1
  instance riêng, dùng cổng thường sẽ nhanh chóng hết connection slot của
  Postgres. `CONN_MAX_AGE=0` đã set sẵn trong `settings.py`.
- Email OTP: `console` backend chỉ dùng được lúc `runserver` local. Trên
  Vercel phải cấu hình SMTP thật (Gmail App Password, Resend, SendGrid...)
  nếu không OTP sẽ "gửi" vào log mà không ai nhận được.
- Vercel serverless function có giới hạn thời gian chạy (khoảng 10s ở gói
  Hobby) — đủ cho luồng đăng ký/đăng nhập hiện tại, nhưng nếu sau này thêm
  tác vụ nặng (gửi email hàng loạt, xử lý ảnh...) nên tách ra background job
  riêng thay vì chạy trong request.

## Việc còn lại (chưa làm trong lần này)

- Chưa dùng bảng `sessions` riêng (refresh token) trong SQL — đang dùng
  session mặc định của Django (cookie-based) vì FE là server-render, không
  cần JWT. Nếu sau này làm thêm app mobile gọi API riêng thì mới cần bảng đó.
- Chưa làm TOTP/HOTP/FIDO2/push-auth — mới chỉ Email OTP lúc đăng ký.
- Chưa có trang quên mật khẩu, đổi mật khẩu.
