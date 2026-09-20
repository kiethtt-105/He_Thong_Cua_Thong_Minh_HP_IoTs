# Cài đặt trang quản trị Manage Sys

Giải nén file zip vào thư mục gốc dự án (`smartlock_django\`, cạnh `manage.py`).
Hai file `smartlock/views.py` và `smartlock/urls.py` sẽ bị ghi đè (đã bỏ code admin + chặn admin đăng nhập cổng user).

## 1. `smartlock_django/settings.py`

```python
INSTALLED_APPS = [
    # ...
    'manage_sys',
]

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    # (whitenoise nếu có)
    'manage_sys.middleware.ManageSysSessionCookieMiddleware',   # <-- ĐẶT NGAY TRƯỚC SessionMiddleware
    'django.contrib.sessions.middleware.SessionMiddleware',
    # ... giữ nguyên phần còn lại
]

# Đổi tên đường dẫn quản trị ở đây (chỉ cần sửa 1 chỗ). Phải bắt đầu và kết thúc bằng "/".
MANAGE_SYS_URL_PREFIX = '/manage-sys/'
MANAGE_SYS_SESSION_SECONDS = 2 * 60 * 60        # phiên admin 2 giờ
# MANAGE_SYS_SESSION_COOKIE_NAME = 'manage_sys_sessionid'   # tùy chọn
```

## 2. `smartlock_django/urls.py`

```python
from django.conf import settings
from django.urls import include, path

urlpatterns = [
    path(settings.MANAGE_SYS_URL_PREFIX.strip('/') + '/', include('manage_sys.urls')),
    path('', include('smartlock.urls')),
    # Nên xóa/đổi dòng path('admin/', admin.site.urls) nếu bạn không muốn lộ /admin
]
```

## 3. Dọn dẹp & tạo tài khoản

- Xóa thư mục cũ `templates\admin-sys\` (không còn dùng).
- Tạo admin đầu tiên: `python manage.py createsuperuser`  (không cần migrate, app này không có model).
- Chạy test: `python manage.py test manage_sys`
- Đăng nhập tại: `http://127.0.0.1:8000/manage-sys/login/`
