# manage_sys/middleware.py
"""
Tách phiên đăng nhập (session) của trang quản trị khỏi trang người dùng.

- Trên đường dẫn quản trị (MANAGE_SYS_URL_PREFIX) chỉ đọc/ghi cookie riêng
  `manage_sys_sessionid`, cookie này bị giới hạn path = prefix quản trị.
- Cookie `sessionid` của user thường bị bỏ qua hoàn toàn trên đường dẫn quản trị,
  và cookie quản trị không bao giờ được trình duyệt gửi tới các trang user.

=> Đăng nhập admin KHÔNG làm user đăng nhập, và ngược lại. Đăng xuất bên nào
   cũng không ảnh hưởng bên kia.

Phải đặt TRƯỚC 'django.contrib.sessions.middleware.SessionMiddleware'.
"""
from django.conf import settings


class ManageSysSessionCookieMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response
        self.prefix = getattr(settings, 'MANAGE_SYS_URL_PREFIX', '/manage-sys/')
        self.cookie_name = getattr(settings, 'MANAGE_SYS_SESSION_COOKIE_NAME', 'manage_sys_sessionid')

    def __call__(self, request):
        if not request.path_info.startswith(self.prefix):
            return self.get_response(request)

        default = settings.SESSION_COOKIE_NAME

        # Request: chỉ cho SessionMiddleware thấy cookie của admin (nếu có)
        admin_sid = request.COOKIES.pop(self.cookie_name, None)
        request.COOKIES.pop(default, None)
        if admin_sid:
            request.COOKIES[default] = admin_sid

        response = self.get_response(request)

        # Response: đổi tên cookie phiên -> cookie của admin, giới hạn path
        morsel = response.cookies.get(default)
        if morsel is not None:
            del response.cookies[default]
            morsel.set(self.cookie_name, morsel.value, morsel.coded_value)
            morsel['path'] = self.prefix
            response.cookies[self.cookie_name] = morsel
        return response
