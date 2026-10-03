# manage_sys/middleware.py
"""
Tách phiên đăng nhập (session) của trang quản trị khỏi trang người dùng.

- Trên đường dẫn quản trị (MANAGE_SYS_URL_PREFIX) chỉ đọc/ghi cookie riêng
  `manage_sys_sessionid`, cookie này bị giới hạn path = prefix quản trị.
- Cookie `sessionid` của user thường bị bỏ qua hoàn toàn trên đường dẫn quản trị,
  và cookie quản trị không bao giờ được trình duyệt gửi tới các trang user.
- Cookie quản trị luôn HttpOnly + SameSite=Strict (chống CSRF/lộ qua script), và Secure khi chạy HTTPS
  (mặc định Secure = not DEBUG; ghi đè bằng settings.MANAGE_SYS_COOKIE_SECURE).

=> Đăng nhập admin KHÔNG làm user đăng nhập, và ngược lại. Đăng xuất bên nào
   cũng không ảnh hưởng bên kia.

Phải đặt TRƯỚC 'django.contrib.sessions.middleware.SessionMiddleware'.
"""
import logging
import time
from contextlib import ExitStack

from django.conf import settings
from django.db import connections


class ManageSysSessionCookieMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response
        self.prefix = getattr(settings, 'MANAGE_SYS_URL_PREFIX', '/manage-sys/')
        self.cookie_name = getattr(settings, 'MANAGE_SYS_SESSION_COOKIE_NAME', 'manage_sys_sessionid')
        self.secure = bool(getattr(settings, 'MANAGE_SYS_COOKIE_SECURE',
                                   getattr(settings, 'SECURE_COOKIES', not settings.DEBUG)))

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

        # Response: đổi tên cookie phiên -> cookie của admin, giới hạn path + cờ bảo mật
        morsel = response.cookies.get(default)
        if morsel is not None:
            del response.cookies[default]
            morsel.set(self.cookie_name, morsel.value, morsel.coded_value)
            morsel['path'] = self.prefix
            morsel['httponly'] = True
            morsel['samesite'] = 'Strict'
            if self.secure:
                morsel['secure'] = True
            response.cookies[self.cookie_name] = morsel
        return response


# =====================================================================================================
# ServerTimingMiddleware (trước đây là smartlock/perf.py)
# =====================================================================================================
# Đo thời gian mỗi request: tổng, thời gian trong DB, số truy vấn. Bật bằng PERF_TIMING=1 (xem settings.py).
#
# Cách đọc kết quả (DevTools > Network > chọn request > Timing > Server Timing):
#   * app  = tổng thời gian server xử lý
#   * db   = tổng thời gian các câu SQL (chưa gồm thời gian MỞ KẾT NỐI)
#   => app - db lớn: mất ở mở kết nối DB / xử lý Python / gửi mail; db lớn + nhiều truy vấn: vòng mạng tới DB ở xa.
# =====================================================================================================
logger = logging.getLogger('smartlock.perf')
SLOW_MS = 500


class ServerTimingMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        stats = {'n': 0, 'ms': 0.0}

        def wrapper(execute, sql, params, many, context):
            t = time.perf_counter()
            try:
                return execute(sql, params, many, context)
            finally:
                stats['n'] += 1
                stats['ms'] += (time.perf_counter() - t) * 1000

        start = time.perf_counter()
        with ExitStack() as stack:
            for conn in connections.all():
                stack.enter_context(conn.execute_wrapper(wrapper))
            response = self.get_response(request)
        total = (time.perf_counter() - start) * 1000
        response['Server-Timing'] = f'app;dur={total:.0f}, db;dur={stats["ms"]:.0f};desc="{stats["n"]} queries"'
        if total >= SLOW_MS:
            logger.warning('SLOW %s %s %.0fms (db %.0fms / %d queries)', request.method, request.path,
                           total, stats['ms'], stats['n'])
        return response