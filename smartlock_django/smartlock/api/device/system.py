"""Route hệ thống công khai - /api/system/health/, /config/"""
from django.db import connection
from django.utils import timezone

from smartlock import services
from smartlock.api.common import api, fail, iso, ok


# ======================================================================
# views.py - GET /system/health/ và GET /system/config/ - công khai, chỉ đọc.
# ======================================================================

@api('GET', auth=False)
def health(request):
    """200 khi web + DB sống, 503 khi DB lỗi. Dùng cho load balancer / uptime monitor."""
    try:
        with connection.cursor() as cur:
            cur.execute('SELECT 1')
    except Exception:
        return fail('DB_UNAVAILABLE', 'Cơ sở dữ liệu chưa sẵn sàng.', 503)
    return ok({'status': 'up', 'server_time': iso(timezone.now())})


@api('GET', auth=False)
def config(request):
    """Cấu hình công khai cho app trước khi đăng nhập (ẩn/hiện nút Đăng ký...)."""
    cfg = services.system_settings()
    return ok({'server_time': iso(timezone.now()),
               'registration_enabled': bool(cfg.registration_enabled)})
