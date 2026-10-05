"""GET /announcements/ - thông báo hệ thống đang bật (quản trị đăng ở manage_sys).

Trước đây app chỉ nhận 5 thông báo mới nhất lồng trong /bootstrap/; endpoint này cho xem đầy đủ + phân trang.
"""
from smartlock.api.common import api, ok, paginate
from smartlock.models import Announcement

from ..serializers import announcement_json


@api('GET', auth='any')
def announcements(request):
    qs = Announcement.objects.filter(is_active=True).order_by('-created_at')
    return ok(paginate(request, qs, announcement_json))
