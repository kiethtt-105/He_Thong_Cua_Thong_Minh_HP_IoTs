"""Phản hồi JSON chuẩn (ok/fail/ApiError) + đọc/kiểm tra dữ liệu vào + phân trang.

Quy ước phản hồi:
    thành công : {"ok": true, ...}
    thất bại   : {"ok": false, "error": {"code": "...", "message": "..."}}
"""
import json

from django.core.paginator import EmptyPage, Paginator
from django.http import JsonResponse
from django.utils import timezone

from smartlock import services


MAX_BODY_BYTES = 256 * 1024


class ApiError(Exception):
    def __init__(self, code, message, status=400, **extra):
        super().__init__(message)
        self.code, self.message, self.status, self.extra = code, message, status, extra


def ok(data=None, status=200, **extra):
    resp = JsonResponse({'ok': True, **(data or {}), **extra}, status=status)
    resp['Cache-Control'] = 'no-store'
    return resp


def fail(code, message, status=400, **extra):
    resp = JsonResponse({'ok': False, 'error': {'code': code, 'message': message, **extra}}, status=status)
    resp['Cache-Control'] = 'no-store'
    return resp


def read_json(request) -> dict:
    if len(request.body) > MAX_BODY_BYTES:
        raise ApiError('PAYLOAD_TOO_LARGE', 'Dữ liệu gửi lên quá lớn.', 413)
    if not request.body:
        return {}
    try:
        data = json.loads(request.body.decode('utf-8'))
    except (ValueError, UnicodeDecodeError):
        raise ApiError('BAD_JSON', 'Nội dung phải là JSON hợp lệ (UTF-8).', 400)
    if not isinstance(data, dict):
        raise ApiError('BAD_JSON', 'Nội dung JSON phải là một object.', 400)
    return data


def s(data, key, max_len=255, required=False) -> str:
    """Lấy chuỗi đã strip + cắt độ dài."""
    val = data.get(key)
    val = '' if val is None else str(val).strip()
    if required and not val:
        raise ApiError('MISSING_FIELD', f'Thiếu trường "{key}".', 400, field=key)
    return val[:max_len]


def uuid_or_404(value):
    u = services.parse_uuid(value)
    if not u:
        raise ApiError('NOT_FOUND', 'Không tìm thấy dữ liệu.', 404)
    return u


def parse_iso(value, field='expires_at'):
    """Chấp nhận ISO-8601 (có/không múi giờ; không múi giờ = giờ máy chủ). Rỗng -> None."""
    if value in (None, ''):
        return None
    from django.utils.dateparse import parse_datetime
    dt = parse_datetime(str(value))
    if dt is None:
        raise ApiError('BAD_DATETIME', f'"{field}" phải theo định dạng ISO-8601 (vd 2026-10-05T18:00:00+07:00).',
                       400, field=field)
    if timezone.is_naive(dt):
        dt = timezone.make_aware(dt)
    return dt


def paginate(request, queryset, serializer, default_size=20, max_size=100) -> dict:
    try:
        page = max(1, int(request.GET.get('page') or 1))
        size = max(1, min(max_size, int(request.GET.get('page_size') or default_size)))
    except ValueError:
        raise ApiError('BAD_PAGINATION', 'page / page_size phải là số nguyên.', 400)
    paginator = Paginator(queryset, size)
    try:
        pg = paginator.page(page)
    except EmptyPage:
        return {'items': [], 'page': page, 'page_size': size, 'total': paginator.count, 'has_next': False}
    return {'items': [serializer(o) for o in pg.object_list], 'page': page, 'page_size': size,
            'total': paginator.count, 'has_next': pg.has_next()}


def iso(dt):
    return dt.isoformat() if dt else None
