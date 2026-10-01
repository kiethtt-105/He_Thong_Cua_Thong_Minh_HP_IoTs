# smartlock/api/common.py
"""
Nền tảng dùng chung của REST API cho app iOS/Android:
  - Định dạng phản hồi thống nhất:  thành công -> {"ok": true, ...}   lỗi -> {"ok": false, "code", "message", ...}
  - api_exception_handler (đã khai báo trong settings.REST_FRAMEWORK)
  - StandardPagination (đã khai báo trong settings.REST_FRAMEWORK)
  - ApiError, PublicAPIView (view không cần đăng nhập + chặn IP đen), kiểm tra phiên bản app tối thiểu.
"""
import logging

from django.conf import settings
from django.core.exceptions import PermissionDenied as DjangoPermissionDenied
from django.http import Http404
from rest_framework import exceptions, status
from rest_framework.pagination import PageNumberPagination
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework.views import APIView, exception_handler as drf_exception_handler

from smartlock import services

logger = logging.getLogger('smartlock.api')


# ---------------------------------------------------------------- phản hồi
def ok(data=None, status_code=status.HTTP_200_OK, **extra):
    """Phản hồi thành công. `data` (nếu có) nằm ở khoá "data"; các tham số khác nằm ngang hàng."""
    body = {'ok': True}
    if data is not None:
        body['data'] = data
    body.update(extra)
    return Response(body, status=status_code)


class ApiError(exceptions.APIException):
    """Lỗi nghiệp vụ có mã máy đọc được (app dùng `code` để hiển thị/điều hướng)."""
    status_code = status.HTTP_400_BAD_REQUEST
    default_detail = 'Yêu cầu không hợp lệ.'
    default_code = 'bad_request'

    def __init__(self, message=None, code=None, status_code=None, **extra):
        super().__init__(detail=message or self.default_detail, code=code or self.default_code)
        if status_code:
            self.status_code = status_code
        self.extra = extra


def _first_message(detail):
    """Lấy 1 câu thông báo đại diện từ cấu trúc detail (dict/list lồng nhau) của DRF."""
    if isinstance(detail, dict):
        for value in detail.values():
            msg = _first_message(value)
            if msg:
                return msg
        return ''
    if isinstance(detail, (list, tuple)):
        for value in detail:
            msg = _first_message(value)
            if msg:
                return msg
        return ''
    return str(detail)


def api_exception_handler(exc, context):
    if isinstance(exc, Http404):
        exc = exceptions.NotFound()
    elif isinstance(exc, DjangoPermissionDenied):
        exc = exceptions.PermissionDenied()

    response = drf_exception_handler(exc, context)
    if response is None:   # lỗi không lường trước -> không lộ chi tiết nội bộ cho client
        logger.exception('API: lỗi không xử lý', exc_info=exc)
        return Response({'ok': False, 'code': 'server_error', 'message': 'Lỗi hệ thống. Vui lòng thử lại sau.'},
                        status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    body = {'ok': False}
    if isinstance(exc, exceptions.ValidationError):
        body.update(code='validation_error', message=_first_message(exc.detail) or 'Dữ liệu không hợp lệ.',
                    errors=exc.detail)
    elif isinstance(exc, exceptions.Throttled):
        body.update(code='throttled', message='Bạn thao tác quá nhanh. Vui lòng thử lại sau.',
                    retry_after=exc.wait)
    elif isinstance(exc, (exceptions.NotAuthenticated, exceptions.AuthenticationFailed)):
        code = getattr(exc.detail, 'code', None) or 'unauthorized'
        body.update(code='unauthorized' if code == 'authentication_failed' else code,
                    message=_first_message(exc.detail) or 'Chưa đăng nhập hoặc phiên đã hết hạn.')
    elif isinstance(exc, exceptions.PermissionDenied):
        body.update(code='forbidden', message=_first_message(exc.detail) or 'Bạn không có quyền thực hiện thao tác này.')
    elif isinstance(exc, exceptions.NotFound):
        body.update(code='not_found', message='Không tìm thấy dữ liệu yêu cầu.')
    else:
        code = getattr(exc.detail, 'code', None) if hasattr(exc, 'detail') else None
        body.update(code=code or 'error', message=_first_message(getattr(exc, 'detail', '')) or 'Yêu cầu không hợp lệ.')
    body.update(getattr(exc, 'extra', {}) or {})
    response.data = body
    return response


# ---------------------------------------------------------------- phân trang
class StandardPagination(PageNumberPagination):
    page_size = 20
    page_size_query_param = 'page_size'
    max_page_size = 100

    def get_paginated_response(self, data):
        return Response({
            'ok': True,
            'count': self.page.paginator.count,
            'page': self.page.number,
            'next': self.get_next_link(),
            'previous': self.get_previous_link(),
            'results': data,
        })


# ---------------------------------------------------------------- view không cần đăng nhập
class PublicAPIView(APIView):
    """Không dùng session/Bearer (nên không dính CSRF), nhưng vẫn chặn IP trong danh sách đen."""
    authentication_classes = []
    permission_classes = [AllowAny]

    def initial(self, request, *args, **kwargs):
        if services.ip_blacklisted(services.client_ip(request)):
            raise ApiError('Địa chỉ IP của bạn đã bị chặn.', code='ip_blocked', status_code=403)
        super().initial(request, *args, **kwargs)


# ---------------------------------------------------------------- phiên bản app
def _version_tuple(value):
    parts = []
    for p in str(value or '').split('.'):
        digits = ''.join(ch for ch in p if ch.isdigit())
        parts.append(int(digits) if digits else 0)
    return tuple(parts) or (0,)


def check_app_version(request):
    """Nếu app gửi header X-App-Version thấp hơn MOBILE_MIN_APP_VERSION -> 426 (app hiện màn hình bắt cập nhật)."""
    current = request.META.get('HTTP_X_APP_VERSION', '').strip()
    minimum = getattr(settings, 'MOBILE_MIN_APP_VERSION', '')
    if current and minimum and _version_tuple(current) < _version_tuple(minimum):
        raise ApiError('Phiên bản ứng dụng đã cũ. Vui lòng cập nhật để tiếp tục.', code='upgrade_required',
                       status_code=426, min_app_version=minimum,
                       latest_app_version=getattr(settings, 'MOBILE_LATEST_APP_VERSION', minimum))
