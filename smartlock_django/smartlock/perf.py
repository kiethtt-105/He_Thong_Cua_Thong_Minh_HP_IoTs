# smartlock/perf.py
"""Đo thời gian mỗi request: tổng, thời gian trong DB, số truy vấn. Bật bằng PERF_TIMING=1 (xem settings.py).

Cách đọc kết quả (DevTools > Network > chọn request > Timing > Server Timing):
  * app  = tổng thời gian server xử lý
  * db   = tổng thời gian các câu SQL (chưa gồm thời gian MỞ KẾT NỐI)
  => app - db lớn: mất ở mở kết nối DB / xử lý Python / gửi mail; db lớn + nhiều truy vấn: vòng mạng tới DB ở xa.
"""
import logging
import time
from contextlib import ExitStack

from django.db import connections

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