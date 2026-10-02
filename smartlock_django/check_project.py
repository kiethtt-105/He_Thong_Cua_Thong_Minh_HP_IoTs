#!/usr/bin/env python
"""
Kiểm tra nhanh dự án Smartlock. Đặt cạnh manage.py rồi chạy:

    python check_project.py            # kiểm tra cấu hình hiện tại
    python check_project.py --deploy   # thêm `check --deploy` (nên chạy với DEBUG=False)

Thoát mã 1 nếu có lỗi (FAIL), 0 nếu chỉ có OK/WARN -> dùng được trong CI.
"""
import inspect
import os
import sys

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'smartlock_django.settings')

RESULTS = {'OK': 0, 'WARN': 0, 'FAIL': 0}


def report(level, msg):
    RESULTS[level] += 1
    icon = {'OK': '✅', 'WARN': '⚠️ ', 'FAIL': '❌'}[level]
    print(f'{icon} [{level}] {msg}')


def section(title):
    print(f'\n=== {title} ===')


def main():
    deploy = '--deploy' in sys.argv

    # ---------- 1. Môi trường / settings ----------
    section('1. Môi trường & settings')
    for var in ('DJANGO_SECRET_KEY', 'FERNET_KEY'):
        report('OK' if os.environ.get(var) else 'FAIL', f'Biến môi trường {var}')
    try:
        import django
        django.setup()
    except Exception as e:  # noqa: BLE001
        report('FAIL', f'django.setup() lỗi: {e!r}')
        return finish()
    from django.conf import settings
    report('OK', f'Settings nạp được: {settings.SETTINGS_MODULE}')

    if settings.DEBUG:
        report('WARN', 'DEBUG=True (chỉ chấp nhận khi dev/demo)')
    else:
        report('OK', 'DEBUG=False')
    if '*' in settings.ALLOWED_HOSTS and not settings.DEBUG:
        report('WARN', 'ALLOWED_HOSTS có "*" khi DEBUG=False')
    if getattr(settings, 'DEMO_LOGS_ENABLED', False) and not settings.DEBUG:
        report('WARN', 'DEMO_LOGS_ENABLED=True khi DEBUG=False: /demo/system-logs/ đang lộ log hệ thống')
    if not getattr(settings, 'ADMIN_REQUIRE_2FA', False):
        report('WARN', 'ADMIN_REQUIRE_2FA=False: /admin/ chưa bắt 2FA')
    if 'smartlock' not in settings.INSTALLED_APPS and \
            not any(a.startswith('smartlock.') for a in settings.INSTALLED_APPS):
        report('FAIL', 'App "smartlock" chưa có trong INSTALLED_APPS')
    else:
        report('OK', 'App smartlock có trong INSTALLED_APPS')

    # ---------- 2. System check của Django ----------
    section('2. django check')
    from django.core.management import call_command
    from django.core.management.base import SystemCheckError
    try:
        call_command('check', deploy=deploy, verbosity=0)
        report('OK', 'manage.py check' + (' --deploy' if deploy else '') + ' sạch')
    except SystemCheckError as e:
        report('FAIL', f'System check: {e}')
    except Exception as e:  # noqa: BLE001
        report('FAIL', f'check lỗi: {e!r}')

    # ---------- 3. Migrations ----------
    section('3. Migrations')
    try:
        from django.core.management import call_command as cc
        from io import StringIO
        out = StringIO()
        try:
            cc('makemigrations', check=True, dry_run=True, stdout=out, verbosity=1)
            report('OK', 'Model khớp migrations (không có thay đổi chưa tạo)')
        except SystemExit:
            report('FAIL', 'Có thay đổi model chưa có migration -> chạy makemigrations')
        from django.db import connection
        from django.db.migrations.executor import MigrationExecutor
        plan = MigrationExecutor(connection).migration_plan(
            MigrationExecutor(connection).loader.graph.leaf_nodes())
        report('OK' if not plan else 'WARN',
               'DB đã migrate đủ' if not plan else f'DB còn {len(plan)} migration chưa áp dụng (migrate)')
    except Exception as e:  # noqa: BLE001
        report('WARN', f'Không kiểm tra được DB/migrations: {e!r}')

    # ---------- 4. URLconf -> views ----------
    section('4. URL & views')
    from django.urls import get_resolver
    from django.urls.resolvers import URLPattern, URLResolver
    from smartlock import views

    def walk(patterns, prefix=''):
        for p in patterns:
            if isinstance(p, URLResolver):
                yield from walk(p.url_patterns, prefix + str(p.pattern))
            elif isinstance(p, URLPattern):
                yield prefix + str(p.pattern), p

    names = set()
    for route, p in walk(get_resolver().url_patterns):
        if p.name:
            if p.name in names:
                report('WARN', f'Trùng tên URL: {p.name}')
            names.add(p.name)
        if not callable(p.callback):
            report('FAIL', f'Route {route} callback không gọi được')
    report('OK', f'{len(names)} URL có tên, callback đều gọi được')

    import smartlock.urls as su
    missing = [n for n in re_views(su) if not hasattr(views, n)]
    report('FAIL' if missing else 'OK',
           f'View thiếu trong views.py: {missing}' if missing else 'Mọi views.* trong urls.py đều tồn tại')

    # View nhạy cảm không đăng nhập: demo logs + MQTT webhook
    for name in ('public_system_logs', 'public_system_logs_api'):
        src = inspect.getsource(getattr(views, name)) if hasattr(views, name) else ''
        if 'DEMO_LOGS_ENABLED' in src or 'Http404' in src or 'raise' in src:
            report('OK', f'{name}: có cơ chế chặn khi tắt demo')
        else:
            report('WARN', f'{name}: không thấy kiểm tra DEMO_LOGS_ENABLED trong source')
    for name in ('mqtt_auth_webhook', 'mqtt_acl_webhook'):
        src = inspect.getsource(getattr(views, name)) if hasattr(views, name) else ''
        has_secret = any(k in src.lower() for k in ('secret', 'token', 'authorization', 'x-'))
        report('OK' if has_secret else 'WARN',
               f'{name}: ' + ('có kiểm tra secret/header' if has_secret else 'chưa thấy xác thực webhook'))

    # ---------- 5. Admin ----------
    section('5. Django admin')
    from django.apps import apps
    from django.contrib import admin
    from smartlock import admin as _a  # noqa: F401
    sm_models = list(apps.get_app_config('smartlock').get_models())
    unreg = [m.__name__ for m in sm_models if m not in admin.site._registry]
    report('OK' if not unreg else 'WARN',
           'Mọi model smartlock đã đăng ký admin' if not unreg else f'Model chưa đăng ký admin: {unreg}')
    for m in sm_models:
        ma = admin.site._registry.get(m)
        if ma is None:
            continue
        leaked = [f.name for f in m._meta.fields
                  if f.name.endswith(('_hash', '_encrypted')) and f.name not in (ma.exclude or ())]
        if leaked:
            report('FAIL', f'{m.__name__}: cột nhạy cảm chưa bị ẩn trong admin: {leaked}')
    report('OK', 'Đã quét cột _hash/_encrypted trong admin')

    # ---------- 6. Services & signals ----------
    section('6. Services')
    from smartlock import services
    for fn in ('register_signals', 'audit', 'is_admin'):
        report('OK' if hasattr(services, fn) else 'FAIL', f'services.{fn}')

    return finish()


def re_views(urls_module):
    """Tên các view được urls.py tham chiếu (views.xxx)."""
    import re
    src = inspect.getsource(urls_module)
    return sorted(set(re.findall(r'views\.(\w+)', src)))


def finish():
    print(f"\nTổng kết: {RESULTS['OK']} OK, {RESULTS['WARN']} WARN, {RESULTS['FAIL']} FAIL")
    return 1 if RESULTS['FAIL'] else 0


if __name__ == '__main__':
    sys.exit(main())
