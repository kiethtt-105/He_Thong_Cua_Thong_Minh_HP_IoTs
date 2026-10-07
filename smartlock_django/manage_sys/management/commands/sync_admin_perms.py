# Đặt vào: smartlock/management/commands/sync_admin_perms.py   (cần có __init__.py ở management/ và commands/)
# Chạy:    python manage.py sync_admin_perms          (thêm --dry-run để chỉ xem)
# Nâng MỌI tài khoản đang là admin (is_admin / is_staff / is_superuser) lên đủ 3 cờ -> quyền cao nhất như /admin.
from django.core.management.base import BaseCommand
from django.db.models import Q
from django.contrib.auth import get_user_model


class Command(BaseCommand):
    help = 'Cấp quyền cao nhất (is_admin + is_staff + is_superuser) cho mọi tài khoản quản trị đang hoạt động.'

    def add_arguments(self, parser):
        parser.add_argument('--dry-run', action='store_true')

    def handle(self, *args, **opts):
        User = get_user_model()
        qs = (User.objects.filter(is_active=True)
              .filter(Q(is_admin=True) | Q(is_staff=True) | Q(is_superuser=True))
              .exclude(is_admin=True, is_staff=True, is_superuser=True))
        for u in qs:
            self.stdout.write(f'{"[dry] " if opts["dry_run"] else ""}nâng quyền: {u.email}')
        if not opts['dry_run']:
            n = qs.update(is_admin=True, is_staff=True, is_superuser=True)
            self.stdout.write(self.style.SUCCESS(f'Đã cập nhật {n} tài khoản.'))