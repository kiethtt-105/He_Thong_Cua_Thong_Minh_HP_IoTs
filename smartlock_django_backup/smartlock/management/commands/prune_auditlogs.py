# manage_sys/management/commands/prune_auditlogs.py
"""Dọn AuditLog cũ để bảng không phình vô hạn (chạy định kỳ bằng cron / Task Scheduler):

    python manage.py prune_auditlogs                 # info/warning > 180 ngày, critical > 730 ngày
    python manage.py prune_auditlogs --days 90 --critical-days 365
    python manage.py prune_auditlogs --dry-run       # chỉ đếm, không xoá

Log mức critical (gỡ chủ, cấp quyền admin, xoay secret...) giữ lâu hơn. Xoá theo lô để không giữ
transaction dài. Mỗi lần xoá thật tự ghi 1 dòng AuditLog MANAGE_AUDIT_PRUNED.
"""
from datetime import timedelta

from django.core.management.base import BaseCommand, CommandError
from django.utils import timezone

from smartlock.models import AuditLog

BATCH = 5000


class Command(BaseCommand):
    help = 'Xoá AuditLog cũ (info/warning theo --days, critical theo --critical-days).'

    def add_arguments(self, parser):
        parser.add_argument('--days', type=int, default=180, help='Giữ info/warning bao nhiêu ngày (mặc định 180).')
        parser.add_argument('--critical-days', type=int, default=730, help='Giữ critical bao nhiêu ngày (mặc định 730).')
        parser.add_argument('--dry-run', action='store_true', help='Chỉ đếm, không xoá.')

    def handle(self, *args, **opts):
        days, critical_days = opts['days'], opts['critical_days']
        if days < 1 or critical_days < days:
            raise CommandError('--days >= 1 và --critical-days phải >= --days.')
        now = timezone.now()
        plans = [
            ('info/warning', AuditLog.objects.exclude(severity='critical').filter(created_at__lt=now - timedelta(days=days))),
            ('critical', AuditLog.objects.filter(severity='critical', created_at__lt=now - timedelta(days=critical_days))),
        ]
        total = 0
        for label, qs in plans:
            if opts['dry_run']:
                n = qs.count()
            else:
                n = 0
                while True:
                    ids = list(qs.values_list('pk', flat=True)[:BATCH])
                    if not ids:
                        break
                    AuditLog.objects.filter(pk__in=ids).delete()
                    n += len(ids)
            total += n
            self.stdout.write(f'{label}: {n} dòng{" (dry-run)" if opts["dry_run"] else " đã xoá"}')
        if not opts['dry_run'] and total:
            AuditLog.objects.create(action='MANAGE_AUDIT_PRUNED', severity='warning',
                                    metadata={'deleted': total, 'days': days, 'critical_days': critical_days})
        self.stdout.write(self.style.SUCCESS(f'Xong: {total} dòng.'))
