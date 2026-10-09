# manage_sys/management/commands/prune_auditlogs.py
"""Dọn log cũ để bảng smartlock_activitylog không phình vô hạn (chạy định kỳ bằng cron / Task Scheduler):

    python manage.py prune_auditlogs                      # mặc định bên dưới
    python manage.py prune_auditlogs --days 90 --critical-days 365 --status-days 7
    python manage.py prune_auditlogs --dry-run            # chỉ đếm, không xoá

Sau khi gộp bảng, AuditLog/NfcLog/AccessEvent/DeviceStatusLog đều nằm trong ActivityLog (cột `kind`).
Proxy AuditLog chỉ thấy kind='AUDIT' nên lệnh này xoá qua ActivityLog để dọn đủ cả 4 loại:
  AUDIT  info/warning  > --days            (mặc định 180)
  AUDIT  critical      > --critical-days   (mặc định 730)
  NFC                  > --days
  ACCESS               > --access-days     (mặc định 365)
  STATUS               > --status-days     (mặc định 30; subscriber ghi mỗi phút/khoá nên phình nhanh nhất)
Xoá theo lô để không giữ transaction dài. Mỗi lần xoá thật tự ghi 1 dòng AuditLog MANAGE_AUDIT_PRUNED.
"""
from datetime import timedelta

from django.core.management.base import BaseCommand, CommandError
from django.utils import timezone

from smartlock.models import ActivityLog, AuditLog

BATCH = 5000


class Command(BaseCommand):
    help = 'Xoá log cũ trong ActivityLog (AUDIT / NFC / ACCESS / STATUS).'

    def add_arguments(self, parser):
        parser.add_argument('--days', type=int, default=180, help='Giữ AUDIT info/warning và NFC bao nhiêu ngày (180).')
        parser.add_argument('--critical-days', type=int, default=730, help='Giữ AUDIT critical bao nhiêu ngày (730).')
        parser.add_argument('--access-days', type=int, default=365, help='Giữ lịch sử ra vào (ACCESS) bao nhiêu ngày (365).')
        parser.add_argument('--status-days', type=int, default=30, help='Giữ bản tin trạng thái (STATUS) bao nhiêu ngày (30).')
        parser.add_argument('--dry-run', action='store_true', help='Chỉ đếm, không xoá.')

    def handle(self, *args, **opts):
        days, critical_days = opts['days'], opts['critical_days']
        access_days, status_days = opts['access_days'], opts['status_days']
        if min(days, access_days, status_days) < 1 or critical_days < days:
            raise CommandError('Các số ngày phải >= 1 và --critical-days phải >= --days.')
        now = timezone.now()

        def old(kind, d):
            return ActivityLog.objects.filter(kind=kind, created_at__lt=now - timedelta(days=d))

        plans = [
            ('AUDIT info/warning', old('AUDIT', days).exclude(severity='critical')),
            ('AUDIT critical', old('AUDIT', critical_days).filter(severity='critical')),
            ('NFC', old('NFC', days)),
            ('ACCESS', old('ACCESS', access_days)),
            ('STATUS', old('STATUS', status_days)),
        ]
        total, detail = 0, {}
        for label, qs in plans:
            if opts['dry_run']:
                n = qs.count()
            else:
                n = 0
                while True:
                    ids = list(qs.values_list('pk', flat=True)[:BATCH])
                    if not ids:
                        break
                    ActivityLog.objects.filter(pk__in=ids).delete()
                    n += len(ids)
            total += n
            detail[label] = n
            self.stdout.write(f'{label}: {n} dòng{" (dry-run)" if opts["dry_run"] else " đã xoá"}')
        if not opts['dry_run'] and total:
            AuditLog.objects.create(action='MANAGE_AUDIT_PRUNED', severity='warning',
                                    metadata={'deleted': total, 'by_kind': detail, 'days': days,
                                              'critical_days': critical_days, 'access_days': access_days,
                                              'status_days': status_days})
        self.stdout.write(self.style.SUCCESS(f'Xong: {total} dòng.'))
