# smartlock/management/commands/mark_offline_devices.py
"""
Chạy định kỳ (cron mỗi 1 phút, vd. qua crontab hoặc celery-beat):

    * * * * * /path/venv/bin/python /path/project/manage.py mark_offline_devices

MQTT chỉ báo "thiết bị vừa gửi status lúc nào" (last_seen_at); nó KHÔNG tự báo khi
thiết bị mất kết nối đột ngột (rớt mạng, mất điện...) trừ khi dùng MQTT Last Will
(khuyến nghị cấu hình thêm ở firmware). Command này là lớp bảo hiểm thứ 2: nếu
device.status='online' mà last_seen_at quá cũ -> coi như mất kết nối, set 'offline'.
"""
from django.core.management.base import BaseCommand
from django.utils import timezone
from datetime import timedelta

from smartlock.models import Device

OFFLINE_AFTER_SECONDS = 180  # không nhận status > 3 phút -> coi là offline


class Command(BaseCommand):
    help = 'Chuyển các thiết bị online nhưng lâu không gửi status về trạng thái offline.'

    def handle(self, *args, **options):
        cutoff = timezone.now() - timedelta(seconds=OFFLINE_AFTER_SECONDS)
        n = Device.objects.filter(status='online', last_seen_at__lt=cutoff).update(status='offline')
        if n:
            self.stdout.write(self.style.WARNING(f'Đã chuyển {n} thiết bị sang offline (mất kết nối).'))