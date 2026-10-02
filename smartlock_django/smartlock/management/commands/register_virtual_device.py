# smartlock/management/commands/register_virtual_device.py
"""
Đăng ký thiết bị ảo (do virtual_device.py tạo) vào DB ở trạng thái 'provisioning' (chưa có chủ),
giống 1 khoá mới xuất xưởng. Sau đó user claim bằng Device code + Secret (trang /devices/claim/).

    python manage.py register_virtual_device virtual_device/devices/DEV-XXXX/identity.json
    python manage.py register_virtual_device --all          # đăng ký mọi thiết bị trong virtual_device/devices
    python manage.py register_virtual_device --list

Chạy lại được: nếu khoá đã có chủ thì CHỈ cập nhật thông tin phần cứng (không đụng owner/status).
Chỉ chạy khi DEBUG=True (file identity chứa secret dạng thô).
"""
import json
from pathlib import Path

from django.conf import settings
from django.core.management.base import BaseCommand, CommandError

from smartlock.models import Device

DEFAULT_DIR = Path(settings.BASE_DIR) / 'virtual_device' / 'devices'


class Command(BaseCommand):
    help = 'Đăng ký thiết bị ảo vào DB (provisioning, chưa có chủ) để claim như khoá thật.'

    def add_arguments(self, parser):
        parser.add_argument('identity', nargs='?', help='Đường dẫn identity.json của thiết bị ảo.')
        parser.add_argument('--all', action='store_true', help='Đăng ký mọi thiết bị trong virtual_device/devices.')
        parser.add_argument('--list', action='store_true', help='Liệt kê thiết bị đã đăng ký (mode=simulated).')

    def handle(self, *args, **opts):
        if opts['list']:
            for d in Device.objects.filter(device_mode='simulated').order_by('created_at'):
                self.stdout.write(f'{d.device_code}  {d.status:12} owner={d.owner.email if d.owner_id else "-"}  {d.name}')
            return
        if not settings.DEBUG:
            raise CommandError('register_virtual_device chỉ chạy khi DEBUG=True.')
        if opts['all']:
            paths = sorted(DEFAULT_DIR.glob('*/identity.json'))
        elif opts['identity']:
            paths = [Path(opts['identity'])]
        else:
            raise CommandError('Cần đường dẫn identity.json hoặc --all.')
        if not paths:
            raise CommandError(f'Không có identity.json nào (thư mục {DEFAULT_DIR}).')
        for p in paths:
            self._register(p)

    def _register(self, path):
        try:
            ident = json.loads(Path(path).read_text(encoding='utf-8'))
            code, secret_hash = ident['device_code'].strip().upper(), ident['secret_hash']
        except (OSError, ValueError, KeyError) as e:
            raise CommandError(f'identity.json không hợp lệ ({path}): {e}')
        hw = {'provisioning_secret_hash': secret_hash, 'mac_address': (ident.get('mac') or '').upper() or None,
              'firmware_version': (ident.get('firmware') or '')[:30] or None,
              'device_mode': 'simulated'}
        device = Device.objects.filter(device_code=code).first()
        if device is None:
            Device.objects.create(device_code=code, name=ident.get('name') or code, location=ident.get('location'),
                                  status='provisioning', owner=None, **hw)   # đúng chk_devices_owner_vs_status
            self.stdout.write(self.style.SUCCESS(
                f'Đã đăng ký {code} (provisioning). Chạy thiết bị ảo rồi claim bằng secret trong device_info.txt.'))
            return
        for k, v in hw.items():
            setattr(device, k, v)
        device.save(update_fields=list(hw) + ['updated_at'])
        state = f'owner={device.owner.email}' if device.owner_id else f'status={device.status}'
        self.stdout.write(self.style.WARNING(f'{code} đã tồn tại ({state}): chỉ cập nhật secret/MAC/firmware.'))
