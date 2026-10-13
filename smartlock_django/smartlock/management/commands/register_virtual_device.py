# smartlock/management/commands/register_device.py   (thay cho register_virtual_device.py)
"""
Đăng ký 1 thiết bị (ảo HOẶC thật) vào DB ở trạng thái 'provisioning' (chưa có chủ) từ chính file config.json
của thiết bị, rồi user claim bằng Device code + Secret ở /devices/claim/. Chỉ dùng khi DEV (DEBUG=True).

    python manage.py register_device ../device/config.json                    # giả lập (mặc định)
    python manage.py register_device ../device/config.json --mode physical     # board thật (Raspberry Pi...)
    python manage.py register_device --list

Đọc: device_code, secret, hardware.mac/firmware. Nếu có state/config.json cạnh file đó (MAC do máy giả lập tự sinh)
thì gộp vào. Chỉ lưu HASH của secret vào DB, không lưu secret thô.
Chạy lại được: khoá đã có chủ -> CHỈ cập nhật MAC/firmware (không đụng owner/status/secret/mode).
"""
import json
from pathlib import Path

from django.conf import settings
from django.core.management.base import BaseCommand, CommandError

from smartlock import services
from smartlock.api.device import MAC_RE
from smartlock.models import Device


def _load(path: Path) -> dict:
    try:
        return json.loads(path.read_text(encoding='utf-8'))
    except (OSError, ValueError) as e:
        raise CommandError(f'Không đọc được {path}: {e}')


def _merge(base: dict, over: dict) -> dict:
    for k, v in over.items():
        if isinstance(v, dict) and isinstance(base.get(k), dict):
            _merge(base[k], v)
        else:
            base[k] = v
    return base


class Command(BaseCommand):
    help = 'Đăng ký thiết bị ảo/thật từ device/config.json vào DB (provisioning, chưa có chủ).'

    def add_arguments(self, parser):
        parser.add_argument('config', nargs='?', help='Đường dẫn device/config.json')
        parser.add_argument('--mode', choices=('simulated', 'physical'), default='simulated',
                            help='simulated = máy giả lập (mặc định) | physical = board thật')
        parser.add_argument('--name', help='Tên hiển thị (mặc định = device_code)')
        parser.add_argument('--list', action='store_true', help='Liệt kê thiết bị chưa claim / đã claim.')

    def handle(self, *args, **opts):
        if opts['list']:
            for d in Device.objects.select_related('owner').order_by('created_at'):
                self.stdout.write(f'{d.device_code}  {d.device_mode:9} {d.status:12} '
                                  f'owner={d.owner.email if d.owner_id else "-"}  {d.name}')
            return
        if not settings.DEBUG:
            raise CommandError('register_device chỉ chạy khi DEBUG=True. Production: tạo thiết bị ở trang admin.')
        if not opts['config']:
            raise CommandError('Cần đường dẫn device/config.json (hoặc --list).')

        path = Path(opts['config']).resolve()
        cfg = _load(path)
        state_cfg = path.parent / 'state' / 'config.json'
        if state_cfg.exists():
            _merge(cfg, _load(state_cfg))
        code = str(cfg.get('device_code') or '').strip().upper()
        secret = str(cfg.get('secret') or '')
        if not code or not secret:
            raise CommandError('config.json thiếu device_code hoặc secret.')
        hwc = cfg.get('hardware') or {}
        mac = str(hwc.get('mac') or '').upper()
        mac = mac if MAC_RE.match(mac) else None
        fw = str(hwc.get('firmware') or '')[:30] or None

        device = Device.objects.filter(device_code=code).first()
        if device is None:
            Device.objects.create(
                device_code=code, name=opts['name'] or code, status='provisioning', owner=None,   # chk_devices_owner_vs_status
                provisioning_secret_hash=services.hash_token(secret), device_mode=opts['mode'],
                mac_address=mac, firmware_version=fw)
            self.stdout.write(self.style.SUCCESS(
                f'Đã đăng ký {code} ({opts["mode"]}, provisioning). Vào /devices/claim/ nhập code + secret trong config.json.'))
            return

        fields = {'mac_address': mac, 'firmware_version': fw}
        if not device.owner_id:                                  # chưa có chủ: nạp lại identity mới
            fields.update(provisioning_secret_hash=services.hash_token(secret), device_mode=opts['mode'])
        for k, v in fields.items():
            setattr(device, k, v)
        device.save(update_fields=list(fields) + ['updated_at'])
        self.stdout.write(self.style.WARNING(
            f'{code} đã tồn tại: ' + (f'đã có chủ ({device.owner.email}) -> chỉ cập nhật MAC/firmware.'
                                      if device.owner_id else 'cập nhật secret/MAC/firmware.')))