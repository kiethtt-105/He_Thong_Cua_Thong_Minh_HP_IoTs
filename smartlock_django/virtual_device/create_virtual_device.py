#!/usr/bin/env python
"""
Tạo thiết bị ảo trong DB, IN thông tin ra màn hình và ghi sẵn VDEV_CODE/VDEV_SECRET vào .env CHUNG của server.
Các bước còn lại (gán chủ, mở/khoá...) admin tự làm trên web.

    python virtual_device/create_virtual_device.py --code SL-DEMO-001 --name "Cửa demo"
    python virtual_device/create_virtual_device.py --code SL-DEMO-001 --rotate   # đã có (vd tạo ở web) -> lấy secret mới
"""
import argparse
import json
import os
import secrets
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))                     # thư mục chứa manage.py
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'smartlock_django.settings')

import django  # noqa: E402
django.setup()

from smartlock.models import Device  # noqa: E402
from smartlock.services import hash_token  # noqa: E402


def write_env(code, secret):
    """Ghi VDEV_CODE/VDEV_SECRET vào .env CHUNG của server (<repo>/.env), giữ nguyên các dòng khác."""
    path = HERE.parent.parent / '.env'
    keep = []
    if path.exists():
        keep = [l for l in path.read_text(encoding='utf-8').splitlines()
                if not l.startswith(('VDEV_CODE=', 'VDEV_SECRET='))]
    path.write_text('\n'.join(keep + [f'VDEV_CODE={code}', f'VDEV_SECRET={secret}']) + '\n', encoding='utf-8')
    return path


def main():
    p = argparse.ArgumentParser()
    p.add_argument('--code', default='SL-DEMO-001')
    p.add_argument('--name', default='Khoá ảo demo')
    p.add_argument('--mac', default='AA:BB:CC:00:00:01')
    p.add_argument('--rotate', action='store_true', help='thiết bị đã tồn tại: đặt secret mới')
    p.add_argument('--no-env', action='store_true', help='không ghi .env')
    p.add_argument('--json', action='store_true')
    a = p.parse_args()
    code, secret = a.code.strip().upper(), secrets.token_hex(16)

    dev = Device.objects.filter(device_code=code).first()
    if dev and not a.rotate:
        sys.exit(f'❌ {code} đã tồn tại. Thêm --rotate để lấy secret mới (secret cũ mất hiệu lực).')
    if dev:
        dev.provisioning_secret_hash = hash_token(secret)
        dev.save(update_fields=['provisioning_secret_hash', 'updated_at'])
        action = 'ĐÃ ĐẶT SECRET MỚI'
    else:
        dev = Device.objects.create(device_code=code, name=a.name, mac_address=a.mac.upper(),
                                    device_mode='simulated', provisioning_secret_hash=hash_token(secret),
                                    firmware_version='1.0.0-sim')
        action = 'ĐÃ TẠO THIẾT BỊ'
    env = None if a.no_env else write_env(code, secret)

    if a.json:
        return print(json.dumps({'device_code': code, 'secret': secret, 'id': str(dev.id), 'status': dev.status}))

    line = '=' * 60
    print(f'\n{line}\n  ✅ {action}\n{line}')
    print(f'  Mã thiết bị : {dev.device_code}')
    print(f'  Tên         : {dev.name}')
    print(f'  Loại        : {dev.get_device_mode_display()}')
    print(f'  MAC         : {dev.mac_address}')
    print(f'  Trạng thái  : {dev.status}  (chờ gán chủ)')
    print(f'  ID          : {dev.id}')
    print(f'  SECRET      : {secret}      <- chỉ hiện 1 lần, hãy lưu lại')
    print(line)
    print(f'  Đã ghi VDEV_CODE/VDEV_SECRET vào: {env}' if env else '  (Không ghi .env)')
    print('\n  Việc còn lại (admin làm trên web):')
    print('   1. Chạy broker + subscriber MQTT, rồi bật khoá ảo (VS Code ▶ Khởi động, hoặc')
    print('      python virtual_device/virtual_lock.py) để khoá gửi tín hiệu về server.')
    print(f'   2. Web /manage-sys/devices/ -> mở "{dev.name}" -> Gán chủ.')
    print('      Chủ phải là tài khoản USER THƯỜNG (tài khoản admin không được làm chủ khoá).')
    print('      Gán chủ chỉ được khi khoá ảo đã kết nối (nhận tín hiệu gần đây).')
    print('   3. Hoặc user tự thêm khoá: Thiết bị -> Thêm khoá bằng mã + secret ở trên.')
    print(f'{line}\n')


if __name__ == '__main__':
    main()
