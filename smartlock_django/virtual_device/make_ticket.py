#!/usr/bin/env python
"""Sinh vé BLE/NFC cho 1 user (giống services.issue_phone_ticket) để dán vào lệnh `ble` / `nfc` của khoá ảo.

    python virtual_device/make_ticket.py --code SL-DEMO-001 --user-email a@b.com --kind ble
"""
import argparse
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'smartlock_django.settings')
import django  # noqa: E402
django.setup()
from smartlock import services  # noqa: E402
from smartlock.models import Device, User  # noqa: E402

p = argparse.ArgumentParser()
p.add_argument('--code', required=True)
p.add_argument('--user-email', required=True)
p.add_argument('--kind', choices=['ble', 'nfc'], default='ble')
p.add_argument('--ttl', type=int, default=None, help='giây hiệu lực (mặc định theo settings)')
p.add_argument('--expired', action='store_true', help='tạo vé đã hết hạn để test từ chối')
a = p.parse_args()
dev = Device.objects.get(device_code=a.code.upper())
user = User.objects.get(email=a.user_email)
ticket, exp = services.issue_phone_ticket(dev, user, a.kind, ttl=-60 if a.expired else a.ttl)
print(ticket)
