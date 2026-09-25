# smartlock/management/commands/seed_test_devices.py
#
#     python manage.py seed_test_devices --owner=kieth02@admin.vn
#
# Tạo ra:
#   - 2 Device (device_mode='simulated', status='online'), device_code cố định
#     DEV-SIM-001 / DEV-SIM-002
#   - 1 NfcReader (reader_mode='simulated') cho mỗi device
#   - 1 AccessCard THẬT hợp lệ, gắn CardDeviceAccess với DEV-SIM-001, UID in ra màn hình để test
#   - 1 DoorPinCode còn hạn 60 phút cho DEV-SIM-001, PIN in ra màn hình để test pin_entry
#
# Chạy đc: script kiểm tra device_code đã tồn tại thì cập nhật lạithay vì tạo trùng (get_or_create theo device_code).

import hashlib
import secrets

from django.contrib.auth import get_user_model
from django.core.management.base import BaseCommand, CommandError
from django.utils import timezone
from datetime import timedelta

from smartlock.models import AccessCard, CardDeviceAccess, Device, NfcReader, NfcReaderConfig
from smartlock import access_control

User = get_user_model()


def _hash(value: str) -> str:
    return hashlib.sha256(str(value).encode()).hexdigest()


class Command(BaseCommand):
    help = 'Tạo 2 thiết bị giả lập + thẻ RFID + PIN hợp lệ để test hệ thống end-to-end.'

    def add_arguments(self, parser):
        parser.add_argument('--owner', type=str, default='',
                             help='Email của user sẽ làm owner cho 2 thiết bị test.')

    def handle(self, *args, **options):
        owner = self._resolve_owner(options['owner'])
        self.stdout.write(self.style.SUCCESS(f'Dùng owner: {owner.email}'))

        provisioning_secret = 'test-secret-please-change'
        devices = []
        for i, code in enumerate(['DEV-SIM-001', 'DEV-SIM-002'], start=1):
            device, created = Device.objects.update_or_create(
                device_code=code,
                defaults={
                    'provisioning_secret_hash': _hash(provisioning_secret),
                    'device_mode': 'simulated',
                    'owner': owner,
                    'name': f'Khoá cửa giả lập #{i}',
                    'status': 'online',
                    'battery_level': 90,
                    'location': f'Phòng test {i}',
                    'last_seen_at': timezone.now(),
                },
            )
            reader, _ = NfcReader.objects.update_or_create(
                device=device, reader_mode='simulated',
                defaults={'name': f'Đầu đọc giả lập {i}', 'is_active': True, 'last_seen_at': timezone.now()},
            )
            NfcReaderConfig.objects.get_or_create(reader=reader)
            devices.append(device)
            self.stdout.write(f'  {"Tạo mới" if created else "Đã cập nhật"} device_code={code} '
                               f'(secret dùng cho username/password MQTT: "{code}" / "{provisioning_secret}")')

        # ---- Thẻ RFID hợp lệ, gắn với DEV-SIM-001 ----
        raw_uid = secrets.token_hex(4).upper()  # vd. "A1B2C3D4"
        card, _ = AccessCard.objects.update_or_create(
            card_uid_hash=_hash(raw_uid),
            defaults={'user': owner, 'name': 'Thẻ test tự động', 'is_active': True},
        )
        CardDeviceAccess.objects.get_or_create(access_card=card, device=devices[0])

        # ---- PIN hợp lệ 60 phút, gắn với DEV-SIM-001 ----
        plain_pin = ''.join(secrets.choice('0123456789') for _ in range(6))
        pin = access_control.issue_door_pin(
            device=devices[0], created_by=owner, plain_pin=plain_pin,
            ttl_minutes=60, label='PIN test tự động', max_uses=5,
        )

        self.stdout.write(self.style.SUCCESS('\n===== DỮ LIỆU TEST - DÙNG NGAY TRONG mosquitto_pub ====='))
        self.stdout.write(f'  UID thẻ RFID hợp lệ (DEV-SIM-001): {raw_uid}')
        self.stdout.write(f'  Mã PIN hợp lệ (DEV-SIM-001, hết hạn sau 60 phút, tối đa 5 lần): {plain_pin}')
        self.stdout.write('\nLệnh test nhanh:')
        self.stdout.write(
            f'  mosquitto_pub -h localhost -t "smartlock/DEV-SIM-001/event" '
            f'-m "{{\\"type\\": \\"rfid_tap\\", \\"uid\\": \\"{raw_uid}\\"}}"'
        )
        self.stdout.write(
            f'  mosquitto_pub -h localhost -t "smartlock/DEV-SIM-001/event" '
            f'-m "{{\\"type\\": \\"pin_entry\\", \\"pin\\": \\"{plain_pin}\\"}}"'
        )
        self.stdout.write(
            '  mosquitto_pub -h localhost -t "smartlock/DEV-SIM-002/status" '
            '-m "{\\"battery_level\\": 77, \\"lock_state\\": \\"locked\\"}"'
        )

    def _resolve_owner(self, owner_email: str):
        if owner_email:
            user = User.objects.filter(email__iexact=owner_email).first()
            if not user:
                raise CommandError(f'Không tìm thấy user với email "{owner_email}".')
            return user
        user = User.objects.filter(is_superuser=True).first() or User.objects.filter(is_staff=True).first()
        if not user:
            raise CommandError(
                'Chưa có user nào là staff/superuser trong DB. Chạy lại với --owner=email@cua_ban '
                'hoặc tạo trước 1 tài khoản (python manage.py createsuperuser).'
            )
        return user