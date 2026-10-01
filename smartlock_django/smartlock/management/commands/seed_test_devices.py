# smartlock/management/commands/seed_test_devices.py
"""
    python manage.py seed_test_devices --owner=email@cua_ban

Tạo 2 thiết bị giả lập (DEV-SIM-001 / DEV-SIM-002) + 1 đầu đọc mô phỏng mỗi thiết bị,
1 thẻ RFID hợp lệ, 1 mã PIN 60 phút và 1 vé Bluetooth cho DEV-SIM-001, rồi in ra các lệnh
mosquitto_pub để test end-to-end. Chạy lại nhiều lần được (update_or_create theo device_code).
"""
import secrets

from django.conf import settings
from django.contrib.auth import get_user_model
from django.core.management.base import BaseCommand, CommandError
from django.utils import timezone

from smartlock import services
from smartlock.models import AccessCard, CardDeviceAccess, Device, NfcReader, hash_card_uid

User = get_user_model()
PROVISIONING_SECRET = 'test-secret-please-change'


class Command(BaseCommand):
    help = 'Tạo 2 thiết bị giả lập + thẻ RFID + PIN + vé Bluetooth hợp lệ để test hệ thống.'

    def add_arguments(self, parser):
        parser.add_argument('--owner', type=str, default='', help='Email của user làm owner.')

    def handle(self, *args, **options):
        # Secret cố định + thiết bị giả: tuyệt đối không chạy trên production.
        if not settings.DEBUG:
            raise CommandError('seed_test_devices chỉ chạy khi DEBUG=True (dữ liệu test dùng secret cố định).')
        owner = self._resolve_owner(options['owner'])
        self.stdout.write(self.style.SUCCESS(f'Dùng owner: {owner.email}'))

        devices = []
        for i, code in enumerate(['DEV-SIM-001', 'DEV-SIM-002'], start=1):
            device, created = Device.objects.update_or_create(
                device_code=code,
                defaults={
                    'provisioning_secret_hash': services.hash_token(PROVISIONING_SECRET),
                    'device_mode': 'simulated', 'owner': owner,
                    'name': f'Khoá cửa giả lập #{i}', 'status': 'online', 'battery_level': 90,
                    'location': f'Phòng test {i}', 'last_seen_at': timezone.now(),
                },
            )
            NfcReader.objects.update_or_create(
                device=device, reader_mode='simulated',
                defaults={'name': f'Đầu đọc giả lập {i}', 'is_active': True, 'last_seen_at': timezone.now()},
            )
            devices.append(device)
            self.stdout.write(f'  {"Tạo mới" if created else "Đã cập nhật"} {code} '
                              f'(MQTT user/password: "{code}" / "{PROVISIONING_SECRET}")')

        raw_uid = secrets.token_hex(4).upper()
        card, _ = AccessCard.objects.update_or_create(
            card_uid_hash=hash_card_uid(raw_uid),
            defaults={'user': owner, 'name': 'Thẻ test tự động', 'is_active': True},
        )
        CardDeviceAccess.objects.get_or_create(access_card=card, device=devices[0])

        _, plain_pin = services.issue_unique_door_pin(
            device=devices[0], created_by=owner, ttl_minutes=60, label='PIN test tự động', max_uses=5)
        ticket, exp = services.issue_ble_ticket(devices[0], owner)

        w = self.stdout.write
        w(self.style.SUCCESS('\n===== DỮ LIỆU TEST ====='))
        w(f'  UID thẻ RFID hợp lệ (DEV-SIM-001): {raw_uid}')
        w(f'  Mã PIN hợp lệ (DEV-SIM-001, 60 phút, tối đa 5 lần): {plain_pin}')
        w(f'  Vé Bluetooth (DEV-SIM-001, hạn unix {exp}): {ticket}')
        w('\nLệnh test nhanh:')
        w(f'  mosquitto_pub -h localhost -t "smartlock/DEV-SIM-001/event" '
          f'-m "{{\\"type\\": \\"rfid_tap\\", \\"uid\\": \\"{raw_uid}\\"}}"')
        w(f'  mosquitto_pub -h localhost -t "smartlock/DEV-SIM-001/event" '
          f'-m "{{\\"type\\": \\"pin_entry\\", \\"pin\\": \\"{plain_pin}\\"}}"')
        w(f'  mosquitto_pub -h localhost -t "smartlock/DEV-SIM-001/event" '
          f'-m "{{\\"type\\": \\"ble_unlock\\", \\"ticket\\": \\"{ticket}\\", \\"at\\": {int(timezone.now().timestamp())}}}"')
        w('  mosquitto_pub -h localhost -t "smartlock/DEV-SIM-002/status" '
          '-m "{\\"battery_level\\": 77, \\"lock_state\\": \\"locked\\"}"')

    def _resolve_owner(self, owner_email):
        if owner_email:
            user = User.objects.filter(email__iexact=owner_email).first()
            if not user:
                raise CommandError(f'Không tìm thấy user với email "{owner_email}".')
            return user
        user = User.objects.filter(is_superuser=True).first() or User.objects.filter(is_staff=True).first()
        if not user:
            raise CommandError('Chưa có user staff/superuser. Chạy lại với --owner=email hoặc '
                               'tạo trước 1 tài khoản (python manage.py createsuperuser).')
        return user