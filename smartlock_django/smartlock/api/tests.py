# smartlock/api/tests.py
"""Test toàn bộ API user. Chạy:
    python manage.py test smartlock.api --settings=smartlock_django.settings_test -v 2
MQTT luôn được mock - không cần broker."""
import uuid
from datetime import timedelta
from unittest import mock

from django.core import mail
from django.core.cache import cache
from django.test import TestCase
from django.utils import timezone
from rest_framework.test import APIClient

from .. import access_control, rules_engine
from ..models import (
    AccessCard, AccessEvent, Announcement, AuditLog, AutomationRule, Device, DeviceAccess,
    DeviceCommand, DeviceStatusLog, DoorPinCode, FaceProfile, NfcLog, Notification, Permission,
    ShareAccessCode, SupportRequest, User,
)
from ..mqtt_client import MqttPublishError
from .common import ensure_default_permissions

BASE = '/api/v1/'
PUBLISH = 'smartlock.api.views.publish_command'
AC_PUBLISH = 'smartlock.access_control.publish_command'
PASSWORD = 'Pass12345!x'


class ApiTestCase(TestCase):
    def setUp(self):
        cache.clear()
        ensure_default_permissions()
        self.owner = self.make_user('owner')
        self.other = self.make_user('other')
        self.device = self.make_device(self.owner)
        self.c = self.client_for(self.owner)
        self.oc = self.client_for(self.other)

    # ---------- helpers
    def make_user(self, name):
        return User.objects.create_user(email=f'{name}@example.com', username=name, password=PASSWORD,
                                        is_active=True, email_verified=True)

    def make_device(self, owner, name='Cửa chính', status='online'):
        return Device.objects.create(device_code=f'DEV-{uuid.uuid4().hex[:8].upper()}', name=name,
                                     provisioning_secret_hash='x', owner=owner, status=status)

    def client_for(self, user, **kw):
        c = APIClient(**kw)
        c.force_login(user)
        return c

    def share(self, device, user, codes=(), expires=None):
        acc = DeviceAccess.objects.create(device=device, user=user, created_by=device.owner,
                                          accepted=True, expires_at=expires)
        acc.permissions.set(Permission.objects.filter(code__in=codes))
        return acc

    def get(self, path, c=None, **params):
        return (c or self.c).get(BASE + path, params)

    def post(self, path, data=None, c=None):
        return (c or self.c).post(BASE + path, data or {}, format='json')

    def patch(self, path, data, c=None):
        return (c or self.c).patch(BASE + path, data, format='json')

    def delete(self, path, c=None):
        return (c or self.c).delete(BASE + path)

    def dev(self, suffix='', device=None):
        return f'devices/{(device or self.device).id}/{suffix}'


# ====================================================================== nền tảng
class AuthAndMetaTests(ApiTestCase):
    def test_unauthenticated_is_rejected(self):
        anon = APIClient()
        u = uuid.uuid4()
        for path in ['me/', 'meta/', 'dashboard/', 'announcements/', 'devices/', f'devices/{u}/',
                     f'devices/{u}/status-logs/', f'devices/{u}/commands/', 'permissions/', 'my-accesses/',
                     'share-codes/', 'nfc-cards/', f'devices/{u}/door-pins/', f'devices/{u}/face-profiles/',
                     'access-events/', 'support-requests/', 'notifications/', 'notifications/unread-count/',
                     'automation-rules/', 'audit-logs/']:
            self.assertIn(anon.get(BASE + path).status_code, (401, 403), path)

    def test_csrf_endpoint_sets_cookie(self):
        r = APIClient().get(BASE + 'csrf/')
        self.assertEqual(r.status_code, 200)
        self.assertIn('csrftoken', r.cookies)

    def test_csrf_enforced_on_writes(self):
        c = self.client_for(self.owner, enforce_csrf_checks=True)
        r = c.post(BASE + 'devices/', {'name': 'X'}, format='json')
        self.assertEqual(r.status_code, 403)

    def test_meta(self):
        r = self.get('meta/')
        self.assertEqual(r.status_code, 200)
        body = r.json()
        codes = {p['code'] for p in body['permissions']}
        self.assertTrue({'LOCK', 'UNLOCK', 'manage_pins', 'manage_face_profiles'} <= codes)
        self.assertIn('BATTERY_LOW', {t['value'] for t in body['automation_triggers']})
        self.assertEqual(sorted(body['commands']), ['LOCK', 'REBOOT', 'UNLOCK'])

    def test_permissions_list(self):
        self.assertEqual(self.get('permissions/').status_code, 200)

    def test_dashboard_and_announcements(self):
        Announcement.objects.create(title='Bảo trì', body='...', is_active=True)
        Notification.objects.create(user=self.owner, title='t', message='m')
        r = self.get('dashboard/')
        self.assertEqual(r.status_code, 200)
        b = r.json()
        self.assertEqual(b['total_devices'], 1)
        self.assertEqual(b['online_devices'], 1)
        self.assertEqual(b['unread_count'], 1)
        self.assertEqual(len(b['chart']['labels']), 7)
        self.assertEqual(len(b['announcements']), 1)
        self.assertEqual(len(self.get('announcements/').json()), 1)


class ProfileTests(ApiTestCase):
    def test_me_get_patch(self):
        self.assertEqual(self.get('me/').json()['username'], 'owner')
        r = self.patch('me/', {'full_name': ' Nguyễn A ', 'phone': '0900000000'})
        self.assertEqual(r.status_code, 200)
        self.owner.refresh_from_db()
        self.assertEqual(self.owner.full_name, 'Nguyễn A')
        self.assertTrue(AuditLog.objects.filter(action='PROFILE_UPDATED', actor_user=self.owner).exists())

    def test_me_does_not_leak_password(self):
        self.assertNotIn('password', self.get('me/').json())

    def test_change_password(self):
        bad = self.post('me/password/', {'old_password': 'sai', 'new_password1': 'Abcdef123!',
                                         'new_password2': 'Abcdef123!'})
        self.assertEqual(bad.status_code, 400)
        mismatch = self.post('me/password/', {'old_password': PASSWORD, 'new_password1': 'Abcdef123!',
                                              'new_password2': 'khac'})
        self.assertEqual(mismatch.status_code, 400)
        ok = self.post('me/password/', {'old_password': PASSWORD, 'new_password1': 'Abcdef123!',
                                        'new_password2': 'Abcdef123!'})
        self.assertEqual(ok.status_code, 200)
        self.owner.refresh_from_db()
        self.assertTrue(self.owner.check_password('Abcdef123!'))
        self.assertEqual(self.get('me/').status_code, 200)      # phiên hiện tại còn sống
        self.assertTrue(Notification.objects.filter(user=self.owner, type='SECURITY').exists())

    def test_change_password_rate_limited_after_5_failures(self):
        for _ in range(5):
            self.post('me/password/', {'old_password': 'sai', 'new_password1': 'a', 'new_password2': 'a'})
        r = self.post('me/password/', {'old_password': PASSWORD, 'new_password1': 'Abcdef123!',
                                       'new_password2': 'Abcdef123!'})
        self.assertEqual(r.status_code, 429)


# ====================================================================== thiết bị
class DeviceTests(ApiTestCase):
    def test_create_device_returns_secret_once(self):
        r = self.post('devices/', {'name': 'Cửa sau'})
        self.assertEqual(r.status_code, 201)
        body = r.json()
        self.assertIn('no-store', r['Cache-Control'])
        secret = body['provisioning_secret']
        d = Device.objects.get(id=body['device']['id'])
        self.assertEqual(d.owner, self.owner)
        self.assertNotEqual(d.provisioning_secret_hash, secret)
        self.assertNotIn('provisioning_secret_hash', body['device'])
        self.assertTrue(body['device']['is_owner'])
        self.assertTrue(mail.outbox)                                  # email cho chủ thiết bị

    def test_create_device_blank_name(self):
        self.assertEqual(self.post('devices/', {'name': '   '}).status_code, 400)

    def test_list_and_isolation(self):
        self.assertEqual(len(self.get('devices/').json()), 1)
        self.assertEqual(self.get('devices/', c=self.oc).json(), [])
        self.assertEqual(self.get(self.dev(), c=self.oc).status_code, 404)

    def test_lock_state_from_latest_status(self):
        old = DeviceStatusLog.objects.create(device=self.device, battery_level=80, lock_state='unlocked')
        DeviceStatusLog.objects.filter(pk=old.pk).update(recorded_at=timezone.now() - timedelta(minutes=5))
        DeviceStatusLog.objects.create(device=self.device, battery_level=79, lock_state='locked')
        self.assertEqual(self.get('devices/').json()[0]['lock_state'], 'locked')
        detail = self.get(self.dev()).json()
        self.assertEqual(detail['device']['lock_state'], 'locked')
        self.assertEqual(detail['last_status']['battery_level'], 79)
        self.assertEqual(self.get(self.dev('status-logs/')).json()['count'], 2)

    def test_lock_state_unknown_without_logs(self):
        self.assertEqual(self.get('devices/').json()[0]['lock_state'], 'unknown')

    def test_patch_owner_only(self):
        r = self.patch(self.dev(), {'name': 'Mới', 'location': ' Tầng 1 ', 'wifi_enabled': False})
        self.assertEqual(r.status_code, 200)
        self.device.refresh_from_db()
        self.assertEqual((self.device.name, self.device.location, self.device.wifi_enabled),
                         ('Mới', 'Tầng 1', False))
        self.share(self.device, self.other, ['LOCK'])
        self.assertEqual(self.patch(self.dev(), {'name': 'Hack'}, c=self.oc).status_code, 403)
        self.assertTrue(AuditLog.objects.filter(action='DEVICE_UPDATE_DENIED').exists())

    def test_shared_user_sees_device_not_owner_flag(self):
        self.share(self.device, self.other, ['LOCK'])
        d = self.get('devices/', c=self.oc).json()[0]
        self.assertFalse(d['is_owner'])

    def test_expired_share_hides_device(self):
        self.share(self.device, self.other, ['LOCK'], expires=timezone.now() + timedelta(seconds=1))
        DeviceAccess.objects.update(valid_from=timezone.now() - timedelta(hours=2),
                                    expires_at=timezone.now() - timedelta(hours=1))
        self.assertEqual(self.get('devices/', c=self.oc).json(), [])


class CommandTests(ApiTestCase):
    def test_lock_success_and_poll(self):
        with mock.patch(PUBLISH) as pub:
            r = self.post(self.dev('command/'), {'command': 'lock'})
        self.assertEqual(r.status_code, 202)
        payload = pub.call_args[0][1]
        self.assertEqual(payload['command'], 'LOCK')
        cid = r.json()['command_id']
        self.assertEqual(self.get(self.dev(f'commands/{cid}/')).json()['status'], 'sent')
        self.assertEqual(self.get(self.dev('commands/')).json()['count'], 1)
        self.assertTrue(AuditLog.objects.filter(action='CMD_LOCK', device=self.device).exists())

    def test_invalid_command(self):
        self.assertEqual(self.post(self.dev('command/'), {'command': 'DROP'}).status_code, 400)

    def test_device_offline_409(self):
        Device.objects.filter(pk=self.device.pk).update(status='offline')
        with mock.patch(PUBLISH) as pub:
            self.assertEqual(self.post(self.dev('command/'), {'command': 'UNLOCK'}).status_code, 409)
        pub.assert_not_called()

    def test_duplicate_429(self):
        with mock.patch(PUBLISH):
            self.assertEqual(self.post(self.dev('command/'), {'command': 'LOCK'}).status_code, 202)
            self.assertEqual(self.post(self.dev('command/'), {'command': 'LOCK'}).status_code, 429)

    def test_mqtt_failure_502(self):
        with mock.patch(PUBLISH, side_effect=MqttPublishError('down')):
            r = self.post(self.dev('command/'), {'command': 'LOCK'})
        self.assertEqual(r.status_code, 502)
        self.assertEqual(DeviceCommand.objects.get().status, 'failed')

    def test_permissions_for_shared_user(self):
        self.share(self.device, self.other, ['LOCK'])
        with mock.patch(PUBLISH):
            self.assertEqual(self.post(self.dev('command/'), {'command': 'LOCK'}, c=self.oc).status_code, 202)
            self.assertEqual(self.post(self.dev('command/'), {'command': 'UNLOCK'}, c=self.oc).status_code, 403)
            self.assertEqual(self.post(self.dev('command/'), {'command': 'REBOOT'}, c=self.oc).status_code, 403)

    def test_command_visibility(self):
        self.share(self.device, self.other, ['LOCK'])
        with mock.patch(PUBLISH):
            cid = self.post(self.dev('command/'), {'command': 'LOCK'}, c=self.oc).json()['command_id']
            self.post(self.dev('command/'), {'command': 'UNLOCK'})     # lệnh của chủ
        self.assertEqual(self.get(self.dev('commands/')).json()['count'], 2)            # chủ thấy hết
        self.assertEqual(self.get(self.dev('commands/'), c=self.oc).json()['count'], 1)  # người được chia sẻ chỉ thấy của mình
        self.assertEqual(self.get(self.dev(f'commands/{cid}/'), c=self.oc).status_code, 200)

    def test_expired_command_poll(self):
        cmd = DeviceCommand.objects.create(device=self.device, issued_by=self.owner, command_type='LOCK',
                                           status='sent', command_token_hash='h',
                                           expires_at=timezone.now() - timedelta(seconds=1))
        self.assertEqual(self.get(self.dev(f'commands/{cmd.id}/')).json()['status'], 'expired')


# ====================================================================== quyền & chia sẻ
class AccessTests(ApiTestCase):
    def test_grant_update_revoke_flow(self):
        r = self.post(self.dev('accesses/'), {'identifier': 'OTHER@example.com', 'permissions': ['LOCK']})
        self.assertEqual(r.status_code, 201)
        aid = r.json()['id']
        self.assertEqual(r.json()['permissions'], ['LOCK'])
        self.assertTrue(Notification.objects.filter(user=self.other, type='ACCESS').exists())
        self.assertEqual(len(self.get('my-accesses/', c=self.oc).json()['results']), 1)
        self.assertEqual(len(self.get(self.dev('accesses/')).json()), 1)

        r = self.patch(self.dev(f'accesses/{aid}/'), {'permissions': ['UNLOCK']})
        self.assertEqual(r.json()['permissions'], ['UNLOCK'])

        with mock.patch(PUBLISH):
            self.assertEqual(self.post(self.dev('command/'), {'command': 'UNLOCK'}, c=self.oc).status_code, 202)
        self.assertEqual(self.delete(self.dev(f'accesses/{aid}/')).status_code, 204)
        self.assertEqual(self.get(self.dev(), c=self.oc).status_code, 404)
        self.assertTrue(AuditLog.objects.filter(action='ACCESS_REVOKED').exists())
        self.assertTrue(Notification.objects.filter(user=self.other, title__icontains='thu hồi').exists())

    def test_grant_validation(self):
        p = self.dev('accesses/')
        self.assertEqual(self.post(p, {'identifier': 'nobody'}).status_code, 400)
        self.assertEqual(self.post(p, {'identifier': 'owner'}).status_code, 400)          # tự cấp cho mình
        r = self.post(p, {'identifier': 'other', 'permissions': ['NOPE']})
        self.assertEqual(r.status_code, 400)
        self.assertIn('permissions', r.json())
        past = (timezone.now() - timedelta(hours=1)).isoformat()
        self.assertEqual(self.post(p, {'identifier': 'other', 'expires_at': past}).status_code, 400)

    def test_grant_again_updates_not_duplicates(self):
        p = self.dev('accesses/')
        self.post(p, {'identifier': 'other', 'permissions': ['LOCK']})
        self.post(p, {'identifier': 'other', 'permissions': ['LOCK', 'UNLOCK']})
        self.assertEqual(DeviceAccess.objects.filter(device=self.device, user=self.other, is_active=True).count(), 1)

    def test_only_owner_manages_access(self):
        self.assertEqual(self.get(self.dev('accesses/'), c=self.oc).status_code, 404)     # chưa được chia sẻ
        self.share(self.device, self.other, ['LOCK'])
        self.assertEqual(self.get(self.dev('accesses/'), c=self.oc).status_code, 403)
        self.assertEqual(self.post(self.dev('accesses/'), {'identifier': 'owner'}, c=self.oc).status_code, 403)


class ShareCodeTests(ApiTestCase):
    def create_code(self, **extra):
        return self.post('share-codes/', {'device_id': str(self.device.id), 'minutes': 10,
                                          'permissions': ['LOCK'], **extra})

    def test_create_list_delete(self):
        r = self.create_code()
        self.assertEqual(r.status_code, 201)
        self.assertIn('no-store', r['Cache-Control'])
        self.assertRegex(r.json()['code'], r'^\d{6}$')
        lst = self.get('share-codes/').json()
        self.assertEqual(len(lst), 1)
        self.assertNotIn('code', lst[0])                                  # danh sách không lộ mã
        self.assertNotIn('code_hash', lst[0])
        self.assertEqual(self.delete(f'share-codes/{lst[0]["id"]}/').status_code, 204)
        self.assertEqual(ShareAccessCode.objects.count(), 0)

    def test_create_validation(self):
        bad_minutes = self.post('share-codes/', {'device_id': str(self.device.id), 'minutes': 5000})
        self.assertEqual(bad_minutes.status_code, 400)
        foreign = self.post('share-codes/', {'device_id': str(self.device.id)}, c=self.oc)
        self.assertEqual(foreign.status_code, 404)
        unknown_perm = self.post('share-codes/', {'device_id': str(self.device.id), 'permissions': ['X']})
        self.assertEqual(unknown_perm.status_code, 400)

    def test_email_recipient(self):
        r = self.create_code(recipient='other')
        self.assertEqual(r.json()['email_status'], 'sent')
        self.assertTrue(any('other@example.com' in m.to for m in mail.outbox))
        self.assertEqual(self.create_code(recipient='ghost').json()['email_status'], 'recipient_not_found')

    def test_redeem_flow_single_use(self):
        code = self.create_code().json()['code']
        r = self.post('share-codes/redeem/', {'code': code}, c=self.oc)
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.json()['permissions'], ['LOCK'])
        self.assertEqual(self.get('devices/', c=self.oc).json()[0]['id'], str(self.device.id))
        third = self.client_for(self.make_user('third'))
        self.assertEqual(self.post('share-codes/redeem/', {'code': code}, c=third).status_code, 400)  # đã dùng
        self.assertTrue(Notification.objects.filter(user=self.owner, type='SHARE').exists())

    def test_redeem_accepts_formatted_code(self):
        code = self.create_code().json()['code']
        self.assertEqual(self.post('share-codes/redeem/', {'code': f'{code[:3]} {code[3:]}'}, c=self.oc).status_code, 200)

    def test_redeem_own_device_rejected(self):
        code = self.create_code().json()['code']
        self.assertEqual(self.post('share-codes/redeem/', {'code': code}).status_code, 400)

    def test_redeem_rate_limit(self):
        for _ in range(5):
            self.assertEqual(self.post('share-codes/redeem/', {'code': '000000'}, c=self.oc).status_code, 400)
        code = self.create_code().json()['code']
        self.assertEqual(self.post('share-codes/redeem/', {'code': code}, c=self.oc).status_code, 429)

    def test_cannot_delete_others_code(self):
        self.create_code()
        cid = ShareAccessCode.objects.get().id
        self.assertEqual(self.delete(f'share-codes/{cid}/', c=self.oc).status_code, 404)


# ====================================================================== NFC / thẻ
class NfcTests(ApiTestCase):
    def test_reader_lifecycle(self):
        r = self.post(self.dev('nfc-readers/'), {'name': 'Đầu đọc 1'})
        self.assertEqual(r.status_code, 201)
        rid = r.json()['id']
        self.assertTrue(r.json()['is_active'])
        r = self.patch(self.dev(f'nfc-readers/{rid}/'), {'is_active': False, 'auto_register': True})
        self.assertEqual(r.status_code, 200)
        self.assertEqual((r.json()['is_active'], r.json()['auto_register']), (False, True))
        self.assertEqual(len(self.get(self.dev('nfc-readers/')).json()), 1)
        self.assertEqual(self.get(self.dev('nfc-logs/')).json()['count'], 3)      # connected + disconnected + config
        self.assertEqual(NfcLog.objects.filter(device=self.device).count(), 3)

    def test_reader_owner_only(self):
        self.assertEqual(self.get(self.dev('nfc-readers/'), c=self.oc).status_code, 404)
        self.share(self.device, self.other, ['LOCK'])
        self.assertEqual(self.post(self.dev('nfc-readers/'), {}, c=self.oc).status_code, 403)
        self.assertEqual(self.get(self.dev('nfc-logs/'), c=self.oc).status_code, 403)

    def test_card_lifecycle(self):
        r = self.post(self.dev('nfc-cards/'), {'uid': 'aa:bb:cc:dd', 'name': 'Thẻ 1'})
        self.assertEqual(r.status_code, 201)
        body = r.json()
        self.assertNotIn('card_uid_hash', body)
        self.assertNotIn('AABBCCDD', str(body))
        cid = body['id']
        self.assertEqual(self.post(self.dev('nfc-cards/'), {'uid': 'AABBCCDD'}).status_code, 400)    # trùng
        self.assertEqual(self.post(self.dev('nfc-cards/'), {'uid': 'AB'}).status_code, 400)          # quá ngắn
        self.assertEqual(len(self.get('nfc-cards/').json()), 1)
        r = self.patch(f'nfc-cards/{cid}/', {'name': 'Mới', 'is_active': False})
        self.assertEqual((r.json()['name'], r.json()['is_active']), ('Mới', False))
        self.assertEqual(self.delete(f'nfc-cards/{cid}/').status_code, 204)
        self.assertEqual(AccessCard.objects.count(), 0)

    def test_card_isolation(self):
        cid = self.post(self.dev('nfc-cards/'), {'uid': 'AABBCCDD'}).json()['id']
        self.assertEqual(self.get('nfc-cards/', c=self.oc).json(), [])
        self.assertEqual(self.patch(f'nfc-cards/{cid}/', {'name': 'x'}, c=self.oc).status_code, 404)
        self.assertEqual(self.delete(f'nfc-cards/{cid}/', c=self.oc).status_code, 404)

    def test_registered_card_works_on_tap(self):
        self.post(self.dev('nfc-cards/'), {'uid': 'aa:bb:cc:dd'})
        with mock.patch(AC_PUBLISH):
            ev = access_control.verify_rfid_tap(self.device, 'AABBCCDD')
        self.assertTrue(ev.success)
        with mock.patch(AC_PUBLISH):
            ev = access_control.verify_rfid_tap(self.device, '11223344')
        self.assertFalse(ev.success)


# ====================================================================== PIN / khuôn mặt / lịch sử
class DoorPinTests(ApiTestCase):
    def issue(self, c=None, **extra):
        return self.post(self.dev('door-pins/'), {'ttl_minutes': 60, 'max_uses': 1, 'label': 'Khách', **extra}, c=c)

    def test_issue_list_revoke(self):
        r = self.issue()
        self.assertEqual(r.status_code, 201)
        self.assertIn('no-store', r['Cache-Control'])
        pin, pid = r.json()['pin'], r.json()['id']
        self.assertRegex(pin, r'^\d{6}$')
        lst = self.get(self.dev('door-pins/'))
        self.assertEqual(lst.json()['count'], 1)
        self.assertNotIn(pin, lst.content.decode())
        self.assertNotIn('pin_hash', lst.content.decode())
        self.assertEqual(lst.json()['results'][0]['state'], 'active')
        r = self.post(self.dev(f'door-pins/{pid}/revoke/'))
        self.assertEqual(r.json()['state'], 'revoked')

    def test_validation(self):
        self.assertEqual(self.issue(ttl_minutes=0).status_code, 400)
        self.assertEqual(self.issue(ttl_minutes=99999).status_code, 400)
        self.assertEqual(self.issue(max_uses=-1).status_code, 400)

    def test_permission_manage_pins(self):
        self.share(self.device, self.other, ['LOCK'])
        self.assertEqual(self.issue(c=self.oc).status_code, 403)
        self.assertEqual(self.get(self.dev('door-pins/'), c=self.oc).status_code, 403)
        self.assertTrue(AuditLog.objects.filter(action='DOOR_PIN_CREATE_DENIED').exists())
        self.share(self.device, self.make_user('mgr'), ['manage_pins'])
        mgr_client = self.client_for(User.objects.get(username='mgr'))
        self.assertEqual(self.issue(c=mgr_client).status_code, 201)

    def test_issued_pin_opens_door_once(self):
        pin = self.issue().json()['pin']
        with mock.patch(AC_PUBLISH) as pub:
            first = access_control.verify_door_pin(self.device, pin)
            second = access_control.verify_door_pin(self.device, pin)
        self.assertTrue(first.success)
        self.assertFalse(second.success)          # PIN dùng 1 lần
        self.assertEqual(pub.call_count, 1)
        self.assertEqual(DoorPinCode.objects.get().use_count, 1)

    def test_revoked_pin_does_not_open(self):
        r = self.issue().json()
        self.post(self.dev(f'door-pins/{r["id"]}/revoke/'))
        with mock.patch(AC_PUBLISH):
            self.assertFalse(access_control.verify_door_pin(self.device, r['pin']).success)

    def test_pin_refunded_when_mqtt_fails(self):
        pin = self.issue().json()['pin']
        with mock.patch(AC_PUBLISH, side_effect=MqttPublishError('down')):
            self.assertFalse(access_control.verify_door_pin(self.device, pin).success)
        self.assertEqual(DoorPinCode.objects.get().use_count, 0)


class FaceTests(ApiTestCase):
    EMB = [round(i / 100, 3) for i in range(32)]

    def register(self, c=None, **over):
        return self.post(self.dev('face-profiles/'),
                         {'name': 'Chủ nhà', 'embedding': self.EMB, 'consent_confirmed': True, **over}, c=c)

    def test_register_validation(self):
        self.assertEqual(self.register(consent_confirmed=False).status_code, 400)
        self.assertEqual(self.register(embedding=[0.1] * 10).status_code, 400)
        self.assertEqual(self.register(embedding=['a'] * 40).status_code, 400)

    def test_register_never_returns_embedding(self):
        r = self.register()
        self.assertEqual(r.status_code, 201)
        self.assertNotIn('embedding', r.content.decode())
        self.assertNotIn('embedding', self.get(self.dev('face-profiles/')).content.decode())
        self.assertEqual(self.register().status_code, 201)               # đăng ký lại = cập nhật, không nhân đôi
        self.assertEqual(FaceProfile.objects.count(), 1)

    def test_toggle_and_recognition(self):
        pid = self.register().json()['id']
        with mock.patch(AC_PUBLISH):
            self.assertTrue(access_control.verify_face(self.device, self.EMB).success)
        r = self.patch(self.dev(f'face-profiles/{pid}/'), {'is_active': False})
        self.assertFalse(r.json()['is_active'])
        with mock.patch(AC_PUBLISH):
            self.assertFalse(access_control.verify_face(self.device, self.EMB).success)

    def test_delete_removes_biometric_data(self):
        pid = self.register().json()['id']
        self.assertEqual(self.delete(self.dev(f'face-profiles/{pid}/')).status_code, 204)
        self.assertEqual(FaceProfile.objects.count(), 0)
        self.assertTrue(AuditLog.objects.filter(action='FACE_PROFILE_DELETED').exists())

    def test_shared_user_scope(self):
        self.register()
        self.share(self.device, self.other, ['LOCK'])
        self.assertEqual(self.register(c=self.oc).status_code, 403)       # thiếu manage_face_profiles
        DeviceAccess.objects.get(user=self.other).permissions.add(Permission.objects.get(code='manage_face_profiles'))
        self.assertEqual(self.register(c=self.oc).status_code, 201)
        self.assertEqual(len(self.get(self.dev('face-profiles/')).json()), 2)              # chủ thấy cả 2
        mine = self.get(self.dev('face-profiles/'), c=self.oc).json()
        self.assertEqual(len(mine), 1)                                                     # người kia chỉ thấy của mình
        owner_profile = FaceProfile.objects.get(user=self.owner)
        self.assertEqual(self.patch(self.dev(f'face-profiles/{owner_profile.id}/'),
                                    {'is_active': False}, c=self.oc).status_code, 404)


class AccessEventTests(ApiTestCase):
    def setUp(self):
        super().setUp()
        AccessEvent.objects.create(device=self.device, method='PIN', success=True, user=self.owner)
        AccessEvent.objects.create(device=self.device, method='RFID', success=False, reason='UNKNOWN_CARD')
        AccessEvent.objects.create(device=self.device, method='FACE', success=True, user=self.other)

    def test_owner_sees_all_and_filters(self):
        self.assertEqual(self.get('access-events/').json()['count'], 3)
        self.assertEqual(self.get('access-events/', method='RFID').json()['count'], 1)
        self.assertEqual(self.get('access-events/', success='true').json()['count'], 2)
        self.assertEqual(self.get('access-events/', device=str(self.device.id)).json()['count'], 3)
        self.assertEqual(self.get('access-events/', device=str(uuid.uuid4())).json()['count'], 0)
        self.assertEqual(self.get('access-events/', device='rác').json()['count'], 0)

    def test_shared_user_sees_only_own_events(self):
        self.share(self.device, self.other, ['LOCK'])
        r = self.get('access-events/', c=self.oc).json()
        self.assertEqual(r['count'], 1)
        self.assertEqual(r['results'][0]['method'], 'FACE')

    def test_stranger_sees_nothing(self):
        self.assertEqual(self.get('access-events/', c=self.oc).json()['count'], 0)


# ====================================================================== hỗ trợ / thông báo / luật / log
class SupportTests(ApiTestCase):
    def create(self, action='ADD_CARD', c=None):
        return self.post('support-requests/', {'device_id': str(self.device.id), 'action': action}, c=c)

    def test_create_normal_and_recovery(self):
        r = self.create('ADD_CARD')
        self.assertEqual(r.status_code, 201)
        self.assertIn('no-store', r['Cache-Control'])
        self.assertTrue(r.json()['authorization_code'])
        self.assertIsNone(r.json()['recovery_code'])
        self.assertNotIn('authorization_code_hash', r.json())
        r = self.create('RECOVERY')
        self.assertTrue(r.json()['recovery_code'])

    def test_recovery_notifies_admins(self):
        User.objects.create_user(email='admin@example.com', username='admin', password=PASSWORD,
                                 is_active=True, is_admin=True)
        mail.outbox.clear()
        self.create('TRANSFER_OWNER')
        self.assertTrue(any('admin@example.com' in m.to for m in mail.outbox))

    def test_validation(self):
        self.assertEqual(self.post('support-requests/', {'device_id': str(self.device.id), 'action': 'X'}).status_code, 400)
        self.assertEqual(self.create(c=self.oc).status_code, 404)          # không phải chủ
        for _ in range(5):
            self.create()
        self.assertEqual(self.create().status_code, 409)                   # quá 5 yêu cầu chờ

    def test_list_detail_cancel(self):
        sid = self.create().json()['id']
        self.assertEqual(self.get('support-requests/').json()['count'], 1)
        self.assertEqual(self.get(f'support-requests/{sid}/').json()['status'], 'pending')
        self.assertEqual(self.post(f'support-requests/{sid}/cancel/').json()['status'], 'cancelled')
        self.assertEqual(self.post(f'support-requests/{sid}/cancel/').status_code, 409)

    def test_isolation_and_expiry(self):
        sid = self.create().json()['id']
        self.assertEqual(self.get(f'support-requests/{sid}/', c=self.oc).status_code, 404)
        self.assertEqual(self.post(f'support-requests/{sid}/cancel/', c=self.oc).status_code, 404)
        SupportRequest.objects.update(expires_at=timezone.now() - timedelta(minutes=1))
        self.assertEqual(self.get(f'support-requests/{sid}/').json()['status'], 'expired')


class NotificationTests(ApiTestCase):
    def setUp(self):
        super().setUp()
        self.n = [Notification.objects.create(user=self.owner, title=f't{i}', message='m', is_read=(i == 0))
                  for i in range(3)]
        self.foreign = Notification.objects.create(user=self.other, title='x', message='m')

    def test_list_and_counts(self):
        r = self.get('notifications/').json()
        self.assertEqual((r['count'], r['unread_count']), (3, 2))
        self.assertEqual(self.get('notifications/', filter='unread').json()['count'], 2)
        self.assertEqual(self.get('notifications/unread-count/').json()['unread_count'], 2)

    def test_mark_read(self):
        r = self.post(f'notifications/{self.n[1].id}/read/')
        self.assertTrue(r.json()['is_read'])
        self.assertEqual(self.post('notifications/read-all/').json()['updated'], 1)
        self.assertEqual(self.get('notifications/unread-count/').json()['unread_count'], 0)

    def test_delete(self):
        self.assertEqual(self.delete(f'notifications/{self.n[1].id}/').status_code, 204)
        self.assertEqual(self.delete(f'notifications/{self.n[1].id}/').status_code, 404)
        self.assertEqual(self.delete('notifications/read/').json()['deleted'], 1)        # chỉ n[0] đã đọc
        self.assertEqual(Notification.objects.filter(user=self.owner).count(), 1)

    def test_cannot_touch_others(self):
        self.assertEqual(self.post(f'notifications/{self.foreign.id}/read/').status_code, 404)
        self.assertEqual(self.delete(f'notifications/{self.foreign.id}/').status_code, 404)
        self.delete('notifications/read/')
        self.assertTrue(Notification.objects.filter(id=self.foreign.id).exists())


class AutomationRuleTests(ApiTestCase):
    def payload(self, **over):
        return {'name': 'Pin yếu', 'trigger_type': 'BATTERY_LOW', 'threshold_value': 20,
                'action_type': 'NOTIFY_ONLY', 'notify_severity': 'warning', 'cooldown_seconds': 0,
                'device': str(self.device.id), **over}

    def test_crud_toggle(self):
        r = self.post('automation-rules/', self.payload())
        self.assertEqual(r.status_code, 201)
        rid = r.json()['id']
        self.assertEqual(r.json()['device_name'], self.device.name)
        self.assertEqual(len(self.get('automation-rules/').json()), 1)
        self.assertEqual(self.get(f'automation-rules/{rid}/').status_code, 200)
        r = self.patch(f'automation-rules/{rid}/', {'threshold_value': 30, 'name': 'Mới'})
        self.assertEqual(r.status_code, 200)
        self.assertEqual(float(r.json()['threshold_value']), 30.0)
        self.assertFalse(self.post(f'automation-rules/{rid}/toggle/').json()['is_active'])
        self.assertTrue(self.post(f'automation-rules/{rid}/toggle/').json()['is_active'])
        self.assertEqual(self.delete(f'automation-rules/{rid}/').status_code, 204)
        self.assertEqual(AutomationRule.objects.count(), 0)

    def test_all_devices_rule(self):
        r = self.post('automation-rules/', self.payload(device=None))
        self.assertEqual(r.status_code, 201)
        self.assertIsNone(r.json()['device'])

    def test_validation(self):
        self.assertEqual(self.post('automation-rules/', self.payload(threshold_value=None)).status_code, 400)
        self.assertEqual(self.post('automation-rules/', self.payload(threshold_value=150)).status_code, 400)
        self.assertEqual(self.post('automation-rules/', self.payload(threshold_value=-1)).status_code, 400)
        self.assertEqual(self.post('automation-rules/', self.payload(trigger_type='X')).status_code, 400)
        self.assertEqual(self.post('automation-rules/', self.payload(action_type='X')).status_code, 400)
        self.assertEqual(self.post('automation-rules/', self.payload(name='')).status_code, 400)
        tamper = self.payload(trigger_type='TAMPER_DETECTED', threshold_value=None)
        self.assertEqual(self.post('automation-rules/', tamper).status_code, 201)

    def test_cannot_use_foreign_device_or_rule(self):
        foreign = self.make_device(self.other, 'Của người khác')
        self.assertEqual(self.post('automation-rules/', self.payload(device=str(foreign.id))).status_code, 400)
        rid = self.post('automation-rules/', self.payload()).json()['id']
        self.assertEqual(self.get(f'automation-rules/{rid}/', c=self.oc).status_code, 404)
        self.assertEqual(self.patch(f'automation-rules/{rid}/', {'name': 'x'}, c=self.oc).status_code, 404)
        self.assertEqual(self.delete(f'automation-rules/{rid}/', c=self.oc).status_code, 404)
        self.assertEqual(self.post(f'automation-rules/{rid}/toggle/', c=self.oc).status_code, 404)
        self.assertEqual(self.get('automation-rules/', c=self.oc).json(), [])

    def test_rule_fires_end_to_end(self):
        rid = self.post('automation-rules/', self.payload()).json()['id']
        log = DeviceStatusLog.objects.create(device=self.device, battery_level=10, lock_state='locked')
        self.assertEqual(rules_engine.evaluate_device_status(self.device, log), 1)
        logs = self.get(f'automation-rules/{rid}/logs/').json()
        self.assertEqual(logs['count'], 1)
        self.assertEqual(float(logs['results'][0]['measured_value']), 10.0)
        self.assertTrue(Notification.objects.filter(user=self.owner, type='AUTOMATION_RULE').exists())
        self.assertEqual(self.get(f'automation-rules/{rid}/logs/', c=self.oc).status_code, 404)

    def test_rule_not_fired_above_threshold(self):
        self.post('automation-rules/', self.payload())
        log = DeviceStatusLog.objects.create(device=self.device, battery_level=90, lock_state='locked')
        self.assertEqual(rules_engine.evaluate_device_status(self.device, log), 0)


class AuditLogTests(ApiTestCase):
    def test_visibility_and_filters(self):
        self.patch(self.dev(), {'name': 'A'})
        AuditLog.objects.create(actor_user=self.owner, action='LOGIN_FAILED', success=False)
        AuditLog.objects.create(actor_user=self.other, action='SECRET_OTHER')       # không liên quan tới owner
        body = self.get('audit-logs/').json()
        actions = {r['action'] for r in body['results']}
        self.assertIn('DEVICE_UPDATED', actions)
        self.assertNotIn('SECRET_OTHER', actions)
        self.assertEqual({r['action'] for r in self.get('audit-logs/', status='fail').json()['results']},
                         {'LOGIN_FAILED'})
        self.assertTrue(all(r['success'] for r in self.get('audit-logs/', status='ok').json()['results']))
        self.assertEqual(self.get('audit-logs/', q='device_upd').json()['count'], 1)

    def test_no_sensitive_fields_exposed(self):
        AuditLog.objects.create(actor_user=self.owner, action='X', ip_address='1.2.3.4', user_agent='UA',
                                metadata={'secret': 'v'})
        row = self.get('audit-logs/').json()['results'][0]
        for k in ('ip_address', 'user_agent', 'metadata'):
            self.assertNotIn(k, row)

    def test_pagination_page_size_cap(self):
        for i in range(30):
            AuditLog.objects.create(actor_user=self.owner, action=f'A{i}')
        self.assertEqual(len(self.get('audit-logs/').json()['results']), 20)
        self.assertEqual(len(self.get('audit-logs/', page_size=500).json()['results']), 30)