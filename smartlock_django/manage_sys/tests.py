# manage_sys/tests.py  ->  chạy:  python manage.py test manage_sys
from datetime import timedelta

from django.conf import settings
from django.test import TestCase
from django.urls import reverse
from django.utils import timezone

from smartlock import services
from smartlock.models import (
    AccessCard, AuditLog, CardDeviceAccess, Device, DeviceStatusLog, NfcReader, Notification,
    SupportRequest, User,
)

PREFIX = getattr(settings, 'MANAGE_SYS_URL_PREFIX', '/manage-sys/')
ADMIN_COOKIE = getattr(settings, 'MANAGE_SYS_SESSION_COOKIE_NAME', 'manage_sys_sessionid')
PW = 'Str0ng-Pass-12345'


def make_user(email, username, **extra):
    extra.setdefault('is_active', True)
    extra.setdefault('email_verified', True)
    return User.objects.create_user(email=email, username=username, password=PW, **extra)


class ManageSysBase(TestCase):
    def setUp(self):
        self.admin = make_user('admin@example.com', 'admin1', is_admin=True, is_superuser=True)
        self.user = make_user('user@example.com', 'user1')


class AuthSeparationTests(ManageSysBase):
    def test_anonymous_redirected_to_manage_login(self):
        r = self.client.get(reverse('manage_sys:dashboard'))
        self.assertEqual(r.status_code, 302)
        self.assertIn(reverse('manage_sys:login'), r['Location'])

    def test_regular_user_cannot_login_to_manage(self):
        r = self.client.post(reverse('manage_sys:login'), {'identifier': 'user@example.com', 'password': PW})
        self.assertEqual(r.status_code, 200)  # ở lại trang login với thông báo lỗi
        self.assertNotIn(ADMIN_COOKIE, self.client.cookies)
        self.assertEqual(self.client.get(reverse('manage_sys:dashboard')).status_code, 302)

    def test_admin_login_uses_separate_cookie(self):
        r = self.client.post(reverse('manage_sys:login'), {'identifier': 'admin@example.com', 'password': PW})
        self.assertRedirects(r, reverse('manage_sys:dashboard'), fetch_redirect_response=False)
        self.assertIn(ADMIN_COOKIE, self.client.cookies)
        self.assertEqual(self.client.cookies[ADMIN_COOKIE]['path'], PREFIX)
        self.assertNotIn(settings.SESSION_COOKIE_NAME, self.client.cookies)
        self.assertEqual(self.client.get(reverse('manage_sys:dashboard')).status_code, 200)

    def test_admin_session_is_not_valid_on_user_site(self):
        self.client.post(reverse('manage_sys:login'), {'identifier': 'admin@example.com', 'password': PW})
        r = self.client.get(reverse('smartlock:dashboard'))
        self.assertEqual(r.status_code, 302)
        self.assertIn(reverse('smartlock:login'), r['Location'])

    def test_user_session_is_not_valid_on_manage_site(self):
        self.client.force_login(self.user)  # tạo cookie 'sessionid' của user
        r = self.client.get(reverse('manage_sys:dashboard'))
        self.assertEqual(r.status_code, 302)
        self.assertIn(reverse('manage_sys:login'), r['Location'])

    def test_admin_account_rejected_on_user_login(self):
        r = self.client.post(reverse('smartlock:login'), {'identifier': 'admin@example.com', 'password': PW})
        self.assertEqual(r.status_code, 200)
        self.assertNotIn(settings.SESSION_COOKIE_NAME, self.client.cookies)
        self.assertTrue(AuditLog.objects.filter(action='LOGIN_ADMIN_REJECTED').exists())

    def test_logout_requires_post(self):
        self.client.post(reverse('manage_sys:login'), {'identifier': 'admin@example.com', 'password': PW})
        self.assertEqual(self.client.get(reverse('manage_sys:logout')).status_code, 405)
        self.client.post(reverse('manage_sys:logout'))
        self.assertEqual(self.client.get(reverse('manage_sys:dashboard')).status_code, 302)


class ActionTests(ManageSysBase):
    def setUp(self):
        super().setUp()
        self.client.post(reverse('manage_sys:login'), {'identifier': 'admin@example.com', 'password': PW})
        self.device = Device.objects.create(
            device_code='DEV-TEST0001', provisioning_secret_hash='x', name='Cửa chính',
            owner=self.user, status='online')

    def _support(self, **kw):
        defaults = dict(device=self.device, requested_by=self.user, action='ADD_CARD',
                        authorization_code_hash='h', expires_at=timezone.now() + timedelta(hours=1))
        defaults.update(kw)
        return SupportRequest.objects.create(**defaults)

    def test_support_approve_then_execute(self):
        sr = self._support()
        url = reverse('manage_sys:support-detail', args=[sr.id])
        self.client.post(url, {'action': 'approve', 'reason': 'ok'})
        sr.refresh_from_db()
        self.assertEqual((sr.status, sr.processed_by_id), ('approved', self.admin.id))
        self.assertTrue(Notification.objects.filter(user=self.user, type='SUPPORT').exists())
        self.client.post(url, {'action': 'execute'})
        sr.refresh_from_db()
        self.assertEqual(sr.status, 'executed')
        self.assertIsNotNone(sr.completed_at)

    def test_support_cannot_skip_states(self):
        sr = self._support()
        self.client.post(reverse('manage_sys:support-detail', args=[sr.id]), {'action': 'execute'})
        sr.refresh_from_db()
        self.assertEqual(sr.status, 'pending')

    def test_expired_support_is_marked_expired(self):
        sr = self._support(expires_at=timezone.now() - timedelta(minutes=1))
        self.client.post(reverse('manage_sys:support-detail', args=[sr.id]), {'action': 'approve'})
        sr.refresh_from_db()
        self.assertEqual(sr.status, 'expired')

    def test_device_maintenance_toggle(self):
        url = reverse('manage_sys:device-detail', args=[self.device.id])
        self.client.post(url, {'action': 'maintenance_on'})
        self.device.refresh_from_db()
        self.assertEqual(self.device.status, 'maintenance')
        self.client.post(url, {'action': 'maintenance_off'})
        self.device.refresh_from_db()
        self.assertEqual(self.device.status, 'offline')

    def test_cannot_deactivate_self(self):
        self.client.post(reverse('manage_sys:user-detail', args=[self.admin.id]), {'action': 'toggle_active'})
        self.admin.refresh_from_db()
        self.assertTrue(self.admin.is_active)

    def test_non_superuser_admin_cannot_touch_other_admin(self):
        other = make_user('mod@example.com', 'mod1', is_admin=True)  # admin thường, không phải superuser
        self.client.post(reverse('manage_sys:logout'))
        self.client.post(reverse('manage_sys:login'), {'identifier': 'mod@example.com', 'password': PW})
        self.client.post(reverse('manage_sys:user-detail', args=[self.admin.id]), {'action': 'toggle_active'})
        self.admin.refresh_from_db()
        self.assertTrue(self.admin.is_active)
        # nhưng vẫn quản lý được user thường
        self.client.post(reverse('manage_sys:user-detail', args=[self.user.id]), {'action': 'toggle_active'})
        self.user.refresh_from_db()
        self.assertFalse(self.user.is_active)

    def test_settings_rejects_blacklisting_own_ip(self):
        r = self.client.post(reverse('manage_sys:settings'), {
            'verification_token_expiry_minutes': 30, 'share_code_expiry_minutes': 15,
            'session_timeout_hours': 24, 'lockout_stages': '5,10,30',
            'ip_blacklist': '127.0.0.1', 'ip_whitelist': ''})
        self.assertEqual(r.status_code, 302)
        from smartlock.models import SystemSettings
        self.assertEqual(SystemSettings.objects.get(pk=1).ip_blacklist, '')


class DeviceLifecycleTests(ManageSysBase):
    """Quy tắc: admin chỉ gán chủ cho khoá MỚI (provisioning) và chỉ khi khoá đang kết nối;
    khoá bị gỡ chủ (revoked) chỉ user tự claim (kể cả chủ cũ); mọi thao tác đều có AuditLog."""
    SECRET = 's3cret-value'

    def setUp(self):
        super().setUp()
        self.client.post(reverse('manage_sys:login'), {'identifier': 'admin@example.com', 'password': PW})
        self.device = Device.objects.create(
            device_code='DEV-LIFE0001', provisioning_secret_hash=services.hash_token(self.SECRET),
            name='Khoá thử', status='provisioning', owner=None)
        self.url = reverse('manage_sys:device-detail', args=[self.device.id])

    def _connect(self):
        DeviceStatusLog.objects.create(device=self.device, battery_level=90, lock_state='locked')

    def _claim(self, who=None):
        return self.client.post(self.url, {'action': 'claim', 'owner': (who or self.user).email})

    def test_admin_created_device_uses_sha256_secret_and_has_no_owner(self):
        r = self.client.post(reverse('manage_sys:device-create'), {
            'device_code': 'DEV-NEW0001', 'name': 'Mới', 'device_mode': 'simulated',
            'owner_email': '', 'mac_address': ''})
        d = Device.objects.get(device_code='DEV-NEW0001')
        self.assertIsNone(d.owner)
        self.assertEqual(d.status, 'provisioning')
        # đúng kiểu hash mà mqtt_auth_webhook so sánh => thiết bị đăng nhập được broker
        self.assertEqual(d.provisioning_secret_hash, services.hash_token(r.context['secret']))
        self.assertTrue(AuditLog.objects.filter(action='MANAGE_DEVICE_CREATED', device=d).exists())

    def test_claim_denied_when_not_connected(self):
        self._claim()
        self.device.refresh_from_db()
        self.assertIsNone(self.device.owner)
        self.assertTrue(AuditLog.objects.filter(action='MANAGE_DEVICE_CLAIM_FAILED', success=False,
                                                metadata__code='NOT_CONNECTED').exists())

    def test_claim_ok_when_connected(self):
        self._connect()
        self._claim()
        self.device.refresh_from_db()
        self.assertEqual((self.device.owner_id, self.device.status), (self.user.id, 'online'))
        self.assertTrue(self.device.is_purchased)
        self.assertTrue(AuditLog.objects.filter(action='MANAGE_DEVICE_CLAIMED', device=self.device,
                                                actor_user=self.admin, target_user=self.user).exists())

    def test_stale_signal_is_not_connected(self):
        self._connect()
        DeviceStatusLog.objects.filter(device=self.device).update(
            recorded_at=timezone.now() - timedelta(seconds=services.ONLINE_WINDOW_SECONDS + 30))
        self.assertFalse(services.link_status(self.device)['connected'])

    def test_touch_device_never_violates_owner_constraint(self):
        services.touch_device(self.device, firmware='1.2.3')
        self.device.refresh_from_db()
        self.assertEqual(self.device.status, 'provisioning')   # khoá chưa chủ không bị đặt online
        self.assertIsNotNone(self.device.last_seen_at)
        self.assertTrue(services.link_status(self.device)['connected'])

    def test_remove_owner_requires_confirm_then_revokes_everything(self):
        self._connect()
        self._claim()
        self.client.post(self.url, {'action': 'remove_owner', 'confirm': 'sai'})
        self.device.refresh_from_db()
        self.assertEqual(self.device.owner_id, self.user.id)
        self.client.post(self.url, {'action': 'remove_owner', 'confirm': self.device.device_code})
        self.device.refresh_from_db()
        self.assertEqual((self.device.owner_id, self.device.status), (None, 'revoked'))
        self.assertTrue(AuditLog.objects.filter(action='MANAGE_DEVICE_OWNER_REMOVED', severity='critical').exists())
        self.assertTrue(Notification.objects.filter(user=self.user, type='DEVICE', severity='critical').exists())

    def test_admin_cannot_reassign_revoked_but_user_can_reclaim(self):
        self._connect()
        self._claim()
        self.client.post(self.url, {'action': 'remove_owner', 'confirm': self.device.device_code})
        self._connect()
        self._claim(self.user)                                    # admin thử gán lại -> bị từ chối
        self.device.refresh_from_db()
        self.assertIsNone(self.device.owner)
        self.assertTrue(AuditLog.objects.filter(action='MANAGE_DEVICE_CLAIM_FAILED',
                                                metadata__code='ADMIN_CANNOT_REASSIGN').exists())
        # chủ cũ tự thêm lại bằng code + secret -> được
        services.user_claim_device(self.user, self.device.device_code, self.SECRET)
        self.device.refresh_from_db()
        self.assertEqual(self.device.owner_id, self.user.id)

    def test_user_claim_wrong_secret_is_rate_limited(self):
        self._connect()
        for _ in range(services.CLAIM_MAX_FAILS):
            AuditLog.objects.create(actor_user=self.user, action='DEVICE_CLAIM_FAILED', success=False)
        with self.assertRaises(services.ClaimError) as ctx:
            services.user_claim_device(self.user, self.device.device_code, self.SECRET)
        self.assertEqual(ctx.exception.code, 'RATE_LIMITED')

    def test_user_claim_wrong_secret_rejected(self):
        self._connect()
        with self.assertRaises(services.ClaimError) as ctx:
            services.user_claim_device(self.user, self.device.device_code, 'sai')
        self.assertEqual(ctx.exception.code, 'BAD_CREDENTIALS')

    def test_rotate_secret_changes_hash_and_is_logged(self):
        old = self.device.provisioning_secret_hash
        self.client.post(self.url, {'action': 'rotate_secret', 'confirm': self.device.device_code})
        self.device.refresh_from_db()
        self.assertNotEqual(self.device.provisioning_secret_hash, old)
        self.assertTrue(AuditLog.objects.filter(action='MANAGE_DEVICE_SECRET_ROTATED').exists())

    def test_link_endpoint_and_view_audit(self):
        r = self.client.get(reverse('manage_sys:device-link', args=[self.device.id]))
        self.assertFalse(r.json()['connected'])
        self.client.get(self.url)
        self.assertTrue(AuditLog.objects.filter(action='MANAGE_VIEW_DEVICE', actor_user=self.admin).exists())

    def test_rfid_tap_registers_card_only_inside_window(self):
        self._connect()
        self._claim()
        self.device.refresh_from_db()
        reader = NfcReader.objects.create(device=self.device, reader_mode='simulated', is_active=True,
                                          auto_register=True)           # signal mở cửa sổ 60s
        ev = services.verify_rfid_tap(self.device, 'AA:BB:CC:DD')
        self.assertEqual(ev.reason, 'CARD_REGISTERED')
        self.assertTrue(CardDeviceAccess.objects.filter(device=self.device, access_card__user=self.user).exists())
        self.assertTrue(AuditLog.objects.filter(action='CARD_AUTO_REGISTERED', device=self.device).exists())
        # hết cửa sổ -> thẻ lạ khác bị từ chối như thường
        NfcReader.objects.filter(pk=reader.pk).update(auto_register_until=timezone.now() - timedelta(seconds=1))
        ev2 = services.verify_rfid_tap(self.device, '11:22:33:44')
        self.assertEqual(ev2.reason, 'UNKNOWN_CARD')
        self.assertEqual(AccessCard.objects.filter(user=self.user).count(), 1)