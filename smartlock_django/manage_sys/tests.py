# manage_sys/tests.py  ->  chạy:  python manage.py test manage_sys
from datetime import timedelta

from django.conf import settings
from django.test import TestCase
from django.urls import reverse
from django.utils import timezone

from smartlock import services
from smartlock.models import (
    MobileSession, AccessCard, AuditLog, CardDeviceAccess, Device, DeviceStatusLog, NfcReader, Notification,
    User,
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

    def test_settings_saved_without_ip_lists(self):
        r = self.client.post(reverse('manage_sys:settings'), {
            'verification_token_expiry_minutes': 45, 'share_code_expiry_minutes': 20,
            'session_timeout_hours': 12, 'lockout_stages': '5,10,30'})
        self.assertEqual(r.status_code, 302)
        from smartlock.models import SystemSettings
        st = SystemSettings.objects.get(pk=1)
        self.assertEqual((st.verification_token_expiry_minutes, st.share_code_expiry_minutes,
                          st.session_timeout_hours), (45, 20, 12))
        self.assertFalse(hasattr(st, 'ip_blacklist'))
        self.assertFalse(hasattr(st, 'ip_whitelist'))


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
            'owner_email': '', 'mac_address': ''}, follow=True)   # POST -> redirect -> trang hiển thị secret
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
        self.client.post(self.url, {'action': 'remove_owner', 'confirm': 'sai', 'current_password': PW})
        self.device.refresh_from_db()
        self.assertEqual(self.device.owner_id, self.user.id)
        self.client.post(self.url, {'action': 'remove_owner', 'confirm': self.device.device_code, 'current_password': PW})
        self.device.refresh_from_db()
        self.assertEqual((self.device.owner_id, self.device.status), (None, 'revoked'))
        self.assertTrue(AuditLog.objects.filter(action='MANAGE_DEVICE_OWNER_REMOVED', severity='critical').exists())
        self.assertTrue(Notification.objects.filter(user=self.user, type='DEVICE', severity='critical').exists())

    def test_admin_cannot_reassign_revoked_but_user_can_reclaim(self):
        self._connect()
        self._claim()
        self.client.post(self.url, {'action': 'remove_owner', 'confirm': self.device.device_code, 'current_password': PW})
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
        self.client.post(self.url, {'action': 'rotate_secret', 'confirm': self.device.device_code, 'current_password': PW})
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

class LoginHardeningTests(ManageSysBase):
    def _login(self, ident, pw=PW):
        return self.client.post(reverse('manage_sys:login'), {'identifier': ident, 'password': pw})

    def _error_text(self, r):
        return [str(m) for m in r.context['messages']]

    def test_locked_admin_gets_same_message_as_unknown_email(self):
        from datetime import timedelta as td
        self.admin.login_locked_until = timezone.now() + td(minutes=10)
        self.admin.save(update_fields=['login_locked_until'])
        locked = self._error_text(self._login('admin@example.com'))
        unknown = self._error_text(self._login('nobody@example.com'))
        wrong = self._error_text(self._login('user@example.com', 'sai-mat-khau'))
        self.assertEqual(locked, unknown)
        self.assertEqual(unknown, wrong)
        self.assertNotIn(ADMIN_COOKIE, self.client.cookies)   # đúng mật khẩu nhưng đang khóa -> không vào được


class SecretRevealTests(ManageSysBase):
    def setUp(self):
        super().setUp()
        self.client.post(reverse('manage_sys:login'), {'identifier': 'admin@example.com', 'password': PW})
        self.device = Device.objects.create(
            device_code='DEV-SEC00001', provisioning_secret_hash=services.hash_token('old'),
            name='Khoá', status='provisioning', owner=None)
        self.url = reverse('manage_sys:device-detail', args=[self.device.id])
        self.reveal = reverse('manage_sys:device-secret', args=[self.device.id])

    def test_rotate_redirects_and_refresh_does_not_rotate_again(self):
        r = self.client.post(self.url, {'action': 'rotate_secret', 'confirm': self.device.device_code, 'current_password': PW})
        self.assertRedirects(r, self.reveal, fetch_redirect_response=False)
        self.device.refresh_from_db()
        hash_after_rotate = self.device.provisioning_secret_hash
        page = self.client.get(self.reveal)                       # hiển thị secret
        secret = page.context['secret']
        self.assertEqual(services.hash_token(secret), hash_after_rotate)
        self.client.get(self.reveal)                              # "F5": không còn secret, KHÔNG xoay lại
        self.device.refresh_from_db()
        self.assertEqual(self.device.provisioning_secret_hash, hash_after_rotate)
        self.assertEqual(AuditLog.objects.filter(action='MANAGE_DEVICE_SECRET_ROTATED').count(), 1)

    def test_secret_shown_once_then_redirected(self):
        self.client.post(self.url, {'action': 'rotate_secret', 'confirm': self.device.device_code, 'current_password': PW})
        self.assertEqual(self.client.get(self.reveal).status_code, 200)
        self.assertRedirects(self.client.get(self.reveal), self.url, fetch_redirect_response=False)

    def test_secret_not_stored_in_plaintext_in_session(self):
        self.client.post(self.url, {'action': 'rotate_secret', 'confirm': self.device.device_code, 'current_password': PW})
        stash = self.client.session['manage_pending_secret']
        self.device.refresh_from_db()
        # blob là token Fernet, không chứa secret gốc; secret gốc chỉ lấy được qua trang reveal
        secret = self.client.get(self.reveal).context['secret']
        self.assertNotIn(secret, str(stash))

    def test_secret_not_in_audit_metadata(self):
        self.client.post(self.url, {'action': 'rotate_secret', 'confirm': self.device.device_code, 'current_password': PW})
        secret = self.client.get(self.reveal).context['secret']
        for log in AuditLog.objects.filter(device=self.device):
            self.assertNotIn(secret, str(log.metadata))


class DeactivateRevokesMobileTests(ManageSysBase):
    def test_deactivate_revokes_mobile_sessions(self):
        self.client.post(reverse('manage_sys:login'), {'identifier': 'admin@example.com', 'password': PW})
        s = MobileSession.objects.create(
            user=self.user, refresh_hash='h' * 64, fcm_token='tok',
            expires_at=timezone.now() + timedelta(days=30))
        self.client.post(reverse('manage_sys:user-detail', args=[self.user.id]), {'action': 'toggle_active'})
        s.refresh_from_db()
        self.assertIsNotNone(s.revoked_at)
        self.assertEqual(s.fcm_token, '')


class ReauthTests(ManageSysBase):
    def setUp(self):
        super().setUp()
        self.client.post(reverse('manage_sys:login'), {'identifier': 'admin@example.com', 'password': PW})
        self.url = reverse('manage_sys:user-detail', args=[self.user.id])

    def test_grant_admin_needs_correct_password(self):
        self.client.post(self.url, {'action': 'grant_admin', 'current_password': 'sai'})
        self.user.refresh_from_db()
        self.assertFalse(self.user.is_admin)
        self.assertTrue(AuditLog.objects.filter(action='MANAGE_REAUTH_FAILED', actor_user=self.admin).exists())
        self.admin.refresh_from_db()
        self.assertEqual(self.admin.login_failed_attempts, 1)          # tính vào bộ đếm khóa
        self.client.post(self.url, {'action': 'grant_admin', 'current_password': PW})
        self.user.refresh_from_db()
        self.assertTrue(self.user.is_admin)

    def test_missing_password_is_rejected(self):
        self.client.post(self.url, {'action': 'grant_admin'})
        self.user.refresh_from_db()
        self.assertFalse(self.user.is_admin)

    def test_remove_owner_and_rotate_need_password(self):
        dev = Device.objects.create(device_code='DEV-RE000001', provisioning_secret_hash='x',
                                    name='K', owner=self.user, status='online')
        url = reverse('manage_sys:device-detail', args=[dev.id])
        self.client.post(url, {'action': 'rotate_secret', 'confirm': dev.device_code, 'current_password': 'sai'})
        self.client.post(url, {'action': 'remove_owner', 'confirm': dev.device_code})
        dev.refresh_from_db()
        self.assertEqual((dev.provisioning_secret_hash, dev.owner_id), ('x', self.user.id))


class HighAdminPolicyTests(ManageSysBase):
    """Admin thường (is_admin, KHÔNG superuser): xem + vận hành gần như Superuser, trừ thao tác nhạy cảm."""
    def setUp(self):
        super().setUp()
        self.mod = make_user('mod@example.com', 'mod1', is_admin=True)
        self.client.post(reverse('manage_sys:login'), {'identifier': 'mod@example.com', 'password': PW})
        self.device = Device.objects.create(device_code='DEV-HA000001', provisioning_secret_hash='x',
                                            name='K', owner=self.user, status='online')

    def test_can_view_everything(self):
        for name, args in (('dashboard', []), ('users', []), ('logs', []), ('login-attempts', []),
                           ('devices', []), ('settings', []), ('announcements', []),
                           ('user-detail', [self.user.id]), ('user-detail', [self.admin.id]),
                           ('device-detail', [self.device.id])):
            self.assertEqual(self.client.get(reverse(f'manage_sys:{name}', args=args)).status_code, 200, name)

    def test_can_manage_other_plain_admin_but_not_superuser(self):
        peer = make_user('peer@example.com', 'peer1', is_admin=True)
        self.client.post(reverse('manage_sys:user-detail', args=[peer.id]), {'action': 'toggle_active'})
        peer.refresh_from_db()
        self.assertFalse(peer.is_active)
        self.client.post(reverse('manage_sys:user-detail', args=[self.admin.id]), {'action': 'toggle_active'})
        self.admin.refresh_from_db()
        self.assertTrue(self.admin.is_active)

    def test_cannot_grant_or_revoke_admin_even_with_password(self):
        url = reverse('manage_sys:user-detail', args=[self.user.id])
        self.client.post(url, {'action': 'grant_admin', 'current_password': PW})
        self.user.refresh_from_db()
        self.assertFalse(self.user.is_admin)
        self.assertTrue(AuditLog.objects.filter(action='MANAGE_ACTION_DENIED', actor_user=self.mod).exists())

    def test_cannot_rotate_secret_or_remove_owner(self):
        url = reverse('manage_sys:device-detail', args=[self.device.id])
        self.client.post(url, {'action': 'rotate_secret', 'confirm': self.device.device_code,
                               'current_password': PW})
        self.client.post(url, {'action': 'remove_owner', 'confirm': self.device.device_code,
                               'current_password': PW})
        self.device.refresh_from_db()
        self.assertEqual((self.device.provisioning_secret_hash, self.device.owner_id), ('x', self.user.id))

    def test_can_still_operate_devices(self):
        url = reverse('manage_sys:device-detail', args=[self.device.id])
        self.client.post(url, {'action': 'maintenance_on'})
        self.device.refresh_from_db()
        self.assertEqual(self.device.status, 'maintenance')

    def test_device_detail_exposes_metadata_only(self):
        ctx = self.client.get(reverse('manage_sys:device-detail', args=[self.device.id])).context
        for key in ('cards', 'pins', 'faces', 'access_events'):
            self.assertIn(key, ctx)
        self.assertFalse(ctx['can_sensitive'])


class AdminNotOwnerTests(ManageSysBase):
    """Tài khoản quản trị KHÔNG được làm chủ khoá (chủ khoá phải là user thường)."""
    def setUp(self):
        super().setUp()
        self.client.post(reverse('manage_sys:login'), {'identifier': 'admin@example.com', 'password': PW})
        self.other_admin = make_user('adm2@example.com', 'adm2', is_admin=True)

    def test_claim_to_admin_rejected(self):
        dev = Device.objects.create(device_code='DEV-NOADM001', provisioning_secret_hash='x',
                                    name='K', status='provisioning')
        with self.assertRaises(services.ClaimError) as ctx:
            services.claim_device(dev.id, self.other_admin, by_admin=True)
        self.assertEqual(ctx.exception.code, 'OWNER_IS_ADMIN')

    def test_device_create_with_admin_owner_rejected(self):
        self.client.post(reverse('manage_sys:device-create'), {
            'device_code': 'DEV-NOADM002', 'name': 'K', 'device_mode': 'physical',
            'owner_email': 'adm2@example.com'})
        self.assertFalse(Device.objects.filter(device_code='DEV-NOADM002').exists())

    def test_cannot_grant_admin_to_device_owner(self):
        Device.objects.create(device_code='DEV-NOADM003', provisioning_secret_hash='x',
                              name='K', owner=self.user, status='online')
        self.client.post(reverse('manage_sys:user-detail', args=[self.user.id]),
                         {'action': 'grant_admin', 'current_password': PW})
        self.user.refresh_from_db()
        self.assertFalse(self.user.is_admin)


class SettingsPermissionTests(ManageSysBase):
    URL_DATA = {'verification_token_expiry_minutes': 45, 'share_code_expiry_minutes': 20,
                'session_timeout_hours': 12, 'lockout_stages': '5,10,30'}

    def test_plain_admin_can_view_but_not_save(self):
        make_user('mod@example.com', 'mod1', is_admin=True)
        self.client.post(reverse('manage_sys:login'), {'identifier': 'mod@example.com', 'password': PW})
        url = reverse('manage_sys:settings')
        self.assertEqual(self.client.get(url).status_code, 200)
        self.client.post(url, self.URL_DATA)
        from smartlock.models import SystemSettings
        self.assertNotEqual(SystemSettings.objects.get(pk=1).session_timeout_hours, 12)

    def test_superuser_can_save(self):
        self.client.post(reverse('manage_sys:login'), {'identifier': 'admin@example.com', 'password': PW})
        self.client.post(reverse('manage_sys:settings'), self.URL_DATA)
        from smartlock.models import SystemSettings
        self.assertEqual(SystemSettings.objects.get(pk=1).session_timeout_hours, 12)


class StrictAuditTests(ManageSysBase):
    def test_critical_action_rolled_back_when_audit_fails(self):
        from unittest import mock
        self.client.post(reverse('manage_sys:login'), {'identifier': 'admin@example.com', 'password': PW})
        with mock.patch.object(AuditLog.objects, 'create', side_effect=RuntimeError('db down')):
            self.client.post(reverse('manage_sys:user-detail', args=[self.user.id]),
                             {'action': 'grant_admin', 'current_password': PW})
        self.user.refresh_from_db()
        self.assertFalse(self.user.is_admin)           # không có log -> không cấp quyền


class SuperuserGuardTests(ManageSysBase):
    def test_last_superuser_cannot_be_orphaned(self):
        from manage_sys.views import _would_orphan_superusers
        self.assertTrue(_would_orphan_superusers(self.admin))           # chỉ có 1 superuser
        make_user('root2@example.com', 'root2', is_admin=True, is_superuser=True)
        self.assertFalse(_would_orphan_superusers(self.admin))
        self.assertFalse(_would_orphan_superusers(self.user))           # user thường: không liên quan


class LoginExtrasTests(ManageSysBase):
    def test_new_ip_login_notifies(self):
        AuditLog.objects.create(action='MANAGE_LOGIN', actor_user=self.admin, ip_address='10.9.9.9')
        self.client.post(reverse('manage_sys:login'), {'identifier': 'admin@example.com', 'password': PW})
        self.assertTrue(Notification.objects.filter(user=self.admin, type='SECURITY').exists())

    def test_known_ip_and_first_login_do_not_notify(self):
        self.client.post(reverse('manage_sys:login'), {'identifier': 'admin@example.com', 'password': PW})   # lần đầu
        self.client.post(reverse('manage_sys:logout'))
        self.client.post(reverse('manage_sys:login'), {'identifier': 'admin@example.com', 'password': PW})   # cùng IP
        self.assertFalse(Notification.objects.filter(user=self.admin, type='SECURITY').exists())

    def test_admin_cookie_flags(self):
        self.client.post(reverse('manage_sys:login'), {'identifier': 'admin@example.com', 'password': PW})
        c = self.client.cookies[ADMIN_COOKIE]
        self.assertTrue(c['httponly'])
        self.assertEqual(c['samesite'], 'Strict')

    def test_dashboard_stats(self):
        self.client.post(reverse('manage_sys:login'), {'identifier': 'admin@example.com', 'password': PW})
        r = self.client.get(reverse('manage_sys:dashboard'))
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.context['stats']['total_users'], 2)
        self.assertEqual(r.context['stats']['active_users'], 2)


class ClientIpTests(TestCase):
    def _req(self, xff=None, remote='10.0.0.1'):
        from django.test import RequestFactory
        extra = {'REMOTE_ADDR': remote}
        if xff is not None:
            extra['HTTP_X_FORWARDED_FOR'] = xff
        return RequestFactory().get('/', **extra)

    def test_xff_ignored_when_not_trusted(self):
        with self.settings(TRUST_PROXY_HEADERS=False):
            self.assertEqual(services.client_ip(self._req('1.2.3.4')), '10.0.0.1')

    def test_spoofed_first_xff_element_is_ignored(self):
        with self.settings(TRUST_PROXY_HEADERS=True, TRUST_PROXY_COUNT=1):
            # client giả mạo 6.6.6.6; proxy của mình thêm 203.0.113.9 ở cuối
            self.assertEqual(services.client_ip(self._req('6.6.6.6, 203.0.113.9')), '203.0.113.9')

    def test_two_trusted_proxies(self):
        with self.settings(TRUST_PROXY_HEADERS=True, TRUST_PROXY_COUNT=2):
            self.assertEqual(services.client_ip(self._req('6.6.6.6, 203.0.113.9, 172.16.0.1')), '203.0.113.9')

    def test_short_xff_falls_back_to_remote_addr(self):
        with self.settings(TRUST_PROXY_HEADERS=True, TRUST_PROXY_COUNT=2):
            self.assertEqual(services.client_ip(self._req('6.6.6.6')), '10.0.0.1')

    def test_invalid_value_falls_back(self):
        with self.settings(TRUST_PROXY_HEADERS=True, TRUST_PROXY_COUNT=1):
            self.assertEqual(services.client_ip(self._req('khong-phai-ip')), '10.0.0.1')


class PruneAuditLogsTests(TestCase):
    def test_prunes_by_severity_and_age(self):
        from django.core.management import call_command
        old = timezone.now() - timedelta(days=200)
        very_old = timezone.now() - timedelta(days=800)
        keep = AuditLog.objects.create(action='A_KEEP_NEW', severity='info')
        a = AuditLog.objects.create(action='A_OLD_INFO', severity='info')
        b = AuditLog.objects.create(action='A_OLD_CRIT', severity='critical')
        c = AuditLog.objects.create(action='A_VERY_OLD_CRIT', severity='critical')
        AuditLog.objects.filter(pk=a.pk).update(created_at=old)
        AuditLog.objects.filter(pk=b.pk).update(created_at=old)
        AuditLog.objects.filter(pk=c.pk).update(created_at=very_old)
        call_command('prune_auditlogs', '--dry-run', stdout=__import__('io').StringIO())
        self.assertEqual(AuditLog.objects.count(), 4)                   # dry-run không xoá
        call_command('prune_auditlogs', stdout=__import__('io').StringIO())
        left = set(AuditLog.objects.values_list('action', flat=True))
        self.assertIn('A_KEEP_NEW', left)
        self.assertIn('A_OLD_CRIT', left)                               # critical giữ 730 ngày
        self.assertNotIn('A_OLD_INFO', left)
        self.assertNotIn('A_VERY_OLD_CRIT', left)