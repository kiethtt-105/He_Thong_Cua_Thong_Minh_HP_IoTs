# manage_sys/tests.py  ->  chạy:  python manage.py test manage_sys
from datetime import timedelta

from django.conf import settings
from django.test import TestCase
from django.urls import reverse
from django.utils import timezone

from smartlock.models import AuditLog, Device, Notification, SupportRequest, User

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
