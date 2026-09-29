# smartlock/api/tests_mobile.py
"""Test lớp xác thực Bearer cho app Android. Chạy:
    python manage.py test smartlock.api.tests_mobile --settings=smartlock_django.settings_test -v 2
(settings_test.py cần thừa hưởng REST_FRAMEWORK từ settings.py - xem settings_additions.py)"""
import time
from unittest import mock

import pyotp
from django.contrib.auth.tokens import default_token_generator
from django.core import mail
from django.utils.encoding import force_bytes
from django.utils.http import urlsafe_base64_encode
from rest_framework.test import APIClient

from ..models import (
    AuditLog, Fido2Credential, MobileSession, TwoFactorConfig, User, sync_two_fa_flag,
)
from ..utils import SmartlockUtils as U
from .tests import PASSWORD, ApiTestCase

B = '/api/v1/'
NEW_PASSWORD = 'NewPass987!zz'


class MobileTestCase(ApiTestCase):
    def anon(self):
        return APIClient()

    def bearer(self, token):
        c = APIClient()
        c.credentials(HTTP_AUTHORIZATION=f'Bearer {token}')
        return c

    def login(self, identifier='owner', password=PASSWORD, **extra):
        return self.anon().post(B + 'auth/login/', {'identifier': identifier, 'password': password, **extra},
                                format='json')

    def login_tokens(self, identifier='owner', **extra):
        r = self.login(identifier, **extra)
        self.assertEqual(r.status_code, 200, r.content)
        return r.json()

    def enable_totp(self, user):
        secret = pyotp.random_base32()
        cfg = TwoFactorConfig.objects.get_or_create(user=user)[0]
        cfg.set_totp_secret(secret)
        cfg.totp_confirmed = True
        cfg.preferred_method = 'totp'
        cfg.save()
        sync_two_fa_flag(user)
        return secret


class LoginAndTokenTests(MobileTestCase):
    def test_login_returns_tokens_and_bearer_works(self):
        body = self.login_tokens(device_name='Pixel 8', app_version='1.2.0')
        self.assertEqual(body['token_type'], 'Bearer')
        self.assertEqual(body['user']['username'], 'owner')
        r = self.bearer(body['access_token']).get(B + 'me/')
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.json()['email'], 'owner@example.com')
        s = MobileSession.objects.get(pk=body['session_id'])
        self.assertEqual(s.device_name, 'Pixel 8')
        self.assertNotIn(body['refresh_token'], (s.refresh_hash,))       # DB chỉ lưu hash
        self.assertTrue(AuditLog.objects.filter(action='LOGIN', actor_user=self.owner).exists())

    def test_bearer_token_needs_no_csrf(self):
        body = self.login_tokens()
        c = APIClient(enforce_csrf_checks=True)
        c.credentials(HTTP_AUTHORIZATION=f"Bearer {body['access_token']}")
        self.assertEqual(c.post(B + 'devices/', {'name': 'Cửa sau'}, format='json').status_code, 201)

    def test_wrong_password_and_lockout(self):
        for _ in range(5):
            r = self.login(password='sai-mat-khau')
            self.assertEqual(r.status_code, 400)
            self.assertEqual(r.json()['code'], 'invalid_credentials')
        r = self.login()                         # đúng mật khẩu nhưng đang bị khoá
        self.assertEqual(r.status_code, 429)
        self.assertEqual(r.json()['code'], 'account_locked')

    def test_admin_account_rejected(self):
        User.objects.create_user(email='adm@example.com', username='adm', password=PASSWORD,
                                 is_active=True, email_verified=True, is_admin=True)
        r = self.login('adm')
        self.assertEqual(r.status_code, 400)
        self.assertEqual(r.json()['code'], 'invalid_credentials')

    def test_unverified_account_gets_403(self):
        User.objects.create_user(email='new@example.com', username='newbie', password=PASSWORD,
                                 is_active=False, email_verified=False)
        r = self.login('new@example.com')
        self.assertEqual(r.status_code, 403)
        self.assertEqual(r.json()['code'], 'email_unverified')

    def test_login_by_email_also_works(self):
        self.assertEqual(self.login('owner@example.com').status_code, 200)

    def test_missing_or_bad_bearer(self):
        self.assertEqual(self.anon().get(B + 'me/').status_code, 401)
        self.assertEqual(self.bearer('rác').get(B + 'me/').status_code, 401)

    def test_expired_access_token(self):
        body = self.login_tokens()
        with mock.patch('smartlock.api.mobile_auth.ACCESS_TTL', -1):
            r = self.bearer(body['access_token']).get(B + 'me/')
        self.assertEqual(r.status_code, 401)
        self.assertEqual(r.json()['code'], 'token_expired')

    def test_deactivated_user_token_rejected(self):
        body = self.login_tokens()
        User.objects.filter(pk=self.owner.pk).update(is_active=False)
        r = self.bearer(body['access_token']).get(B + 'me/')
        self.assertEqual(r.status_code, 401)
        self.assertEqual(r.json()['code'], 'account_disabled')

    def test_refresh_rotates_and_reuse_kills_session(self):
        first = self.login_tokens()
        r = self.anon().post(B + 'auth/refresh/', {'refresh_token': first['refresh_token']}, format='json')
        self.assertEqual(r.status_code, 200)
        second = r.json()
        self.assertNotEqual(second['refresh_token'], first['refresh_token'])
        self.assertEqual(self.bearer(second['access_token']).get(B + 'me/').status_code, 200)

        # dùng lại refresh token cũ => bị coi là lộ => huỷ phiên
        r = self.anon().post(B + 'auth/refresh/', {'refresh_token': first['refresh_token']}, format='json')
        self.assertEqual(r.status_code, 401)
        self.assertEqual(r.json()['code'], 'invalid_refresh')
        r = self.anon().post(B + 'auth/refresh/', {'refresh_token': second['refresh_token']}, format='json')
        self.assertEqual(r.status_code, 401)
        self.assertEqual(self.bearer(second['access_token']).get(B + 'me/').status_code, 401)

    def test_refresh_with_garbage_token(self):
        r = self.anon().post(B + 'auth/refresh/', {'refresh_token': 'abc'}, format='json')
        self.assertEqual(r.status_code, 401)

    def test_logout_revokes_session(self):
        body = self.login_tokens()
        c = self.bearer(body['access_token'])
        self.assertEqual(c.post(B + 'auth/logout/').status_code, 204)
        self.assertEqual(c.get(B + 'me/').status_code, 401)
        r = self.anon().post(B + 'auth/refresh/', {'refresh_token': body['refresh_token']}, format='json')
        self.assertEqual(r.status_code, 401)

    def test_logout_all(self):
        a, b = self.login_tokens(), self.login_tokens()
        r = self.bearer(a['access_token']).post(B + 'auth/logout-all/')
        self.assertEqual(r.json()['revoked'], 2)
        self.assertEqual(self.bearer(b['access_token']).get(B + 'me/').status_code, 401)

    def test_session_limit(self):
        with mock.patch('smartlock.api.mobile_auth.MAX_SESSIONS', 2):
            tokens = [self.login_tokens() for _ in range(3)]
        self.assertEqual(self.bearer(tokens[0]['access_token']).get(B + 'me/').status_code, 401)
        self.assertEqual(self.bearer(tokens[2]['access_token']).get(B + 'me/').status_code, 200)

    def test_sessions_list_and_revoke_other(self):
        a = self.login_tokens(device_name='Máy A')
        b = self.login_tokens(device_name='Máy B')
        ca = self.bearer(a['access_token'])
        rows = ca.get(B + 'auth/sessions/').json()
        self.assertEqual(len(rows), 2)
        self.assertEqual([r['device_name'] for r in rows if r['current']], ['Máy A'])
        self.assertEqual(ca.delete(B + f"auth/sessions/{b['session_id']}/").status_code, 204)
        self.assertEqual(self.bearer(b['access_token']).get(B + 'me/').status_code, 401)
        self.assertEqual(ca.delete(B + f"auth/sessions/{b['session_id']}/").status_code, 404)

    def test_cannot_revoke_someone_elses_session(self):
        other = self.login_tokens('other')
        mine = self.bearer(self.login_tokens()['access_token'])
        self.assertEqual(mine.delete(B + f"auth/sessions/{other['session_id']}/").status_code, 404)

    def test_change_password_revokes_other_sessions_only(self):
        a, b = self.login_tokens(), self.login_tokens()
        ca = self.bearer(a['access_token'])
        r = ca.post(B + 'me/password/', {'old_password': PASSWORD, 'new_password1': NEW_PASSWORD,
                                         'new_password2': NEW_PASSWORD}, format='json')
        self.assertEqual(r.status_code, 200, r.content)
        self.assertEqual(ca.get(B + 'me/').status_code, 200)
        self.assertEqual(self.bearer(b['access_token']).get(B + 'me/').status_code, 401)
        self.assertEqual(self.login(password=NEW_PASSWORD).status_code, 200)

    def test_existing_session_login_is_not_broken(self):
        # web SPA vẫn dùng cookie session + CSRF như cũ
        self.assertEqual(self.get('me/').status_code, 200)


class PushAndConfigTests(MobileTestCase):
    def test_push_token_put_delete_and_claim(self):
        a, b = self.login_tokens(), self.login_tokens()
        ca, cb = self.bearer(a['access_token']), self.bearer(b['access_token'])
        self.assertEqual(ca.put(B + 'me/push-token/', {'fcm_token': 'tok-1'}, format='json').status_code, 200)
        self.assertEqual(MobileSession.objects.get(pk=a['session_id']).fcm_token, 'tok-1')
        # cùng token đăng ký sang phiên khác -> phiên cũ mất token
        cb.put(B + 'me/push-token/', {'fcm_token': 'tok-1'}, format='json')
        self.assertEqual(MobileSession.objects.get(pk=a['session_id']).fcm_token, '')
        self.assertEqual(MobileSession.objects.get(pk=b['session_id']).fcm_token, 'tok-1')
        self.assertEqual(cb.delete(B + 'me/push-token/').status_code, 204)
        s = MobileSession.objects.get(pk=b['session_id'])
        self.assertEqual((s.fcm_token, s.push_enabled), ('', False))

    def test_push_token_requires_app_session(self):
        r = self.c.put(B + 'me/push-token/', {'fcm_token': 'x'}, format='json')    # cookie session
        self.assertEqual(r.status_code, 400)
        self.assertEqual(r.json()['code'], 'session_required')

    def test_login_with_fcm_token(self):
        body = self.login_tokens(fcm_token='fcm-abc')
        self.assertEqual(MobileSession.objects.get(pk=body['session_id']).fcm_token, 'fcm-abc')

    def test_notification_triggers_push(self):
        with mock.patch('smartlock.push.send_notification_push') as sender:
            with self.captureOnCommitCallbacks(execute=True):
                U.notify(self.owner, 'Pin yếu', 'Còn 5%', severity='warning')
        self.assertEqual(sender.call_count, 1)

    def test_push_is_noop_without_firebase(self):
        from .. import push
        body = self.login_tokens(fcm_token='fcm-abc')
        self.assertTrue(body['session_id'])
        n = self.owner.notification_set.create(type='SYSTEM', title='t', message='m')
        with mock.patch.object(push, '_get_app', return_value=None):
            self.assertEqual(push.send_notification_push(n.pk), 0)

    def test_app_config_is_public(self):
        r = self.anon().get(B + 'app-config/')
        self.assertEqual(r.status_code, 200)
        self.assertIn('server_time', r.json())
        self.assertTrue(r.json()['registration_enabled'])

    def test_sync_bundle(self):
        c = self.bearer(self.login_tokens()['access_token'])
        r = c.get(B + 'sync/')
        self.assertEqual(r.status_code, 200)
        body = r.json()
        for key in ('generated_at', 'unread_count', 'devices', 'notifications', 'recent_logs',
                    'accesses_granted', 'my_accesses', 'announcements'):
            self.assertIn(key, body)
        self.assertEqual([d['id'] for d in body['devices']], [str(self.device.id)])
        self.assertEqual(r['Cache-Control'], 'no-store')

    def test_existing_endpoints_work_with_bearer(self):
        c = self.bearer(self.login_tokens()['access_token'])
        for path in ('devices/', 'dashboard/', 'notifications/', 'access-events/', 'audit-logs/'):
            self.assertEqual(c.get(B + path).status_code, 200, path)


class RegisterAndResetTests(MobileTestCase):
    REG = {'email': 'moi@example.com', 'username': 'nguoimoi', 'full_name': 'Người Mới',
           'password1': PASSWORD, 'password2': PASSWORD}

    def test_register_sends_verification_and_blocks_login_until_verified(self):
        r = self.anon().post(B + 'auth/register/', self.REG, format='json')
        self.assertEqual(r.status_code, 201, r.content)
        self.assertTrue(r.json()['verification_required'])
        self.assertEqual(len(mail.outbox), 1)
        self.assertEqual(self.login('moi@example.com').json()['code'], 'email_unverified')
        User.objects.filter(email='moi@example.com').update(is_active=True, email_verified=True)
        self.assertEqual(self.login('nguoimoi').status_code, 200)

    def test_register_validation(self):
        bad_user = {**self.REG, 'username': 'a@b'}
        self.assertEqual(self.anon().post(B + 'auth/register/', bad_user, format='json').status_code, 400)
        mismatch = {**self.REG, 'password2': 'khac'}
        self.assertEqual(self.anon().post(B + 'auth/register/', mismatch, format='json').status_code, 400)

    def test_register_duplicate_active_email(self):
        dup = {**self.REG, 'email': 'owner@example.com', 'username': 'khac'}
        r = self.anon().post(B + 'auth/register/', dup, format='json')
        self.assertEqual(r.status_code, 409)
        self.assertEqual(r.json()['code'], 'email_exists')

    def test_register_disabled(self):
        st = U.settings()
        st.registration_enabled = False
        st.save()
        r = self.anon().post(B + 'auth/register/', self.REG, format='json')
        self.assertEqual(r.status_code, 403)
        self.assertEqual(r.json()['code'], 'registration_disabled')
        self.assertFalse(self.anon().get(B + 'app-config/').json()['registration_enabled'])

    def test_resend_verification_is_generic(self):
        a = self.anon().post(B + 'auth/resend-verification/', {'email': 'khong-co@example.com'}, format='json')
        self.assertEqual(a.status_code, 200)
        self.assertEqual(len(mail.outbox), 0)

    def test_password_reset_request_is_generic(self):
        unknown = self.anon().post(B + 'auth/password-reset/', {'email': 'ghost@example.com'}, format='json')
        known = self.anon().post(B + 'auth/password-reset/', {'email': 'owner@example.com'}, format='json')
        self.assertEqual(unknown.status_code, 200)
        self.assertEqual(known.status_code, 200)
        self.assertEqual(unknown.json(), known.json())
        self.assertEqual(len(mail.outbox), 1)

    def test_password_reset_confirm(self):
        body = self.login_tokens()
        uid = urlsafe_base64_encode(force_bytes(str(self.owner.pk)))
        token = default_token_generator.make_token(self.owner)
        payload = {'uid': uid, 'token': token, 'new_password1': NEW_PASSWORD, 'new_password2': NEW_PASSWORD}
        r = self.anon().post(B + 'auth/password-reset/confirm/', payload, format='json')
        self.assertEqual(r.status_code, 200, r.content)
        self.assertEqual(self.login().status_code, 400)                      # mật khẩu cũ hết hiệu lực
        self.assertEqual(self.login(password=NEW_PASSWORD).status_code, 200)
        self.assertEqual(self.bearer(body['access_token']).get(B + 'me/').status_code, 401)   # phiên cũ bị huỷ
        # token dùng 1 lần
        r = self.anon().post(B + 'auth/password-reset/confirm/', payload, format='json')
        self.assertEqual(r.status_code, 400)

    def test_password_reset_confirm_bad_token(self):
        uid = urlsafe_base64_encode(force_bytes(str(self.owner.pk)))
        r = self.anon().post(B + 'auth/password-reset/confirm/',
                             {'uid': uid, 'token': 'sai', 'new_password1': NEW_PASSWORD,
                              'new_password2': NEW_PASSWORD}, format='json')
        self.assertEqual(r.status_code, 400)
        self.assertEqual(r.json()['code'], 'invalid_token')


class TwoFactorLoginTests(MobileTestCase):
    def start(self, secret):
        r = self.login()
        self.assertEqual(r.status_code, 200)
        body = r.json()
        self.assertTrue(body['two_factor_required'])
        self.assertNotIn('access_token', body)
        self.assertEqual(body['methods'], ['totp'])
        return body['pending_token']

    def verify(self, pending, code, method='totp', **extra):
        return self.anon().post(B + 'auth/2fa/verify/', {'pending_token': pending, 'method': method,
                                                         'code': code, **extra}, format='json')

    def test_totp_login_success_and_replay_blocked(self):
        secret = self.enable_totp(self.owner)
        code = pyotp.TOTP(secret).now()
        r = self.verify(self.start(secret), code, device_name='Pixel')
        self.assertEqual(r.status_code, 200, r.content)
        self.assertEqual(self.bearer(r.json()['access_token']).get(B + 'me/').status_code, 200)
        # cùng mã TOTP dùng lại (replay) phải bị từ chối
        r = self.verify(self.start(secret), code)
        self.assertEqual(r.status_code, 400)
        self.assertEqual(r.json()['code'], 'invalid_code')

    def test_wrong_code_counts_down_then_kills_pending(self):
        secret = self.enable_totp(self.owner)
        pending = self.start(secret)
        r = self.verify(pending, '000000')
        self.assertEqual((r.status_code, r.json()['attempts_left']), (400, 4))
        with mock.patch('smartlock.api.mobile_auth.MAX_PENDING_FAILS', 2), \
                mock.patch('smartlock.api.auth_views.MAX_PENDING_FAILS', 2):
            r = self.verify(pending, '000000')
        self.assertEqual(r.status_code, 401)
        self.assertEqual(r.json()['code'], 'pending_expired')
        # pending token đã chết, kể cả nhập đúng mã
        self.assertEqual(self.verify(pending, pyotp.TOTP(secret).now()).status_code, 401)

    def test_pending_token_is_single_use(self):
        secret = self.enable_totp(self.owner)
        pending = self.start(secret)
        self.assertEqual(self.verify(pending, pyotp.TOTP(secret).now()).status_code, 200)
        self.assertEqual(self.verify(pending, pyotp.TOTP(secret).now()).status_code, 401)

    def test_garbage_pending_token(self):
        self.assertEqual(self.verify('rác', '123456').status_code, 401)

    def test_method_not_configured(self):
        secret = self.enable_totp(self.owner)
        r = self.verify(self.start(secret), '123456', method='email')
        self.assertEqual(r.status_code, 400)
        self.assertEqual(r.json()['code'], 'invalid_method')

    def test_email_otp_login(self):
        TwoFactorConfig.objects.create(user=self.owner, email_otp_enabled=True, preferred_method='email')
        sync_two_fa_flag(self.owner)
        pending = self.login().json()['pending_token']
        r = self.anon().post(B + 'auth/2fa/email/send/', {'pending_token': pending}, format='json')
        self.assertEqual(r.status_code, 200, r.content)
        self.assertEqual(len(mail.outbox), 1)
        r = self.anon().post(B + 'auth/2fa/email/send/', {'pending_token': pending}, format='json')
        self.assertEqual(r.status_code, 429)                                  # cooldown 60s
        self.assertEqual(r.json()['code'], 'cooldown')

    def test_passkey_only_account_is_rejected_with_clear_code(self):
        Fido2Credential.objects.create(user=self.owner, credential_id='cred-1', public_key=b'k')
        TwoFactorConfig.objects.get_or_create(user=self.owner)
        sync_two_fa_flag(self.owner)
        r = self.login()
        self.assertEqual(r.status_code, 403)
        self.assertEqual(r.json()['code'], 'mobile_2fa_unsupported')


class TwoFactorManageTests(MobileTestCase):
    def setUp(self):
        super().setUp()
        self.mc = self.bearer(self.login_tokens()['access_token'])

    def test_status_defaults(self):
        body = self.mc.get(B + 'me/2fa/').json()
        self.assertFalse(body['enabled'])
        self.assertEqual(body['mobile_supported_methods'], ['totp', 'email'])

    def test_totp_setup_confirm_then_login_requires_2fa_then_disable(self):
        begin = self.mc.post(B + 'me/2fa/totp/begin/').json()
        self.assertTrue(begin['otpauth_uri'].startswith('otpauth://totp/'))
        self.assertEqual(self.mc.post(B + 'me/2fa/totp/begin/').status_code, 200)  # chưa confirm nên bắt đầu lại được
        secret = begin['secret']

        bad = self.mc.post(B + 'me/2fa/totp/confirm/', {'setup_token': begin['setup_token'], 'code': '000000'},
                           format='json')
        self.assertEqual((bad.status_code, bad.json()['code']), (400, 'invalid_code'))

        ok = self.mc.post(B + 'me/2fa/totp/confirm/',
                          {'setup_token': begin['setup_token'], 'code': pyotp.TOTP(secret).now()}, format='json')
        self.assertEqual(ok.status_code, 200, ok.content)
        self.assertTrue(ok.json()['two_fa_enabled'])
        self.assertTrue(self.mc.get(B + 'me/2fa/').json()['totp'])
        self.assertTrue(self.login().json()['two_factor_required'])
        self.assertEqual(self.mc.post(B + 'me/2fa/totp/begin/').status_code, 409)

        # setup_token dùng lại -> hết hiệu lực
        again = self.mc.post(B + 'me/2fa/totp/confirm/',
                             {'setup_token': begin['setup_token'], 'code': pyotp.TOTP(secret).now()}, format='json')
        self.assertEqual(again.status_code, 400)

        # không gỡ được phương thức cuối, phải dùng disable
        r = self.mc.post(B + 'me/2fa/remove/', {'method': 'totp', 'password': PASSWORD}, format='json')
        self.assertEqual((r.status_code, r.json()['code']), (409, 'last_method'))

        # disable: sai mật khẩu / thiếu mã / đúng
        r = self.mc.post(B + 'me/2fa/disable/', {'password': 'sai'}, format='json')
        self.assertEqual(r.json()['code'], 'invalid_password')
        r = self.mc.post(B + 'me/2fa/disable/', {'password': PASSWORD}, format='json')
        self.assertEqual(r.json()['code'], 'code_required')
        next_code = pyotp.TOTP(secret).at(int(time.time()) + 30)              # bước kế tiếp (chống replay)
        r = self.mc.post(B + 'me/2fa/disable/', {'password': PASSWORD, 'method': 'totp', 'code': next_code},
                         format='json')
        self.assertEqual(r.status_code, 200, r.content)
        self.assertFalse(r.json()['two_fa_enabled'])
        self.owner.refresh_from_db()
        self.assertFalse(self.owner.two_fa_enabled)
        self.assertNotIn('two_factor_required', self.login().json())

    def test_email_otp_setup(self):
        r = self.mc.post(B + 'me/2fa/email/send/', {'purpose': 'setup'}, format='json')
        self.assertEqual(r.status_code, 200, r.content)
        self.assertEqual(len(mail.outbox), 1)
        self.assertEqual(self.mc.post(B + 'me/2fa/email/confirm/', {'code': '000000'}, format='json').status_code, 400)
        self.assertFalse(TwoFactorConfig.objects.get(user=self.owner).email_otp_enabled)

    def test_email_verify_purpose_requires_enabled_method(self):
        r = self.mc.post(B + 'me/2fa/email/send/', {'purpose': 'verify'}, format='json')
        self.assertEqual((r.status_code, r.json()['code']), (400, 'method_not_enabled'))

    def test_remove_one_of_two_methods(self):
        secret = self.enable_totp(self.owner)
        cfg = TwoFactorConfig.objects.get(user=self.owner)
        cfg.email_otp_enabled = True
        cfg.save()
        r = self.mc.post(B + 'me/2fa/remove/', {'method': 'email', 'password': PASSWORD}, format='json')
        self.assertEqual(r.status_code, 200, r.content)
        self.assertTrue(r.json()['two_fa_enabled'])
        self.assertTrue(self.mc.get(B + 'me/2fa/').json()['totp'])
        self.assertTrue(secret)

    def test_password_gate_locks_after_5_failures(self):
        self.enable_totp(self.owner)
        cfg = TwoFactorConfig.objects.get(user=self.owner)
        cfg.email_otp_enabled = True
        cfg.save()
        for _ in range(5):
            self.mc.post(B + 'me/2fa/remove/', {'method': 'email', 'password': 'sai'}, format='json')
        r = self.mc.post(B + 'me/2fa/remove/', {'method': 'email', 'password': PASSWORD}, format='json')
        self.assertEqual(r.status_code, 429)