# smartlock/api/auth_views.py
"""
API xác thực + tài khoản cho app Android (Bearer token). Tái dùng đúng nghiệp vụ của views.py (web):
khoá tạm theo bậc, chặn IP, chặn tài khoản admin ở cổng user, 2FA TOTP/Email OTP, audit, thông báo.

Quy ước lỗi: {"detail": "...", "code": "machine_readable"} (+ field khác nếu có) hoặc {"field": ["..."]} khi validate.
Sai tài khoản/mật khẩu trả 400 (không phải 401) để interceptor refresh-token của app không nhầm với hết hạn phiên.

Passkey/WebAuthn KHÔNG hỗ trợ đăng nhập trên app ở bản này (cần Digital Asset Links + Credential Manager);
tài khoản chỉ có passkey sẽ nhận code=mobile_2fa_unsupported.
"""
import hmac
import math
import secrets
from datetime import timedelta

import pyotp
from django.contrib.auth import authenticate
from django.contrib.auth.password_validation import validate_password
from django.contrib.auth.tokens import default_token_generator
from django.conf import settings as dj_settings
from django.core import signing
from django.core.cache import cache
from django.core.exceptions import ValidationError as DjangoValidationError
from django.db import IntegrityError, transaction
from django.urls import reverse
from django.utils import timezone
from django.utils.encoding import force_bytes, force_str
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
from rest_framework import status
from rest_framework.exceptions import ValidationError
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework.throttling import ScopedRateThrottle
from rest_framework.views import APIView

from .. import views as web                     
from ..email_templates import render_email
from ..models import (
    AuditLog, Fido2Credential, MobileSession, OneTimeCode, TwoFactorConfig, User, fernet,
    sync_two_fa_flag,
)
from ..utils import SmartlockUtils as U
from . import auth_serializers as AS
from . import serializers as S
from .common import secret_response
from .mobile_auth import (
    MAX_PENDING_FAILS, claim_fcm_token, issue_session, kill_pending, make_pending_token,
    pending_fail_count, read_pending_token, revoke_user_sessions, rotate_refresh, user_allowed,
)
from .views import ChangePasswordView as _WebChangePasswordView

MOBILE_METHODS = ('totp', 'email')
TOTP_SETUP_SALT = 'smartlock.mobile.totp-setup.v1'
PENDING_TTL = 10 * 60


# ------------------------------------------------------------------ helpers
def err(detail, code, http=status.HTTP_400_BAD_REQUEST, **extra):
    return Response({'detail': detail, 'code': code, **extra}, status=http)


def _valid(serializer_cls, request):
    s = serializer_cls(data=request.data)
    s.is_valid(raise_exception=True)
    return s.validated_data


def _client_info(d):
    return dict(device_name=d.get('device_name', ''), platform=d.get('platform', 'android'),
                app_version=d.get('app_version', ''), fcm_token=d.get('fcm_token', ''))


def _mobile_methods(cfg):
    return [m for m in cfg.available_methods() if m in MOBILE_METHODS]


def _finish_login(request, user, d, two_factor=None):
    U.reset_lockout(user)
    session, payload = issue_session(request, user, **_client_info(d))
    meta = {'client': 'mobile', 'session_id': str(session.id), 'platform': session.platform}
    if two_factor:
        meta['two_factor'] = two_factor
    U.audit(request, 'LOGIN', actor=user, metadata=meta)
    return secret_response({**payload, 'user': S.MeSerializer(user).data})


def _password_gate(request, password):
    """Bắt nhập lại mật khẩu cho thao tác nhạy cảm (tối đa 5 lần sai / 15 phút). None = qua."""
    user = request.user
    recent = AuditLog.objects.filter(
        action='TWO_FACTOR_PASSWORD_FAILED', actor_user=user,
        created_at__gte=timezone.now() - timedelta(minutes=15)).count()
    if recent >= 5:
        return err('Nhập sai mật khẩu quá nhiều lần. Thử lại sau 15 phút.', 'too_many_attempts',
                   status.HTTP_429_TOO_MANY_REQUESTS)
    if not user.check_password(password):
        U.audit(request, 'TWO_FACTOR_PASSWORD_FAILED', success=False, severity='warning', target_user=user)
        return err('Mật khẩu không đúng.', 'invalid_password')
    return None


def _email_send_result(request, user, res, purpose):
    U.audit(request, 'TWO_FACTOR_EMAIL_SENT', actor=None if not request.user.is_authenticated else request.user,
            target_user=user, success=(res == 'sent'), metadata={'purpose': purpose, 'client': 'mobile'})
    if res == 'sent':
        return Response({'detail': f'Đã gửi mã đến {web._mask_email(user.email)}.',
                         'email_masked': web._mask_email(user.email), 'expires_in': web.EMAIL_CODE_TTL_MIN * 60})
    if res == 'cooldown':
        return err(f'Vui lòng đợi {web.EMAIL_CODE_COOLDOWN} giây trước khi gửi lại.', 'cooldown',
                   status.HTTP_429_TOO_MANY_REQUESTS, retry_after_seconds=web.EMAIL_CODE_COOLDOWN)
    return err('Không gửi được email. Vui lòng thử lại sau.', 'email_failed', status.HTTP_502_BAD_GATEWAY)


class _Anon(APIView):
    authentication_classes = []
    permission_classes = [AllowAny]
    throttle_classes = [ScopedRateThrottle]

    def get_authenticate_header(self, request):
        # Không có authenticator nào -> DRF sẽ đổi 401 thành 403; ép về 401 cho pending/refresh token sai.
        return 'Bearer realm="smartlock"'


# ====================== ĐĂNG KÝ / XÁC THỰC EMAIL ======================
class RegisterView(_Anon):
    throttle_scope = 'auth_register'

    def post(self, request):
        if not U.settings().registration_enabled:
            return err('Hệ thống đang tạm đóng đăng ký.', 'registration_disabled', status.HTTP_403_FORBIDDEN)
        d = _valid(AS.RegisterSerializer, request)
        email, username = d['email'].strip(), d['username'].strip()
        full_name = (d.get('full_name') or '').strip()

        if '@' in username:
            raise ValidationError({'username': ['Tên đăng nhập không được chứa ký tự @.']})
        if d['password1'] != d['password2']:
            raise ValidationError({'password2': ['Mật khẩu không khớp.']})
        try:
            validate_password(d['password1'])
        except DjangoValidationError as e:
            raise ValidationError({'password1': list(e.messages)})

        existing = User.objects.filter(email__iexact=email).first()
        if User.objects.filter(username__iexact=username).exclude(
                pk=existing.pk if existing else None).exists():
            raise ValidationError({'username': ['Tên đăng nhập đã được sử dụng.']})

        if existing:
            if existing.is_active or existing.email_verified:
                U.audit(request, 'REGISTER_DUPLICATE_ACTIVE', actor=None, target_user=existing,
                        success=False, severity='warning', username_attempt=email[:150])
                return err('Email này đã có tài khoản. Hãy đăng nhập hoặc dùng "Quên mật khẩu".',
                           'email_exists', status.HTTP_409_CONFLICT)
            # Đăng ký dở dang (chưa xác thực): gửi lại email xác thực thay vì để người dùng kẹt.
            recent = OneTimeCode.objects.filter(
                user=existing, purpose='EMAIL_VERIFY',
                created_at__gt=timezone.now() - timedelta(seconds=60)).exists()
            sent = None
            if not recent:
                sent = U.send_verification(request, existing)
                U.audit(request, 'VERIFY_MAIL_RESENT', actor=None, target_user=existing, success=sent,
                        metadata={'reason': 'duplicate_register_unverified'})
            return Response({'detail': 'Email này đã đăng ký nhưng chưa xác thực. Đã gửi lại email xác thực, '
                                       'vui lòng kiểm tra hộp thư (kể cả mục Spam).',
                             'verification_required': True, 'email': email,
                             'verification_email_sent': sent})

        try:
            with transaction.atomic():
                user = User.objects.create_user(email=email, username=username, password=d['password1'],
                                                full_name=full_name or None)
        except DjangoValidationError as e:
            U.audit(request, 'REGISTER_FAILED', actor=None, success=False, username_attempt=email[:150],
                    metadata={'reason': 'validation'})
            raise ValidationError({'detail': list(e.messages)})
        except IntegrityError:
            U.audit(request, 'REGISTER_FAILED', actor=None, success=False, username_attempt=email[:150],
                    metadata={'reason': 'duplicate'})
            return err('Email hoặc tên đăng nhập đã được sử dụng.', 'duplicate', status.HTTP_409_CONFLICT)

        U.audit(request, 'REGISTER', actor=user, target_user=user, metadata={'client': 'mobile'})
        sent = U.send_verification(request, user)
        if not sent:
            U.audit(request, 'VERIFY_MAIL_FAILED', actor=user, target_user=user, success=False, severity='warning')
        return Response({'detail': 'Đã tạo tài khoản. Vui lòng xác thực email để kích hoạt.',
                         'verification_required': True, 'email': email, 'verification_email_sent': sent},
                        status=status.HTTP_201_CREATED)


class ResendVerificationView(_Anon):
    throttle_scope = 'auth_register'

    def post(self, request):
        email = _valid(AS.EmailOnlySerializer, request)['email'].strip()
        user = User.objects.filter(email__iexact=email, is_active=False, email_verified=False).first()
        if user:
            recent = OneTimeCode.objects.filter(
                user=user, purpose='EMAIL_VERIFY',
                created_at__gt=timezone.now() - timedelta(seconds=60)).exists()
            if recent:
                return err('Vui lòng đợi 60 giây trước khi gửi lại.', 'cooldown',
                           status.HTTP_429_TOO_MANY_REQUESTS, retry_after_seconds=60)
            sent = U.send_verification(request, user)
            U.audit(request, 'VERIFY_MAIL_RESENT', actor=None, target_user=user, success=sent)
            if not sent:
                return err('Không gửi được email. Vui lòng thử lại sau.', 'email_failed',
                           status.HTTP_502_BAD_GATEWAY)
        # Luôn trả cùng 1 kết quả để không lộ email nào đã đăng ký.
        return Response({'detail': 'Nếu tài khoản cần xác thực, email đã được gửi lại.'})


# ====================== ĐĂNG NHẬP / 2FA / TOKEN ======================
class LoginView(_Anon):
    """POST {identifier, password, [device_name, platform, app_version, fcm_token]}
    -> 200 {access_token, refresh_token, expires_in, user}
    -> 200 {two_factor_required: true, pending_token, methods[], ...}  (rồi gọi auth/2fa/verify/)"""
    throttle_scope = 'auth_login'

    def post(self, request):
        d = _valid(AS.LoginSerializer, request)
        identifier, password = d['identifier'].strip(), d['password']
        ip = U.client_ip(request)

        if U.ip_blacklisted(ip):
            U.audit(request, 'LOGIN_BLOCKED_IP', actor=None, success=False, severity='warning',
                    username_attempt=identifier[:150])
            return err('Địa chỉ IP của bạn đã bị chặn.', 'ip_blocked', status.HTTP_403_FORBIDDEN)

        user = U.find_user(identifier)
        now = timezone.now()
        if user and user.login_locked_until and user.login_locked_until > now:
            minutes = math.ceil((user.login_locked_until - now).total_seconds() / 60)
            U.audit(request, 'LOGIN_LOCKED', actor=None, success=False, severity='warning',
                    target_user=user, username_attempt=identifier[:150])
            return err(f'Tài khoản đang bị khóa tạm thời. Thử lại sau {minutes} phút.', 'account_locked',
                       status.HTTP_429_TOO_MANY_REQUESTS, retry_after_minutes=minutes)

        auth_user = authenticate(request._request, username=user.email, password=password) if user else None

        if auth_user and U.is_admin(auth_user):      # admin chỉ đăng nhập ở cổng manage_sys
            U.audit(request, 'LOGIN_ADMIN_REJECTED', actor=None, success=False, severity='warning',
                    target_user=user, username_attempt=identifier[:150])
            return err('Email/Username hoặc mật khẩu không đúng.', 'invalid_credentials')

        if auth_user:
            if auth_user.two_fa_enabled:
                cfg = web._get_cfg(auth_user)
                methods = _mobile_methods(cfg)
                if not methods:
                    U.audit(request, 'LOGIN_2FA_UNSUPPORTED', actor=None, target_user=auth_user,
                            success=False, severity='warning', metadata={'client': 'mobile'})
                    return err('Tài khoản chỉ dùng Passkey cho 2FA, app chưa hỗ trợ. Hãy thêm Google '
                               'Authenticator hoặc Email OTP trên web rồi đăng nhập lại.',
                               'mobile_2fa_unsupported', status.HTTP_403_FORBIDDEN)
                U.audit(request, 'LOGIN_2FA_REQUIRED', actor=None, target_user=auth_user,
                        metadata={'client': 'mobile'})
                preferred = cfg.preferred_method if cfg.preferred_method in methods else methods[0]
                return secret_response({
                    'two_factor_required': True, 'pending_token': make_pending_token(auth_user),
                    'methods': methods, 'preferred_method': preferred,
                    'email_masked': web._mask_email(auth_user.email), 'expires_in': PENDING_TTL,
                })
            return _finish_login(request, auth_user, d)

        if user and not user.is_active and user.check_password(password):
            return err('Tài khoản chưa được kích hoạt. Vui lòng xác thực email.', 'email_unverified',
                       status.HTTP_403_FORBIDDEN, email=user.email)
        if user:
            locked = U.register_failure(user, ip)
            if locked:
                U.audit(request, 'ACCOUNT_LOCKED', actor=None, success=False, severity='critical',
                        target_user=user, username_attempt=identifier[:150],
                        metadata={'locked_minutes': locked})
        U.audit(request, 'LOGIN_FAILED', actor=None, success=False, severity='warning',
                target_user=user, username_attempt=identifier[:150])
        return err('Email/Username hoặc mật khẩu không đúng.', 'invalid_credentials')


class TwoFactorVerifyView(_Anon):
    """POST {pending_token, method: totp|email, code, [device_name, platform, app_version, fcm_token]}."""
    throttle_scope = 'auth_2fa'

    def post(self, request):
        d = _valid(AS.TwoFactorVerifySerializer, request)
        user, jti = read_pending_token(d['pending_token'])

        minutes = web._lock_minutes(user)
        if minutes:
            kill_pending(jti)
            return err(f'Tài khoản đang bị khóa tạm thời. Thử lại sau {minutes} phút.', 'account_locked',
                       status.HTTP_429_TOO_MANY_REQUESTS, retry_after_minutes=minutes)

        cfg = web._get_cfg(user)
        method = d['method']
        if method not in _mobile_methods(cfg):
            return err('Phương thức không hợp lệ.', 'invalid_method')

        ok = (web._verify_totp(cfg, d['code']) if method == 'totp'
              else web._verify_email_code(user, d['code'], 'VERIFY'))
        if ok:
            kill_pending(jti)
            return _finish_login(request, user, d, two_factor=method)

        fails = pending_fail_count(jti)
        locked = U.register_failure(user, U.client_ip(request))
        U.audit(request, 'TWO_FACTOR_FAILED', actor=None, target_user=user, success=False, severity='warning',
                metadata={'method': method, 'purpose': 'login', 'locked_minutes': locked, 'client': 'mobile'})
        if locked:
            kill_pending(jti)
            U.audit(request, 'ACCOUNT_LOCKED', actor=None, success=False, severity='critical',
                    target_user=user, metadata={'locked_minutes': locked, 'stage': '2fa'})
            return err(f'Sai quá nhiều lần. Tài khoản bị khóa {locked} phút.', 'account_locked',
                       status.HTTP_429_TOO_MANY_REQUESTS, retry_after_minutes=locked)
        if fails >= MAX_PENDING_FAILS:
            kill_pending(jti)
            return err('Sai quá nhiều lần. Vui lòng đăng nhập lại từ đầu.', 'pending_expired',
                       status.HTTP_401_UNAUTHORIZED)
        return err('Mã xác thực không đúng hoặc đã hết hạn.', 'invalid_code',
                   attempts_left=MAX_PENDING_FAILS - fails)


class TwoFactorLoginEmailSendView(_Anon):
    """POST {pending_token}: gửi mã Email OTP cho bước 2 khi đăng nhập."""
    throttle_scope = 'auth_2fa'

    def post(self, request):
        user, _jti = read_pending_token(_valid(AS.PendingTokenSerializer, request)['pending_token'])
        if not web._get_cfg(user).email_otp_enabled:
            return err('Email OTP chưa được bật cho tài khoản này.', 'method_not_enabled')
        res = web._send_email_code(user, 'VERIFY')
        return _email_send_result(request, user, res, 'login')


class RefreshView(_Anon):
    """POST {refresh_token} -> cặp token mới (refresh token cũ hết tác dụng). Các lệnh refresh phải
    được app xếp hàng tuần tự: gửi song song 2 lệnh với cùng 1 token sẽ bị coi là dùng lại token."""
    throttle_scope = 'auth_refresh'

    def post(self, request):
        _session, payload = rotate_refresh(_valid(AS.RefreshSerializer, request)['refresh_token'])
        return secret_response(payload)


class LogoutView(APIView):
    def post(self, request):
        session = request.auth if isinstance(request.auth, MobileSession) else None
        if session:
            session.revoke()
        U.audit(request, 'LOGOUT', metadata={'client': 'mobile'})
        return Response(status=status.HTTP_204_NO_CONTENT)


class LogoutAllView(APIView):
    def post(self, request):
        n = revoke_user_sessions(request.user)
        U.audit(request, 'LOGOUT_ALL', severity='warning', metadata={'revoked': n, 'client': 'mobile'})
        return Response({'revoked': n})


def _session_dict(s, current_id):
    return {
        'id': str(s.id), 'device_name': s.device_name, 'platform': s.platform, 'app_version': s.app_version,
        'ip_address': s.ip_address, 'created_at': s.created_at, 'last_used_at': s.last_used_at,
        'expires_at': s.expires_at, 'current': s.id == current_id,
        'push_enabled': bool(s.push_enabled and s.fcm_token),
    }


class SessionListView(APIView):
    """Các máy đang đăng nhập tài khoản này."""
    def get(self, request):
        current = request.auth.id if isinstance(request.auth, MobileSession) else None
        qs = MobileSession.objects.filter(user=request.user, revoked_at__isnull=True,
                                          expires_at__gt=timezone.now()).order_by('-last_used_at')
        return Response([_session_dict(s, current) for s in qs])


class SessionDetailView(APIView):
    def delete(self, request, session_id):
        s = MobileSession.objects.filter(pk=session_id, user=request.user, revoked_at__isnull=True).first()
        if not s:
            return err('Không tìm thấy phiên đăng nhập.', 'not_found', status.HTTP_404_NOT_FOUND)
        s.revoke()
        U.audit(request, 'MOBILE_SESSION_REVOKED', severity='warning',
                metadata={'session_id': str(s.id), 'device_name': s.device_name})
        return Response(status=status.HTTP_204_NO_CONTENT)


# ====================== QUÊN / ĐỔI MẬT KHẨU ======================
class PasswordResetRequestView(_Anon):
    """POST {email}. Luôn trả cùng 1 thông điệp (không lộ email nào có tài khoản)."""
    throttle_scope = 'auth_reset'
    GENERIC = {'detail': 'Nếu email có tài khoản đã xác thực, chúng tôi đã gửi hướng dẫn đặt lại mật khẩu.'}

    def post(self, request):
        email = _valid(AS.EmailOnlySerializer, request)['email'].strip()
        user = User.objects.filter(email__iexact=email).first()
        if not user:
            U.audit(request, 'PASSWORD_RESET_UNKNOWN_EMAIL', actor=None, success=False, severity='warning',
                    username_attempt=email[:150])
            return Response(self.GENERIC)
        if not user.is_active or not user.email_verified or U.is_admin(user):
            U.audit(request, 'PASSWORD_RESET_UNVERIFIED', actor=None, success=False, severity='warning',
                    target_user=user)
            return Response(self.GENERIC)
        if AuditLog.objects.filter(action='PASSWORD_RESET_REQUEST', target_user=user,
                                   created_at__gte=timezone.now() - timedelta(seconds=60)).exists():
            U.audit(request, 'PASSWORD_RESET_THROTTLED', actor=None, success=False, target_user=user)
            return Response(self.GENERIC)

        link = request.build_absolute_uri(reverse('smartlock:reset_password_confirm', args=[
            force_str(urlsafe_base64_encode(force_bytes(str(user.pk)))),
            default_token_generator.make_token(user)]))
        subject, html, plain = render_email('password_reset.html', {
            'full_name': user.full_name or user.username, 'password_reset_link': link, 'reset_link': link,
            'expiry_minutes': dj_settings.PASSWORD_RESET_TIMEOUT // 60})
        sent = U.send_mail(subject, plain, html, user.email)
        U.audit(request, 'PASSWORD_RESET_REQUEST', actor=None, target_user=user, success=sent,
                severity='info' if sent else 'warning', metadata={'client': 'mobile'})
        return Response(self.GENERIC)


class PasswordResetConfirmView(_Anon):
    """POST {uid, token, new_password1, new_password2} - dùng khi app bắt được link đặt lại mật khẩu
    (App Links: https://<host>/reset-password/<uid>/<token>/). Không dùng app link thì người dùng đặt lại trên trang web."""
    throttle_scope = 'auth_reset'

    def post(self, request):
        d = _valid(AS.PasswordResetConfirmSerializer, request)
        try:
            user = User.objects.get(pk=force_str(urlsafe_base64_decode(d['uid'])))
        except Exception:
            user = None
        if (user is None or not user_allowed(user)
                or not default_token_generator.check_token(user, d['token'])):
            U.audit(request, 'PASSWORD_RESET_INVALID', actor=None, success=False, severity='warning',
                    target_user=user)
            return err('Liên kết đặt lại mật khẩu không hợp lệ hoặc đã hết hạn.', 'invalid_token')
        if d['new_password1'] != d['new_password2']:
            raise ValidationError({'new_password2': ['Mật khẩu mới không khớp.']})
        try:
            validate_password(d['new_password1'], user)
        except DjangoValidationError as e:
            raise ValidationError({'new_password1': list(e.messages)})
        user.set_password(d['new_password1'])
        user.save()
        U.reset_lockout(user)
        revoke_user_sessions(user)
        U.audit(request, 'PASSWORD_RESET_DONE', actor=user, target_user=user, metadata={'client': 'mobile'})
        U.notify(user, 'Mật khẩu đã thay đổi', 'Mật khẩu tài khoản vừa được đặt lại.',
                 severity='warning', type_='SECURITY')
        return Response({'detail': 'Mật khẩu đã được thay đổi. Hãy đăng nhập lại.'})


class ChangePasswordView(_WebChangePasswordView):
    """Như view web + thu hồi mọi phiên app khác (phiên hiện tại được giữ)."""
    def post(self, request):
        response = super().post(request)
        if response.status_code == 200:
            keep = request.auth if isinstance(request.auth, MobileSession) else None
            revoke_user_sessions(request.user, except_session=keep)
        return response


# ====================== PUSH TOKEN ======================
class PushTokenView(APIView):
    """PUT {fcm_token, enabled} đăng ký/cập nhật token FCM của máy này (gọi lại mỗi khi FCM cấp token mới).
    DELETE: tắt push cho máy này."""
    @staticmethod
    def _session(request):
        return request.auth if isinstance(request.auth, MobileSession) else None

    def put(self, request):
        session = self._session(request)
        if not session:
            return err('Chỉ dùng được với phiên đăng nhập của app.', 'session_required')
        d = _valid(AS.PushTokenSerializer, request)
        claim_fcm_token(session, d['fcm_token'], d['enabled'])
        return Response({'detail': 'Đã cập nhật token thông báo.', 'push_enabled': session.push_enabled})

    def delete(self, request):
        session = self._session(request)
        if session:
            claim_fcm_token(session, '', False)
        return Response(status=status.HTTP_204_NO_CONTENT)


# ====================== QUẢN LÝ 2FA ======================
def _after_added(request, user, method):
    U.audit(request, 'TWO_FACTOR_METHOD_ADDED', target_user=user, severity='warning',
            metadata={'method': method, 'client': 'mobile'})
    U.notify(user, 'Đã thêm phương thức 2FA', f'Phương thức {method.upper()} vừa được thêm vào tài khoản.',
             type_='SECURITY')
    cfg = web._get_cfg(user)
    was = user.two_fa_enabled
    now_enabled = sync_two_fa_flag(user)
    auto = now_enabled and not was
    if auto:      # phương thức đầu tiên được xác nhận -> tự bật 2FA (giống web)
        cfg.enabled_at = timezone.now()
        cfg.save(update_fields=['enabled_at', 'updated_at'])
        U.audit(request, 'TWO_FACTOR_ENABLED', target_user=user, severity='warning',
                metadata={'method': method, 'auto': True})
    return auto


def _after_removed(request, user, method):
    cfg = web._get_cfg(user)
    left = cfg.available_methods()
    if cfg.preferred_method not in left:
        cfg.preferred_method = left[0] if left else ''
    cfg.save()
    sync_two_fa_flag(user)
    U.audit(request, 'TWO_FACTOR_METHOD_REMOVED', target_user=user, severity='warning',
            metadata={'method': method, 'client': 'mobile'})
    U.notify(user, 'Đã gỡ phương thức 2FA', f'Phương thức {method.upper()} vừa được gỡ khỏi tài khoản.',
             severity='warning', type_='SECURITY')


class TwoFactorStatusView(APIView):
    def get(self, request):
        user = request.user
        cfg = TwoFactorConfig.objects.filter(user=user).first()
        passkeys = Fido2Credential.objects.filter(user=user).order_by('created_at')
        return Response({
            'enabled': user.two_fa_enabled,
            'totp': bool(cfg and cfg.totp_confirmed),
            'email': bool(cfg and cfg.email_otp_enabled),
            'passkeys': [{'id': str(p.id), 'name': p.name, 'created_at': p.created_at,
                          'last_used_at': p.last_used_at} for p in passkeys],
            'preferred_method': cfg.preferred_method if cfg else '',
            'email_masked': web._mask_email(user.email), 'email_verified': user.email_verified,
            'mobile_supported_methods': list(MOBILE_METHODS),
        })


class TotpBeginView(APIView):
    """Bắt đầu thiết lập Google Authenticator. Trả secret + otpauth_uri (app tự vẽ QR) + setup_token."""
    def post(self, request):
        user = request.user
        if web._get_cfg(user).totp_confirmed:
            return err('Google Authenticator đã được thiết lập. Hãy gỡ trước nếu muốn cài lại.',
                       'already_configured', status.HTTP_409_CONFLICT)
        secret = pyotp.random_base32()
        token = signing.dumps({'uid': str(user.pk), 's': fernet.encrypt(secret.encode()).decode(),
                               'jti': secrets.token_urlsafe(9)}, salt=TOTP_SETUP_SALT, compress=False)
        return secret_response({
            'setup_token': token, 'secret': secret,
            'otpauth_uri': pyotp.TOTP(secret).provisioning_uri(name=user.email, issuer_name=web.TOTP_ISSUER),
            'issuer': web.TOTP_ISSUER, 'expires_in': web.SETUP_TTL,
        })


class TotpConfirmView(APIView):
    """POST {setup_token, code}: nhập mã 6 số đầu tiên từ Authenticator để hoàn tất."""
    def post(self, request):
        user = request.user
        d = _valid(AS.TotpConfirmSerializer, request)
        expired = err('Phiên thiết lập đã hết hạn. Hãy bắt đầu lại.', 'setup_expired')
        try:
            data = signing.loads(d['setup_token'], salt=TOTP_SETUP_SALT, max_age=web.SETUP_TTL)
        except signing.BadSignature:
            return expired
        jti = data['jti']
        tries_key, dead_key = f'mobtotp_tries:{jti}', f'mobtotp_dead:{jti}'
        if data['uid'] != str(user.pk) or cache.get(dead_key):
            return expired
        try:
            secret = fernet.decrypt(data['s'].encode()).decode()
        except Exception:
            return expired

        code = web._digits(d['code'])
        totp = pyotp.TOTP(secret)
        step_now = int(timezone.now().timestamp() // totp.interval)
        matched = next((step_now + o for o in (-1, 0, 1)
                        if len(code) == 6 and hmac.compare_digest(
                            totp.at((step_now + o) * totp.interval), code)), None)
        if matched is None:
            cache.add(tries_key, 0, web.SETUP_TTL)
            tries = cache.incr(tries_key)
            if tries >= 5:
                cache.set(dead_key, 1, web.SETUP_TTL)
                return err('Sai quá nhiều lần. Hãy bắt đầu thiết lập lại.', 'setup_expired')
            return err('Mã không đúng. Kiểm tra lại giờ trên điện thoại và thử lại.', 'invalid_code',
                       attempts_left=5 - tries)

        with transaction.atomic():
            cfg = TwoFactorConfig.objects.select_for_update().get_or_create(user=user)[0]
            if cfg.totp_confirmed:
                return err('Google Authenticator đã được thiết lập.', 'already_configured',
                           status.HTTP_409_CONFLICT)
            cfg.set_totp_secret(secret)
            cfg.totp_confirmed = True
            cfg.totp_last_step = matched
            if not cfg.preferred_method:
                cfg.preferred_method = TwoFactorConfig.METHOD_TOTP
            cfg.save()
        cache.set(dead_key, 1, web.SETUP_TTL)
        auto = _after_added(request, user, 'totp')
        return Response({'detail': 'Đã thiết lập Google Authenticator.', 'two_fa_enabled': user.two_fa_enabled,
                         'auto_enabled': auto})


class EmailOtpSendView(APIView):
    """POST {purpose: setup|verify}. setup = thiết lập Email OTP; verify = mã xác nhận thao tác nhạy cảm (vd. tắt 2FA)."""
    throttle_classes = [ScopedRateThrottle]
    throttle_scope = 'auth_2fa'

    def post(self, request):
        user = request.user
        purpose = 'SETUP' if _valid(AS.EmailSendSerializer, request)['purpose'] == 'setup' else 'VERIFY'
        if purpose == 'SETUP' and not user.email_verified:
            return err('Email chưa được xác thực.', 'email_unverified', status.HTTP_403_FORBIDDEN)
        if purpose == 'VERIFY' and not web._get_cfg(user).email_otp_enabled:
            return err('Email OTP chưa được bật.', 'method_not_enabled')
        return _email_send_result(request, user, web._send_email_code(user, purpose), purpose.lower())


class EmailOtpConfirmView(APIView):
    """POST {code}: xác nhận mã đã gửi bởi email/send (purpose=setup) để bật Email OTP."""
    throttle_classes = [ScopedRateThrottle]
    throttle_scope = 'auth_2fa'

    def post(self, request):
        user = request.user
        code = _valid(AS.CodeSerializer, request)['code']
        if not web._verify_email_code(user, code, 'SETUP'):
            return err('Mã không đúng hoặc đã hết hạn.', 'invalid_code')
        with transaction.atomic():
            cfg = TwoFactorConfig.objects.select_for_update().get_or_create(user=user)[0]
            cfg.email_otp_enabled = True
            if not cfg.preferred_method:
                cfg.preferred_method = TwoFactorConfig.METHOD_EMAIL
            cfg.save()
        auto = _after_added(request, user, 'email')
        return Response({'detail': 'Đã bật Email OTP.', 'two_fa_enabled': user.two_fa_enabled,
                         'auto_enabled': auto})


class RemoveMethodView(APIView):
    """POST {method: totp|email, password}. Không gỡ được phương thức cuối khi 2FA đang bật -> dùng me/2fa/disable/."""
    def post(self, request):
        user = request.user
        d = _valid(AS.RemoveMethodSerializer, request)
        method, cfg = d['method'], web._get_cfg(user)
        active = cfg.totp_confirmed if method == 'totp' else cfg.email_otp_enabled
        if not active:
            return err('Phương thức này chưa được thiết lập.', 'method_not_enabled')
        if user.two_fa_enabled and cfg.available_methods() == [method]:
            return err('Đây là phương thức cuối cùng. Hãy dùng "Tắt 2FA" để gỡ hoàn toàn.', 'last_method',
                       status.HTTP_409_CONFLICT)
        bad = _password_gate(request, d['password'])
        if bad:
            return bad
        if method == 'totp':
            cfg.totp_secret_encrypted, cfg.totp_confirmed, cfg.totp_last_step = '', False, 0
        else:
            cfg.email_otp_enabled = False
        cfg.save()
        _after_removed(request, user, method)
        return Response({'detail': 'Đã gỡ phương thức xác thực.', 'two_fa_enabled': user.two_fa_enabled})


class PasskeyDeleteView(APIView):
    """POST {password}: xoá 1 passkey (đăng ký passkey vẫn làm trên web)."""
    def post(self, request, cred_id):
        user = request.user
        password = _valid(AS.PasswordSerializer, request)['password']
        cred = Fido2Credential.objects.filter(pk=cred_id, user=user).first()
        if not cred:
            return err('Không tìm thấy passkey.', 'not_found', status.HTTP_404_NOT_FOUND)
        cfg = web._get_cfg(user)
        if user.two_fa_enabled and len(cfg.available_methods()) == 1 and user.fido2_credentials.count() == 1:
            return err('Đây là phương thức cuối cùng. Hãy dùng "Tắt 2FA" để gỡ hoàn toàn.', 'last_method',
                       status.HTTP_409_CONFLICT)
        bad = _password_gate(request, password)
        if bad:
            return bad
        cred.delete()
        _after_removed(request, user, 'fido2')
        return Response({'detail': 'Đã gỡ passkey.', 'two_fa_enabled': user.two_fa_enabled})


class DisableTwoFactorView(APIView):
    """POST {password, [method, code]}: tắt HẲN 2FA (gỡ TOTP, Email OTP và mọi passkey).
    Cần mật khẩu + 1 mã 2FA hiện hành (totp|email; với email hãy gọi me/2fa/email/send/ purpose=verify trước).
    Tài khoản chỉ có passkey (không thể nhập mã trên app) chỉ cần mật khẩu."""
    def post(self, request):
        user = request.user
        d = _valid(AS.DisableTwoFactorSerializer, request)
        if not user.two_fa_enabled:
            return err('2FA chưa được bật.', 'not_enabled', status.HTTP_409_CONFLICT)
        bad = _password_gate(request, d['password'])
        if bad:
            return bad

        cfg = web._get_cfg(user)
        usable = _mobile_methods(cfg)
        if usable:
            fails = AuditLog.objects.filter(
                action='TWO_FACTOR_DISABLE_FAILED', actor_user=user,
                created_at__gte=timezone.now() - timedelta(minutes=15)).count()
            if fails >= 5:
                return err('Nhập sai mã quá nhiều lần. Thử lại sau 15 phút.', 'too_many_attempts',
                           status.HTTP_429_TOO_MANY_REQUESTS)
            method, code = d.get('method'), d.get('code') or ''
            if method not in usable or not code:
                return err('Cần nhập mã xác thực 2 lớp hiện tại.', 'code_required',
                           methods=usable)
            ok = (web._verify_totp(cfg, code) if method == 'totp'
                  else web._verify_email_code(user, code, 'VERIFY'))
            if not ok:
                U.audit(request, 'TWO_FACTOR_DISABLE_FAILED', success=False, severity='warning',
                        target_user=user, metadata={'method': method})
                return err('Mã xác thực không đúng hoặc đã hết hạn.', 'invalid_code')

        with transaction.atomic():
            cfg.totp_secret_encrypted, cfg.totp_confirmed, cfg.totp_last_step = '', False, 0
            cfg.email_otp_enabled = False
            cfg.preferred_method = ''
            cfg.enabled_at = None
            cfg.save()
            Fido2Credential.objects.filter(user=user).delete()
        sync_two_fa_flag(user)
        U.audit(request, 'TWO_FACTOR_DISABLED', target_user=user, severity='critical',
                metadata={'client': 'mobile'})
        U.notify(user, 'Đã tắt xác thực 2 lớp', 'Xác thực 2 lớp của tài khoản vừa bị tắt.',
                 severity='critical', type_='SECURITY')
        return Response({'detail': 'Đã tắt xác thực 2 lớp.', 'two_fa_enabled': user.two_fa_enabled})