# smartlock/api/auth_views.py
"""Đăng ký / đăng nhập (kèm 2FA TOTP + Email OTP) / refresh / đăng xuất / quên mật khẩu cho app."""
import logging
import math
from datetime import timedelta

from django.conf import settings as dj_settings
from django.contrib.auth import authenticate
from django.contrib.auth.password_validation import validate_password
from django.contrib.auth.tokens import default_token_generator
from django.core import signing
from django.core.exceptions import ValidationError as DjangoValidationError
from django.db import IntegrityError, transaction
from django.urls import reverse
from django.utils import timezone
from django.utils.encoding import force_bytes, force_str
from django.utils.http import urlsafe_base64_encode
from rest_framework import status
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework.throttling import ScopedRateThrottle
from rest_framework.views import APIView

from ..email_templates import render_email
from ..models import AuditLog, OneTimeCode, TwoFactorConfig, User
from ..models import MobileSession
from ..utils import SmartlockUtils as U
from .common import fail
from .mobile_auth import issue_session, revoke_all_sessions, rotate_refresh
from .serializers import (
    ChallengeSerializer, ChangePasswordSerializer, EmailSerializer, LoginSerializer,
    RefreshSerializer, RegisterSerializer, TwoFactorVerifySerializer, UserSerializer,
)

logger = logging.getLogger('smartlock.api.auth')

CHALLENGE_SALT = 'smartlock.mobile.2fa'
CHALLENGE_MAX_AGE = 5 * 60
MAX_2FA_FAILS = 5


class PublicAuthView(APIView):
    """Endpoint công khai: bỏ qua mọi Authorization header (token hỏng không được làm hỏng login)."""
    authentication_classes = []
    permission_classes = [AllowAny]
    throttle_classes = [ScopedRateThrottle]


def _web():
    from .. import views as web   # import muộn: tái dùng _verify_totp / _send_email_code / _verify_email_code
    return web


def _session_response(user, request, info: dict, http=status.HTTP_200_OK):
    session, tokens = issue_session(user, ip=U.client_ip(request), **info)
    U.audit(request, 'MOBILE_LOGIN', actor=user, target_user=user,
            metadata={'session_id': str(session.id), 'device': info.get('device_name', '')[:100]})
    return Response({'user': UserSerializer(user).data, 'session_id': str(session.id), **tokens}, status=http)


# ============================== REGISTER ==============================
class RegisterView(PublicAuthView):
    throttle_scope = 'auth_register'

    def post(self, request):
        if not U.settings().registration_enabled:
            return fail('REGISTRATION_DISABLED', 'Hệ thống đang tạm đóng đăng ký.', status.HTTP_403_FORBIDDEN)
        s = RegisterSerializer(data=request.data)
        s.is_valid(raise_exception=True)
        d = s.validated_data
        email, username = d['email'].strip(), d['username']

        try:
            validate_password(d['password'])
        except DjangoValidationError as e:
            return fail('WEAK_PASSWORD', ' '.join(e.messages), password=e.messages)

        existing = User.objects.filter(email__iexact=email).first()
        if User.objects.filter(username__iexact=username).exclude(pk=existing.pk if existing else None).exists():
            return fail('USERNAME_TAKEN', 'Tên đăng nhập đã được sử dụng.', status.HTTP_409_CONFLICT)
        if existing:
            if existing.is_active or existing.email_verified:
                return fail('EMAIL_EXISTS', 'Email đã có tài khoản. Hãy đăng nhập hoặc dùng "Quên mật khẩu".',
                            status.HTTP_409_CONFLICT)
            _resend_verification(request, existing)   # đăng ký dở: gửi lại mail xác thực
            return Response({'message': 'Email đã đăng ký nhưng chưa xác thực. Đã gửi lại email xác thực.'},
                            status=status.HTTP_202_ACCEPTED)
        try:
            with transaction.atomic():
                user = User.objects.create_user(email=email, username=username, password=d['password'],
                                                full_name=d['full_name'] or None)
        except (DjangoValidationError, IntegrityError, ValueError) as e:
            U.audit(request, 'REGISTER_FAILED', actor=None, success=False, username_attempt=email[:150],
                    metadata={'reason': type(e).__name__})
            return fail('REGISTER_FAILED', 'Không thể tạo tài khoản với thông tin này.', status.HTTP_409_CONFLICT)

        U.audit(request, 'REGISTER', actor=user, target_user=user, metadata={'via': 'mobile'})
        sent = U.send_verification(request, user)
        return Response({'message': 'Đã tạo tài khoản. Vui lòng xác thực email để kích hoạt.',
                         'verification_email_sent': sent}, status=status.HTTP_201_CREATED)


def _resend_verification(request, user) -> bool:
    recent = OneTimeCode.objects.filter(user=user, purpose='EMAIL_VERIFY',
                                        created_at__gt=timezone.now() - timedelta(seconds=60)).exists()
    if recent:
        return False
    sent = U.send_verification(request, user)
    U.audit(request, 'VERIFY_MAIL_RESENT', actor=None, target_user=user, success=sent,
            metadata={'via': 'mobile'})
    return sent


class ResendVerificationView(PublicAuthView):
    throttle_scope = 'auth_register'

    def post(self, request):
        s = EmailSerializer(data=request.data)
        s.is_valid(raise_exception=True)
        user = User.objects.filter(email__iexact=s.validated_data['email']).first()
        if user and not user.email_verified:
            _resend_verification(request, user)
        # Luôn trả như nhau để không lộ email nào đã đăng ký.
        return Response({'message': 'Nếu email hợp lệ và chưa xác thực, chúng tôi đã gửi lại liên kết.'})


# ============================== LOGIN ==============================
class LoginView(PublicAuthView):
    throttle_scope = 'auth_login'

    def post(self, request):
        s = LoginSerializer(data=request.data)
        s.is_valid(raise_exception=True)
        d = s.validated_data
        info = {k: d[k] for k in ('device_name', 'platform', 'app_version', 'fcm_token')}
        identifier, ip, now = d['identifier'].strip(), U.client_ip(request), timezone.now()

        if U.ip_blacklisted(ip):
            U.audit(request, 'LOGIN_BLOCKED_IP', success=False, severity='warning',
                    username_attempt=identifier[:150])
            return fail('IP_BLOCKED', 'Địa chỉ IP của bạn đã bị chặn.', status.HTTP_403_FORBIDDEN)

        user = U.find_user(identifier)
        if user and user.login_locked_until and user.login_locked_until > now:
            minutes = math.ceil((user.login_locked_until - now).total_seconds() / 60)
            U.audit(request, 'LOGIN_LOCKED', success=False, severity='warning', actor=None,
                    target_user=user, username_attempt=identifier[:150])
            return fail('ACCOUNT_LOCKED', f'Tài khoản đang bị khoá tạm thời. Thử lại sau {minutes} phút.',
                        423, retry_after_minutes=minutes)

        auth_user = authenticate(request._request, username=user.email, password=d['password']) if user else None

        # Tài khoản quản trị chỉ đăng nhập ở cổng manage_sys (giống web).
        if auth_user and U.is_admin(auth_user):
            U.audit(request, 'LOGIN_ADMIN_REJECTED', success=False, severity='warning', actor=None,
                    target_user=user, username_attempt=identifier[:150])
            return fail('INVALID_CREDENTIALS', 'Email/Username hoặc mật khẩu không đúng.',
                        status.HTTP_401_UNAUTHORIZED)

        if auth_user:
            if auth_user.two_fa_enabled:
                cfg = TwoFactorConfig.objects.filter(user=auth_user).first()
                methods = [m for m in (cfg.available_methods() if cfg else []) if m != 'fido2']
                if not methods:
                    return fail('TWO_FACTOR_UNSUPPORTED',
                                'Tài khoản chỉ bật Passkey, app chưa hỗ trợ. Hãy thêm TOTP/Email OTP trên web.',
                                status.HTTP_403_FORBIDDEN)
                token = signing.dumps({'uid': str(auth_user.pk), 'info': info}, salt=CHALLENGE_SALT)
                U.audit(request, 'LOGIN_2FA_REQUIRED', actor=None, target_user=auth_user,
                        metadata={'via': 'mobile'})
                return Response({'requires_2fa': True, 'challenge_token': token, 'methods': methods,
                                 'preferred_method': cfg.preferred_method if cfg else ''})
            U.reset_lockout(auth_user)
            return _session_response(auth_user, request, info)

        if user and not user.is_active and user.check_password(d['password']):
            return fail('EMAIL_NOT_VERIFIED', 'Tài khoản chưa được kích hoạt. Vui lòng xác thực email.',
                        status.HTTP_403_FORBIDDEN)
        if user:
            locked = U.register_failure(user, ip)
            if locked:
                U.audit(request, 'ACCOUNT_LOCKED', success=False, severity='critical', actor=None,
                        target_user=user, username_attempt=identifier[:150], metadata={'locked_minutes': locked})
        U.audit(request, 'LOGIN_FAILED', success=False, severity='warning', actor=None,
                target_user=user, username_attempt=identifier[:150], metadata={'via': 'mobile'})
        return fail('INVALID_CREDENTIALS', 'Email/Username hoặc mật khẩu không đúng.',
                    status.HTTP_401_UNAUTHORIZED)


def _user_from_challenge(token):
    try:
        data = signing.loads(token, salt=CHALLENGE_SALT, max_age=CHALLENGE_MAX_AGE)
    except signing.SignatureExpired:
        return None, None, fail('CHALLENGE_EXPIRED', 'Phiên xác thực 2 lớp đã hết hạn, hãy đăng nhập lại.',
                                status.HTTP_401_UNAUTHORIZED)
    except signing.BadSignature:
        return None, None, fail('INVALID_CHALLENGE', 'Phiên xác thực 2 lớp không hợp lệ.',
                                status.HTTP_401_UNAUTHORIZED)
    user = User.objects.filter(pk=data.get('uid'), is_active=True).first()
    if not user:
        return None, None, fail('INVALID_CHALLENGE', 'Phiên xác thực 2 lớp không hợp lệ.',
                                status.HTTP_401_UNAUTHORIZED)
    return user, data.get('info') or {}, None


class TwoFactorSendEmailView(PublicAuthView):
    throttle_scope = 'auth_2fa'

    def post(self, request):
        s = ChallengeSerializer(data=request.data)
        s.is_valid(raise_exception=True)
        user, _info, err = _user_from_challenge(s.validated_data['challenge_token'])
        if err:
            return err
        cfg = TwoFactorConfig.objects.filter(user=user).first()
        if not cfg or not cfg.email_otp_enabled:
            return fail('METHOD_NOT_ENABLED', 'Tài khoản chưa bật Email OTP.', status.HTTP_400_BAD_REQUEST)
        result = _web()._send_email_code(user, 'VERIFY')
        if result == 'cooldown':
            return fail('COOLDOWN', 'Vui lòng đợi khoảng 1 phút trước khi gửi lại mã.', 429)
        if result == 'failed':
            return fail('EMAIL_SEND_FAILED', 'Không gửi được email. Thử lại sau.', status.HTTP_502_BAD_GATEWAY)
        return Response({'message': 'Đã gửi mã xác thực.', 'email': _web()._mask_email(user.email)})


class TwoFactorVerifyView(PublicAuthView):
    throttle_scope = 'auth_2fa'

    def post(self, request):
        s = TwoFactorVerifySerializer(data=request.data)
        s.is_valid(raise_exception=True)
        d = s.validated_data
        user, info, err = _user_from_challenge(d['challenge_token'])
        if err:
            return err

        recent_fails = AuditLog.objects.filter(
            action='MOBILE_2FA_FAILED', target_user=user,
            created_at__gte=timezone.now() - timedelta(minutes=15)).count()
        if recent_fails >= MAX_2FA_FAILS:
            return fail('TOO_MANY_ATTEMPTS', 'Nhập sai quá nhiều lần. Thử lại sau 15 phút.', 429)

        cfg = TwoFactorConfig.objects.filter(user=user).first()
        if not cfg or d['method'] not in cfg.available_methods():
            return fail('METHOD_NOT_ENABLED', 'Phương thức này chưa được bật.', status.HTTP_400_BAD_REQUEST)

        web = _web()
        ok = web._verify_totp(cfg, d['code']) if d['method'] == 'totp' \
            else web._verify_email_code(user, d['code'], 'VERIFY')
        if not ok:
            U.audit(request, 'MOBILE_2FA_FAILED', actor=None, target_user=user, success=False,
                    severity='warning', metadata={'method': d['method']})
            U.register_failure(user, U.client_ip(request))
            return fail('INVALID_CODE', 'Mã xác thực không đúng hoặc đã hết hạn.', status.HTTP_401_UNAUTHORIZED)

        U.reset_lockout(user)
        return _session_response(user, request, info)


# ============================== TOKEN LIFECYCLE ==============================
class RefreshView(PublicAuthView):
    throttle_scope = 'auth_refresh'

    def post(self, request):
        s = RefreshSerializer(data=request.data)
        s.is_valid(raise_exception=True)
        _session, tokens = rotate_refresh(s.validated_data['refresh_token'], ip=U.client_ip(request))
        return Response(tokens)


class LogoutView(APIView):
    def post(self, request):
        if isinstance(request.auth, MobileSession):
            request.auth.revoke()
        U.audit(request, 'MOBILE_LOGOUT')
        return Response(status=status.HTTP_204_NO_CONTENT)


class LogoutAllView(APIView):
    def post(self, request):
        n = revoke_all_sessions(request.user)
        U.audit(request, 'MOBILE_LOGOUT_ALL', severity='warning', metadata={'sessions': n})
        return Response({'revoked': n})


# ============================== PASSWORD ==============================
class ForgotPasswordView(PublicAuthView):
    throttle_scope = 'auth_reset'

    def post(self, request):
        s = EmailSerializer(data=request.data)
        s.is_valid(raise_exception=True)
        email = s.validated_data['email']
        user = User.objects.filter(email__iexact=email).first()
        generic = Response({'message': 'Nếu email hợp lệ, chúng tôi đã gửi liên kết đặt lại mật khẩu.'})

        if not user or not user.is_active or not user.email_verified:
            U.audit(request, 'PASSWORD_RESET_UNKNOWN_EMAIL', actor=None, success=False, severity='warning',
                    target_user=user, username_attempt=email[:150])
            return generic
        if AuditLog.objects.filter(action='PASSWORD_RESET_REQUEST', target_user=user,
                                   created_at__gte=timezone.now() - timedelta(seconds=60)).exists():
            return generic
        link = request.build_absolute_uri(reverse('smartlock:reset_password_confirm', args=[
            force_str(urlsafe_base64_encode(force_bytes(str(user.pk)))), default_token_generator.make_token(user)]))
        subject, html, plain = render_email('password_reset.html', {
            'full_name': user.full_name or user.username, 'password_reset_link': link, 'reset_link': link,
            'expiry_minutes': dj_settings.PASSWORD_RESET_TIMEOUT // 60})
        sent = U.send_mail(subject, plain, html, user.email)
        U.audit(request, 'PASSWORD_RESET_REQUEST', actor=None, target_user=user, success=sent,
                metadata={'via': 'mobile'})
        return generic


class ChangePasswordView(APIView):
    def post(self, request):
        s = ChangePasswordSerializer(data=request.data)
        s.is_valid(raise_exception=True)
        user, d = request.user, s.validated_data

        if AuditLog.objects.filter(action='PASSWORD_CHANGE_FAILED', actor_user=user,
                                   created_at__gte=timezone.now() - timedelta(minutes=15)).count() >= 5:
            return fail('TOO_MANY_ATTEMPTS', 'Nhập sai mật khẩu quá nhiều lần. Thử lại sau 15 phút.', 429)
        if not user.check_password(d['old_password']):
            U.audit(request, 'PASSWORD_CHANGE_FAILED', success=False, severity='warning', target_user=user)
            return fail('WRONG_PASSWORD', 'Mật khẩu hiện tại không đúng.', status.HTTP_400_BAD_REQUEST)
        try:
            validate_password(d['new_password'], user)
        except DjangoValidationError as e:
            return fail('WEAK_PASSWORD', ' '.join(e.messages), password=e.messages)

        user.set_password(d['new_password'])
        user.save()
        revoked = revoke_all_sessions(user, except_session=request.auth if isinstance(request.auth, MobileSession) else None)
        U.audit(request, 'PASSWORD_CHANGED', severity='warning', target_user=user,
                metadata={'via': 'mobile', 'other_sessions_revoked': revoked})
        U.notify(user, 'Mật khẩu đã thay đổi', 'Bạn vừa đổi mật khẩu tài khoản.', severity='warning',
                 type_='SECURITY')
        return Response({'message': 'Đã đổi mật khẩu.', 'other_sessions_revoked': revoked})
