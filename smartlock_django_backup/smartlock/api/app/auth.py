"""Đăng ký, đăng nhập, 2FA, làm mới token, đăng xuất, quên mật khẩu."""
import math
from datetime import timedelta

from django.contrib.auth import authenticate
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError
from django.db import IntegrityError, transaction
from django.utils import timezone

from smartlock import services, twofa
from smartlock.constants import RESET_NEUTRAL_MSG
from smartlock.api.common import (
    api, ApiError, CHALLENGE_TTL_SECONDS, create_session, device_info, make_challenge, ok,
    read_challenge, read_json, rotate_refresh, s,
)
from smartlock.models import AuditLog, MobileSession, OneTimeCode, User

from .serializers import user_json


def _mobile_2fa_methods(user) -> list:
    """Passkey/FIDO2 chưa hỗ trợ trong app (cần RP/origin riêng) -> chỉ totp + email."""
    cfg = twofa.get_cfg(user)
    return [m for m in cfg.available_methods() if m in ('totp', 'email')]


def _finish_login(request, user, info, method=None):
    services.reset_lockout(user)
    session, tokens = create_session(request, user, info)
    services.notify_login(request, user)          # PHẢI trước audit LOGIN (so với lịch sử IP cũ)
    services.audit(request, 'LOGIN', actor=user,
                   metadata={'channel': 'mobile', 'platform': info.get('platform'), 'two_factor': method})
    return ok({'user': user_json(user), **tokens})


@api('POST', auth=False)
def register(request):
    if not services.system_settings().registration_enabled:
        raise ApiError('REGISTRATION_DISABLED', 'Hệ thống đang tạm đóng đăng ký.', 403)
    data = read_json(request)
    email = s(data, 'email', 254, required=True)
    username = s(data, 'username', 50, required=True)
    full_name = s(data, 'full_name', 100)
    password = str(data.get('password') or '')

    if '@' in username:
        raise ApiError('BAD_USERNAME', 'Tên đăng nhập không được chứa ký tự @.', 400, field='username')
    try:
        validate_password(password)
    except ValidationError as e:
        raise ApiError('WEAK_PASSWORD', ' '.join(e.messages), 400, field='password')

    existing = User.objects.filter(email__iexact=email).first()
    if User.objects.filter(username__iexact=username).exclude(pk=existing.pk if existing else None).exists():
        raise ApiError('USERNAME_TAKEN', 'Tên đăng nhập đã được sử dụng.', 409, field='username')

    if existing:
        if existing.is_active or existing.email_verified:
            services.audit(request, 'REGISTER_DUPLICATE_ACTIVE', actor=None, target_user=existing,
                           success=False, severity='warning', username_attempt=email[:150])
            raise ApiError('EMAIL_EXISTS', 'Email này đã có tài khoản. Hãy đăng nhập hoặc dùng "Quên mật khẩu".',
                           409, field='email')
        recent = OneTimeCode.objects.filter(user=existing, purpose='EMAIL_VERIFY',
                                            created_at__gt=timezone.now() - timedelta(seconds=60)).exists()
        if not recent:
            sent = services.send_verification(request, existing)
            services.audit(request, 'VERIFY_MAIL_RESENT', actor=None, target_user=existing, success=sent,
                           metadata={'reason': 'duplicate_register_unverified', 'channel': 'mobile'})
        return ok({'verification_required': True, 'email': email,
                   'message': 'Email đã đăng ký nhưng chưa xác thực. Đã gửi lại email xác thực.'}, 200)

    try:
        with transaction.atomic():
            user = User.objects.create_user(email=email, username=username, password=password,
                                            full_name=full_name or None)
    except ValidationError as e:
        services.audit(request, 'REGISTER_FAILED', actor=None, success=False, username_attempt=email[:150],
                       metadata={'reason': 'validation'})
        raise ApiError('VALIDATION', ' '.join(e.messages), 400)
    except IntegrityError:
        raise ApiError('DUPLICATE', 'Email hoặc tên đăng nhập đã được sử dụng.', 409)
    except ValueError as e:
        raise ApiError('VALIDATION', str(e), 400)

    services.audit(request, 'REGISTER', actor=user, target_user=user, metadata={'channel': 'mobile'})
    sent = services.send_verification(request, user)
    if not sent:
        services.audit(request, 'VERIFY_MAIL_FAILED', actor=user, target_user=user, success=False, severity='warning')
    return ok({'verification_required': True, 'email': user.email, 'email_sent': sent,
               'message': 'Đã tạo tài khoản. Hãy bấm link xác thực trong email rồi đăng nhập.'}, 201)


@api('POST', auth=False)
def resend_verification(request):
    email = s(read_json(request), 'email', 254)
    user = User.objects.filter(email__iexact=email, is_active=False, email_verified=False).first()
    if user and not OneTimeCode.objects.filter(user=user, purpose='EMAIL_VERIFY',
                                               created_at__gt=timezone.now() - timedelta(seconds=60)).exists():
        sent = services.send_verification(request, user)
        services.audit(request, 'VERIFY_MAIL_RESENT', actor=None, target_user=user, success=sent,
                       metadata={'channel': 'mobile'})
    return ok({'message': 'Nếu tài khoản cần xác thực, email đã được gửi lại.'})      # luôn trung tính


@api('POST', auth=False)
def password_reset(request):
    email = s(read_json(request), 'email', 254)
    neutral = ok({'message': RESET_NEUTRAL_MSG})
    user = User.objects.filter(email__iexact=email).first()
    if not user:
        services.audit(request, 'PASSWORD_RESET_UNKNOWN_EMAIL', actor=None, success=False, severity='warning',
                       username_attempt=email[:150])
        return neutral
    if not user.is_active or not user.email_verified:
        services.audit(request, 'PASSWORD_RESET_UNVERIFIED', actor=None, success=False, severity='warning',
                       target_user=user)
        return neutral
    if AuditLog.objects.filter(action='PASSWORD_RESET_REQUEST', target_user=user,
                               created_at__gte=timezone.now() - timedelta(seconds=60)).exists():
        return neutral
    sent = services.send_password_reset(request, user)
    services.audit(request, 'PASSWORD_RESET_REQUEST', actor=None, target_user=user, success=sent,
                   metadata={'channel': 'mobile'})
    return neutral


@api('POST', auth=False)
def login(request):
    data = read_json(request)
    identifier = s(data, 'identifier', 150) or s(data, 'email', 150)
    password = str(data.get('password') or '')
    if not identifier or not password:
        raise ApiError('MISSING_FIELD', 'Vui lòng nhập email/username và mật khẩu.', 400)
    info = device_info(data)
    ip = services.client_ip(request)
    user = services.find_user(identifier)
    now = timezone.now()

    if user and user.login_locked_until and user.login_locked_until > now:
        remaining = math.ceil((user.login_locked_until - now).total_seconds() / 60)
        services.audit(request, 'LOGIN_LOCKED', actor=None, target_user=user, success=False, severity='warning',
                       username_attempt=identifier[:150])
        raise ApiError('ACCOUNT_LOCKED', f'Tài khoản đang bị khóa tạm thời. Thử lại sau {remaining} phút.',
                       423, retry_after_minutes=remaining)

    auth_user = authenticate(request, username=user.email, password=password) if user else None

    if auth_user and services.is_admin(auth_user):       # quản trị chỉ đăng nhập ở cổng riêng
        services.audit(request, 'LOGIN_ADMIN_REJECTED', actor=None, target_user=user, success=False,
                       severity='warning', username_attempt=identifier[:150])
        raise ApiError('INVALID_CREDENTIALS', 'Email/Username hoặc mật khẩu không đúng.', 401)

    if auth_user:
        if auth_user.two_fa_enabled:
            methods = _mobile_2fa_methods(auth_user)
            if not methods:
                raise ApiError('TWO_FACTOR_UNSUPPORTED',
                               'Tài khoản chỉ bật Passkey. Hãy thêm Google Authenticator hoặc Email OTP '
                               'trên web để đăng nhập bằng app.', 403)
            cfg = twofa.get_cfg(auth_user)
            services.audit(request, 'LOGIN_2FA_REQUIRED', actor=None, target_user=auth_user,
                           metadata={'channel': 'mobile'})
            return ok({'two_factor_required': True,
                       'challenge_token': make_challenge(auth_user, info),
                       'methods': methods,
                       'preferred_method': cfg.preferred_method if cfg.preferred_method in methods else methods[0],
                       'expires_in': CHALLENGE_TTL_SECONDS})
        return _finish_login(request, auth_user, info)

    if user and not user.is_active and user.check_password(password):
        raise ApiError('EMAIL_NOT_VERIFIED', 'Tài khoản chưa được kích hoạt. Vui lòng xác thực email.', 403)
    if user:
        locked = services.register_failure(user, ip)
        if locked:
            services.audit(request, 'ACCOUNT_LOCKED', success=False, severity='critical', actor=None,
                           target_user=user, username_attempt=identifier[:150],
                           metadata={'locked_minutes': locked})
    services.audit(request, 'LOGIN_FAILED', success=False, severity='warning', actor=None, target_user=user,
                   username_attempt=identifier[:150], metadata={'channel': 'mobile'})
    raise ApiError('INVALID_CREDENTIALS', 'Email/Username hoặc mật khẩu không đúng.', 401)


def _challenge_user(data):
    ch = read_challenge(s(data, 'challenge_token', 4000, required=True))
    user = User.objects.filter(pk=services.parse_uuid(ch.get('uid'))).first()
    if not user or not user.is_active or services.is_admin(user):
        raise ApiError('CHALLENGE_INVALID', 'Phiên xác thực 2 lớp không hợp lệ.', 401)
    return user, ch.get('info') or {}


@api('POST', auth=False)
def two_factor_email_send(request):
    user, _info = _challenge_user(read_json(request))
    if 'email' not in _mobile_2fa_methods(user):
        raise ApiError('BAD_METHOD', 'Tài khoản chưa bật Email OTP.', 400)
    result = twofa.send_email_code(user, 'VERIFY')
    if result == 'cooldown':
        raise ApiError('COOLDOWN', f'Vui lòng đợi {twofa.EMAIL_CODE_COOLDOWN} giây trước khi gửi lại.', 429,
                       retry_after_seconds=twofa.EMAIL_CODE_COOLDOWN)
    if result != 'sent':
        raise ApiError('MAIL_FAILED', 'Không gửi được email. Vui lòng thử lại.', 502)
    return ok({'sent': True, 'masked_email': services.mask_email(user.email),
               'expires_in': twofa.EMAIL_CODE_TTL_MIN * 60})


@api('POST', auth=False)
def two_factor_verify(request):
    data = read_json(request)
    user, info = _challenge_user(data)
    minutes = twofa.lock_minutes(user)
    if minutes:
        raise ApiError('ACCOUNT_LOCKED', f'Tài khoản đang bị khóa tạm thời. Thử lại sau {minutes} phút.', 423,
                       retry_after_minutes=minutes)
    method = s(data, 'method', 10).lower()
    code = s(data, 'code', 20)
    if method not in _mobile_2fa_methods(user):
        raise ApiError('BAD_METHOD', 'Phương thức xác thực không hợp lệ.', 400)
    good = (twofa.verify_totp(twofa.get_cfg(user), code) if method == 'totp'
            else twofa.verify_email_code(user, code, 'VERIFY'))
    if not good:
        locked = services.register_failure(user, services.client_ip(request))
        services.audit(request, 'TWO_FACTOR_FAILED', actor=None, target_user=user, success=False,
                       severity='warning', metadata={'method': method, 'purpose': 'login', 'channel': 'mobile',
                                                     'locked_minutes': locked})
        if locked:
            services.audit(request, 'ACCOUNT_LOCKED', success=False, severity='critical', actor=None,
                           target_user=user, metadata={'locked_minutes': locked, 'stage': '2fa'})
            raise ApiError('ACCOUNT_LOCKED', f'Sai quá nhiều lần. Tài khoản bị khóa {locked} phút.', 423,
                           retry_after_minutes=locked)
        raise ApiError('TWO_FACTOR_INVALID', 'Mã xác thực không đúng hoặc đã hết hạn.', 401)
    return _finish_login(request, user, info, method)


@api('POST', auth=False)
def refresh(request):
    data = read_json(request)
    _session, tokens = rotate_refresh(request, s(data, 'refresh_token', 200, required=True), s(data, 'fcm_token', 512))
    return ok(tokens)


@api('POST')
def logout(request):
    data = read_json(request)
    user = request.user
    if data.get('all') is True:
        n = 0
        for m in MobileSession.objects.filter(user=user, revoked_at__isnull=True):
            m.revoke()
            n += 1
        services.audit(request, 'LOGOUT_ALL', metadata={'channel': 'mobile', 'sessions': n})
        return ok({'revoked': n})
    request.api_session.revoke()
    services.audit(request, 'LOGOUT', metadata={'channel': 'mobile'})
    return ok({'revoked': 1})
