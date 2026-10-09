# smartlock/api/account.py

import base64
import io
import json
import math
import pyotp
import qrcode
import qrcode.image.svg
from datetime import timedelta

from django.contrib.auth import authenticate, logout as django_logout, update_session_auth_hash
from django.contrib.auth.hashers import check_password, make_password
from django.contrib.auth.password_validation import validate_password
from django.contrib.auth.tokens import default_token_generator
from django.core import signing
from django.core.exceptions import ValidationError
from django.db import IntegrityError, transaction
from django.middleware.csrf import get_token
from django.utils import timezone
from django.utils.encoding import force_str
from django.utils.http import urlsafe_base64_decode
from webauthn import (
    generate_authentication_options,
    generate_registration_options,
    options_to_json,
    verify_authentication_response,
    verify_registration_response,
)
from webauthn.helpers import base64url_to_bytes, bytes_to_base64url
from webauthn.helpers.structs import (
    AuthenticatorSelectionCriteria,
    PublicKeyCredentialDescriptor,
    ResidentKeyRequirement,
    UserVerificationRequirement,
)

from smartlock import services
from smartlock.api.common import (
    api,
    ApiError,
    CHALLENGE_TTL_SECONDS,
    check_csrf,
    claim_fcm_token,
    create_session,
    device_info,
    make_challenge,
    ok,
    read_challenge,
    read_json,
    revoke_all_sessions,
    rotate_refresh,
    s,
    session_json,
    user_json,
    uuid_or_404,
    web_login,
)
from smartlock.services import RESET_NEUTRAL_MSG
from smartlock.models import (
    AccessCard,
    AuditLog,
    Device,
    DeviceAccess,
    FaceProfile,
    Fido2Credential,
    MobileSession,
    OneTimeCode,
    sync_two_fa_flag,
    TwoFactorConfig,
    User,
)


_DUMMY_HASH = None


def _burn_password_check(password):
    global _DUMMY_HASH
    if _DUMMY_HASH is None:
        _DUMMY_HASH = make_password('smartlock-timing-dummy')
    check_password(password, _DUMMY_HASH)


def _2fa_methods(user, web=False) -> list:
    allowed = ('totp', 'email', 'fido2') if web else ('totp', 'email')
    return [m for m in services.get_cfg(user).available_methods() if m in allowed]


def _is_web(info) -> bool:
    return (info or {}).get('client') == 'web'


def _client_info(data) -> dict:
    info = device_info(data)
    if s(data, 'client', 10).lower() == 'web':
        info['client'] = 'web'
    return info


def _finish_login(request, user, info, method=None):
    services.reset_lockout(user)
    if _is_web(info):
        web_login(request, user)
        services.notify_login(request, user)
        services.audit(request, 'LOGIN', actor=user, metadata={'channel': 'web', 'two_factor': method})
        return ok({'user': user_json(user), 'client': 'web', 'csrf_token': get_token(request),
                   'session_expires_in': services.user_session_seconds()})
    session, tokens = create_session(request, user, info)
    User.objects.filter(pk=user.pk).update(last_login=timezone.now())
    services.notify_login(request, user)
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
        existing.set_password(password)
        existing.username = username.strip().lower()
        if full_name:
            existing.full_name = full_name
        existing.save(update_fields=['password', 'username', 'full_name', 'updated_at'])
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
    return ok({'message': 'Nếu tài khoản cần xác thực, email đã được gửi lại.'})


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
    info = _client_info(data)
    if _is_web(info):
        check_csrf(request)
    ip = services.client_ip(request)
    user = services.find_user(identifier)
    now = timezone.now()

    if user and user.login_locked_until and user.login_locked_until > now:
        remaining = math.ceil((user.login_locked_until - now).total_seconds() / 60)
        services.audit(request, 'LOGIN_LOCKED', actor=None, target_user=user, success=False, severity='warning',
                       username_attempt=identifier[:150])
        raise ApiError('ACCOUNT_LOCKED', f'Tài khoản đang bị khóa tạm thời. Thử lại sau {remaining} phút.',
                       423, retry_after_minutes=remaining)

    if user:
        auth_user = authenticate(request, username=user.email, password=password)
    else:
        _burn_password_check(password)
        auth_user = None

    if auth_user and services.is_admin(auth_user):
        services.audit(request, 'LOGIN_ADMIN_REJECTED', actor=None, target_user=user, success=False,
                       severity='warning', username_attempt=identifier[:150])
        raise ApiError('INVALID_CREDENTIALS', 'Email/Username hoặc mật khẩu không đúng.', 401)

    if auth_user:
        if auth_user.two_fa_enabled:
            methods = _2fa_methods(auth_user, _is_web(info))
            if not methods:
                raise ApiError('TWO_FACTOR_UNSUPPORTED',
                               'Tài khoản chỉ bật Passkey. Hãy thêm Google Authenticator hoặc Email OTP '
                               'trên web để đăng nhập bằng app.', 403)
            cfg = services.get_cfg(auth_user)
            services.audit(request, 'LOGIN_2FA_REQUIRED', actor=None, target_user=auth_user,
                           metadata={'channel': 'web' if _is_web(info) else 'mobile'})
            return ok({'two_factor_required': True,
                       'challenge_token': make_challenge(auth_user, info),
                       'methods': methods,
                       'preferred_method': cfg.preferred_method if cfg.preferred_method in methods else methods[0],
                       'expires_in': CHALLENGE_TTL_SECONDS})
        return _finish_login(request, auth_user, info)

    if user and not user.is_active and user.check_password(password):
        if user.email_verified:
            services.audit(request, 'LOGIN_DISABLED_ACCOUNT', actor=None, target_user=user, success=False,
                           severity='warning', username_attempt=identifier[:150])
            raise ApiError('ACCOUNT_DISABLED', 'Tài khoản đã bị vô hiệu hóa. Vui lòng liên hệ quản trị viên.', 403)
        raise ApiError('EMAIL_NOT_VERIFIED', 'Tài khoản chưa được kích hoạt. Vui lòng xác thực email.', 403)
    if user:
        locked = services.register_failure(user, ip)
        if locked:
            services.audit(request, 'ACCOUNT_LOCKED', success=False, severity='critical', actor=None,
                           target_user=user, username_attempt=identifier[:150],
                           metadata={'locked_minutes': locked})
    services.audit(request, 'LOGIN_FAILED', success=False, severity='warning', actor=None, target_user=user,
                   username_attempt=identifier[:150], metadata={'channel': 'web' if _is_web(info) else 'mobile'})
    raise ApiError('INVALID_CREDENTIALS', 'Email/Username hoặc mật khẩu không đúng.', 401)


def _challenge_user(data):
    ch = read_challenge(s(data, 'challenge_token', 4000, required=True))
    user = User.objects.filter(pk=services.parse_uuid(ch.get('uid'))).first()
    if not user or not user.is_active or services.is_admin(user):
        raise ApiError('CHALLENGE_INVALID', 'Phiên xác thực 2 lớp không hợp lệ.', 401)
    return user, ch.get('info') or {}


@api('POST', auth=False)
def two_factor_email_send(request):
    user, info = _challenge_user(read_json(request))
    minutes = services.lock_minutes(user)
    if minutes:
        raise ApiError('ACCOUNT_LOCKED', f'Tài khoản đang bị khóa tạm thời. Thử lại sau {minutes} phút.', 423,
                       retry_after_minutes=minutes)
    if 'email' not in _2fa_methods(user, _is_web(info)):
        raise ApiError('BAD_METHOD', 'Tài khoản chưa bật Email OTP.', 400)
    result = services.send_email_code(user, 'VERIFY')
    if result == 'cooldown':
        raise ApiError('COOLDOWN', f'Vui lòng đợi {services.EMAIL_CODE_COOLDOWN} giây trước khi gửi lại.', 429,
                       retry_after_seconds=services.EMAIL_CODE_COOLDOWN)
    if result != 'sent':
        raise ApiError('MAIL_FAILED', 'Không gửi được email. Vui lòng thử lại.', 502)
    return ok({'sent': True, 'masked_email': services.mask_email(user.email),
               'expires_in': services.EMAIL_CODE_TTL_MIN * 60})


@api('POST', auth=False)
def two_factor_verify(request):
    data = read_json(request)
    user, info = _challenge_user(data)
    if _is_web(info):
        check_csrf(request)
    minutes = services.lock_minutes(user)
    if minutes:
        raise ApiError('ACCOUNT_LOCKED', f'Tài khoản đang bị khóa tạm thời. Thử lại sau {minutes} phút.', 423,
                       retry_after_minutes=minutes)
    method = s(data, 'method', 10).lower()
    code = s(data, 'code', 20)
    if method not in ('totp', 'email') or method not in _2fa_methods(user, _is_web(info)):
        raise ApiError('BAD_METHOD', 'Phương thức xác thực không hợp lệ.', 400)
    good = (services.verify_totp(services.get_cfg(user), code) if method == 'totp'
            else services.verify_email_code(user, code, 'VERIFY'))
    if not good:
        locked = services.register_failure(user, services.client_ip(request))
        services.audit(request, 'TWO_FACTOR_FAILED', actor=None, target_user=user, success=False,
                       severity='warning', metadata={'method': method, 'purpose': 'login',
                                                     'channel': 'web' if _is_web(info) else 'mobile',
                                                     'locked_minutes': locked})
        if locked:
            services.audit(request, 'ACCOUNT_LOCKED', success=False, severity='critical', actor=None,
                           target_user=user, metadata={'locked_minutes': locked, 'stage': '2fa'})
            raise ApiError('ACCOUNT_LOCKED', f'Sai quá nhiều lần. Tài khoản bị khóa {locked} phút.', 423,
                           retry_after_minutes=locked)
        raise ApiError('TWO_FACTOR_INVALID', 'Mã xác thực không đúng hoặc đã hết hạn.', 401)
    return _finish_login(request, user, info, method)


@api('POST', auth=False)
def two_factor_passkey_options(request):
    user, info = _challenge_user(read_json(request))
    if not _is_web(info):
        raise ApiError('WEB_ONLY', 'Passkey chỉ dùng được trên web.', 400)
    check_csrf(request)
    creds = [PublicKeyCredentialDescriptor(id=base64url_to_bytes(c.credential_id))
             for c in Fido2Credential.objects.filter(user=user)]
    if not creds:
        raise ApiError('NO_PASSKEY', 'Tài khoản chưa đăng ký passkey.', 400)
    rp_id, _origin, _name = services.webauthn_rp(request)
    options = generate_authentication_options(rp_id=rp_id, allow_credentials=creds,
                                              user_verification=UserVerificationRequirement.PREFERRED)
    request.session['webauthn_auth'] = {'challenge': bytes_to_base64url(options.challenge),
                                        'uid': str(user.id), 'ts': int(timezone.now().timestamp())}
    return ok({'options': json.loads(options_to_json(options))})


@api('POST', auth=False)
def two_factor_passkey_finish(request):
    data = read_json(request)
    user, info = _challenge_user(data)
    if not _is_web(info):
        raise ApiError('WEB_ONLY', 'Passkey chỉ dùng được trên web.', 400)
    check_csrf(request)
    minutes = services.lock_minutes(user)
    if minutes:
        raise ApiError('ACCOUNT_LOCKED', f'Tài khoản đang bị khóa tạm thời. Thử lại sau {minutes} phút.', 423,
                       retry_after_minutes=minutes)
    state = request.session.pop('webauthn_auth', None)
    now_ts = int(timezone.now().timestamp())
    if (not state or state.get('uid') != str(user.id)
            or now_ts - int(state.get('ts', 0)) > services.WEBAUTHN_TTL):
        raise ApiError('PASSKEY_EXPIRED', 'Yêu cầu passkey đã hết hạn. Hãy thử lại.', 400)
    credential = data.get('credential')
    credential = credential if isinstance(credential, dict) else {}
    cred = Fido2Credential.objects.filter(user=user, credential_id=credential.get('id') or '').first()
    rp_id, origin, _name = services.webauthn_rp(request)
    good = False
    if cred:
        try:
            v = verify_authentication_response(
                credential=credential, expected_challenge=base64url_to_bytes(state['challenge']),
                expected_rp_id=rp_id, expected_origin=origin,
                credential_public_key=bytes(cred.public_key), credential_current_sign_count=cred.sign_count,
                require_user_verification=False)
            cred.sign_count = v.new_sign_count
            cred.last_used_at = timezone.now()
            cred.save(update_fields=['sign_count', 'last_used_at'])
            good = True
        except Exception:
            pass
    if not good:
        locked = services.register_failure(user, services.client_ip(request))
        services.audit(request, 'TWO_FACTOR_FAILED', actor=None, target_user=user, success=False,
                       severity='warning', metadata={'method': 'fido2', 'purpose': 'login', 'channel': 'web',
                                                     'locked_minutes': locked})
        if locked:
            raise ApiError('ACCOUNT_LOCKED', f'Sai quá nhiều lần. Tài khoản bị khóa {locked} phút.', 423,
                           retry_after_minutes=locked)
        raise ApiError('TWO_FACTOR_INVALID', 'Passkey không hợp lệ.', 401)
    return _finish_login(request, user, info, 'fido2')


@api('POST', auth=False)
def refresh(request):
    data = read_json(request)
    _session, tokens = rotate_refresh(request, s(data, 'refresh_token', 200, required=True), s(data, 'fcm_token', 512))
    return ok(tokens)


@api('POST', auth='any')
def logout(request):
    data = read_json(request)
    user = request.user
    if request.client_type == 'web':
        revoked = 0
        if data.get('all') is True:
            revoked = revoke_all_sessions(user)
            services.audit(request, 'LOGOUT_ALL', metadata={'channel': 'web', 'sessions': revoked})
        services.audit(request, 'LOGOUT', metadata={'channel': 'web'})
        django_logout(request)
        return ok({'client': 'web', 'revoked': revoked})
    if data.get('all') is True:
        n = revoke_all_sessions(user)
        services.audit(request, 'LOGOUT_ALL', metadata={'channel': 'mobile', 'sessions': n})
        return ok({'revoked': n})
    request.api_session.revoke()
    services.audit(request, 'LOGOUT', metadata={'channel': 'mobile'})
    return ok({'revoked': 1})


@api('GET', auth=False)
def csrf(request):
    return ok({'csrf_token': get_token(request)})


@api('POST', auth=False)
def verify_email(request):
    token = services.parse_uuid(s(read_json(request), 'token', 64, required=True))
    now = timezone.now()
    vt = None
    if token:
        vt = (OneTimeCode.objects.select_related('user')
              .filter(token_hash=services.hash_token(token), purpose='EMAIL_VERIFY', is_used=False,
                      expires_at__gt=now).first())
    if vt is None or not OneTimeCode.objects.filter(pk=vt.pk, is_used=False).update(is_used=True, used_at=now):
        services.audit(request, 'EMAIL_VERIFY_FAILED', actor=None, success=False, severity='warning')
        raise ApiError('TOKEN_INVALID', 'Link xác thực không hợp lệ hoặc đã hết hạn.', 400)
    user = vt.user
    if user.email_verified:
        if user.is_active:
            return ok({'verified': True, 'message': 'Tài khoản đã được kích hoạt trước đó.'})
        services.audit(request, 'EMAIL_VERIFY_FAILED', actor=None, target_user=user, success=False,
                       severity='warning', metadata={'reason': 'account_disabled'})
        raise ApiError('TOKEN_INVALID', 'Link xác thực không hợp lệ hoặc đã hết hạn.', 400)
    User.objects.filter(pk=user.pk).update(email_verified=True, is_active=True, updated_at=now)
    user.email_verified = user.is_active = True
    services.audit(request, 'EMAIL_VERIFIED', actor=user, target_user=user)
    services.notify(user, 'Chào mừng đến Smart Lock', 'Tài khoản của bạn đã được kích hoạt.', type_='WELCOME')
    return ok({'verified': True, 'message': 'Tài khoản đã được kích hoạt thành công!'})


def _reset_user(request, data):
    uid, token = s(data, 'uid', 200, required=True), s(data, 'token', 200, required=True)
    try:
        user = User.objects.get(pk=force_str(urlsafe_base64_decode(uid)))
    except Exception:
        user = None
    if user is None or not user.is_active or not default_token_generator.check_token(user, token):
        services.audit(request, 'PASSWORD_RESET_INVALID', actor=None, success=False, severity='warning',
                       target_user=user)
        raise ApiError('RESET_INVALID', 'Liên kết đặt lại mật khẩu không hợp lệ hoặc đã hết hạn.', 400)
    return user


@api('POST', auth=False)
def password_reset_check(request):
    _reset_user(request, read_json(request))
    return ok({'valid': True})


@api('POST', auth=False)
def password_reset_confirm(request):
    data = read_json(request)
    user = _reset_user(request, data)
    new = str(data.get('new_password') or '')
    try:
        validate_password(new, user)
    except ValidationError as e:
        raise ApiError('WEAK_PASSWORD', ' '.join(e.messages), 400, field='new_password')
    user.set_password(new)
    user.save()
    revoke_all_sessions(user)
    services.reset_lockout(user)
    services.audit(request, 'PASSWORD_RESET_DONE', actor=user, target_user=user,
                   metadata={'channel': 'api'})
    services.notify(user, 'Mật khẩu đã thay đổi', 'Mật khẩu tài khoản vừa được đặt lại.',
                    severity='warning', type_='SECURITY')
    return ok({'message': 'Mật khẩu đã được thay đổi thành công!'})


def _delete_account(request):
    user = request.user
    if Device.objects.filter(owner=user).exists():
        raise ApiError('OWNS_DEVICES', 'Bạn còn đang sở hữu khoá. Hãy gỡ khoá khỏi tài khoản trước khi xoá.', 409)
    if not user.check_password(str(read_json(request).get('password') or '')):
        services.audit(request, 'ACCOUNT_DELETE_FAILED', success=False, severity='warning', target_user=user)
        raise ApiError('WRONG_PASSWORD', 'Mật khẩu không đúng.', 400, field='password')
    for acc in DeviceAccess.objects.filter(user=user, is_active=True).select_related('device'):
        services.revoke_user_credentials(acc.device, user)
    DeviceAccess.objects.filter(user=user, is_active=True).update(is_active=False, revoked_at=timezone.now())
    FaceProfile.objects.filter(user=user).delete()
    AccessCard.objects.filter(user=user).delete()
    revoke_all_sessions(user)
    services.audit(request, 'ACCOUNT_DELETED', target_user=user, severity='warning',
                   metadata={'channel': request.client_type})
    user.is_active = False
    user.save(update_fields=['is_active', 'updated_at'])
    if request.client_type == 'web':
        django_logout(request)
    return ok({'deleted': True})


@api('GET', 'PATCH', 'DELETE', auth='any')
def me(request):
    user = request.user
    if request.method == 'DELETE':
        return _delete_account(request)
    if request.method == 'PATCH':
        data = read_json(request)
        before = {'full_name': user.full_name, 'phone': user.phone, 'avatar_url': user.avatar_url}
        if 'full_name' in data:
            user.full_name = s(data, 'full_name', 100) or None
        if 'phone' in data:
            user.phone = s(data, 'phone', 20) or None
        if 'avatar_url' in data:
            url = s(data, 'avatar_url', 512)
            if url and not url.lower().startswith(('https://', 'http://')):
                raise ApiError('BAD_FIELD', 'avatar_url phải là http(s).', 400, field='avatar_url')
            user.avatar_url = url or None
        user.save(update_fields=['full_name', 'phone', 'avatar_url', 'updated_at'])
        after = {'full_name': user.full_name, 'phone': user.phone, 'avatar_url': user.avatar_url}
        changes = {k: [before[k], after[k]] for k in after if before[k] != after[k]}
        services.audit(request, 'PROFILE_UPDATED', target_user=user, metadata={'changes': changes} if changes else None)
    return ok({'user': user_json(user),
               'device_count': Device.objects.filter(owner=user).count(),
               'card_count': AccessCard.objects.filter(user=user).count()})


@api('POST', auth='any')
def change_password(request):
    user, data = request.user, read_json(request)
    old, new = str(data.get('old_password') or ''), str(data.get('new_password') or '')
    recent = AuditLog.objects.filter(action='PASSWORD_CHANGE_FAILED', actor_user=user,
                                     created_at__gte=timezone.now() - timedelta(minutes=15)).count()
    if recent >= 5:
        raise ApiError('RATE_LIMITED', 'Nhập sai mật khẩu hiện tại quá nhiều lần. Thử lại sau 15 phút.', 429)
    if not user.check_password(old):
        services.audit(request, 'PASSWORD_CHANGE_FAILED', success=False, severity='warning', target_user=user)
        raise ApiError('WRONG_PASSWORD', 'Mật khẩu hiện tại không đúng.', 400, field='old_password')
    if old == new:
        raise ApiError('SAME_PASSWORD', 'Mật khẩu mới phải khác mật khẩu hiện tại.', 400, field='new_password')
    try:
        validate_password(new, user)
    except ValidationError as e:
        raise ApiError('WEAK_PASSWORD', ' '.join(e.messages), 400, field='new_password')
    user.set_password(new)
    user.save()
    if request.client_type == 'web':
        update_session_auth_hash(request, user)
    others = revoke_all_sessions(user, exclude=request.api_session)
    services.audit(request, 'PASSWORD_CHANGED', severity='warning', target_user=user,
                   metadata={'channel': request.client_type, 'revoked_other_sessions': others})
    services.notify(user, 'Mật khẩu đã thay đổi', 'Bạn vừa đổi mật khẩu tài khoản.', severity='warning',
                    type_='SECURITY')
    return ok({'revoked_other_sessions': others})


@api('GET', 'DELETE', auth='any')
def sessions_list(request):
    if request.method == 'DELETE':
        n = revoke_all_sessions(request.user, exclude=request.api_session)
        services.audit(request, 'MOBILE_SESSIONS_REVOKED_ALL', severity='warning',
                       metadata={'count': n, 'channel': request.client_type})
        return ok({'revoked': n})
    qs = MobileSession.objects.filter(user=request.user, revoked_at__isnull=True,
                                      expires_at__gt=timezone.now()).order_by('-created_at')
    current = request.api_session.id if request.api_session else None
    return ok({'sessions': [session_json(m, current) for m in qs]})


@api('DELETE', auth='any')
def session_revoke(request, session_id):
    m = MobileSession.objects.filter(pk=uuid_or_404(session_id), user=request.user).first()
    if not m:
        raise ApiError('NOT_FOUND', 'Không tìm thấy phiên đăng nhập.', 404)
    m.revoke()
    services.audit(request, 'MOBILE_SESSION_REVOKED', metadata={'session_id': str(m.id), 'channel': request.client_type})
    return ok()


@api('PUT', 'DELETE', auth='any')
def push_token(request):
    session = request.api_session
    if session is None:
        raise ApiError('APP_ONLY', 'Chức năng push token chỉ dành cho app di động.', 400)
    if request.method == 'DELETE':
        session.fcm_token = ''
        session.save(update_fields=['fcm_token'])
        return ok()
    data = read_json(request)
    token = s(data, 'fcm_token', 512)
    if token:
        claim_fcm_token(session, token)
    if 'push_enabled' in data:
        session.push_enabled = bool(data['push_enabled'])
        session.save(update_fields=['push_enabled'])
    return ok({'push_enabled': session.push_enabled, 'has_push_token': bool(session.fcm_token)})


@api('GET', auth='any')
def two_factor_status(request):
    cfg = TwoFactorConfig.objects.filter(user=request.user).first()
    methods = cfg.available_methods() if cfg else []
    return ok({'enabled': request.user.two_fa_enabled, 'methods': methods,
               'usable_in_app': [m for m in methods if m in ('totp', 'email')],
               'manage_on_web': True})


_SETUP_SALT = 'smartlock.api.totp-setup.v1'
SETUP_TTL_SECONDS = 10 * 60
MAX_SETUP_FAILS = 5
MAX_PASSWORD_FAILS = 5


def _qr_data_uri(text: str) -> str:
    img = qrcode.make(text, image_factory=qrcode.image.svg.SvgPathImage, box_size=10, border=2)
    buf = io.BytesIO()
    img.save(buf)
    return 'data:image/svg+xml;base64,' + base64.b64encode(buf.getvalue()).decode()


def _recent_fails(user, action) -> int:
    return AuditLog.objects.filter(action=action, actor_user=user,
                                   created_at__gte=timezone.now() - timedelta(minutes=15)).count()


def _require_password(request, data):
    user = request.user
    if _recent_fails(user, 'TWO_FACTOR_PASSWORD_FAILED') >= MAX_PASSWORD_FAILS:
        raise ApiError('RATE_LIMITED', 'Nhập sai mật khẩu quá nhiều lần. Thử lại sau 15 phút.', 429)
    if not user.check_password(str(data.get('password') or '')):
        services.audit(request, 'TWO_FACTOR_PASSWORD_FAILED', success=False, severity='warning', target_user=user)
        raise ApiError('WRONG_PASSWORD', 'Mật khẩu không đúng.', 400, field='password')


def _after_added(request, user, method) -> dict:
    services.audit(request, 'TWO_FACTOR_METHOD_ADDED', target_user=user, severity='warning',
                   metadata={'method': method})
    services.notify(user, 'Đã thêm phương thức 2FA', f'Phương thức {method.upper()} vừa được thêm vào tài khoản.',
                    severity='info', type_='SECURITY')
    was = user.two_fa_enabled
    now = sync_two_fa_flag(user)
    auto = now and not was
    if auto:
        cfg = services.get_cfg(user)
        cfg.enabled_at = timezone.now()
        cfg.save(update_fields=['enabled_at', 'updated_at'])
        services.audit(request, 'TWO_FACTOR_ENABLED', target_user=user, severity='warning',
                       metadata={'method': method, 'auto': True})
    return {'two_fa_enabled': now, 'auto_enabled': auto,
            'message': ('Đã thêm phương thức xác thực và bật 2FA. Từ lần đăng nhập sau bạn sẽ được yêu cầu xác thực.'
                        if auto else 'Đã thêm phương thức xác thực.')}


def _after_removed(request, user, method) -> dict:
    cfg = services.get_cfg(user)
    left = cfg.available_methods()
    was = user.two_fa_enabled
    if cfg.preferred_method not in left:
        cfg.preferred_method = left[0] if left else ''
    if not left:
        cfg.enabled_at = None
    cfg.save()
    now = sync_two_fa_flag(user)
    services.audit(request, 'TWO_FACTOR_METHOD_REMOVED', target_user=user, severity='warning',
                   metadata={'method': method})
    services.notify(user, 'Đã gỡ phương thức 2FA', f'Phương thức {method.upper()} vừa được gỡ khỏi tài khoản.',
                    severity='warning', type_='SECURITY')
    auto_off = was and not now
    if auto_off:
        services.audit(request, 'TWO_FACTOR_DISABLED', target_user=user, severity='warning',
                       metadata={'method': method, 'auto': True})
        services.notify(user, 'Đã tắt xác thực 2 lớp',
                        'Tài khoản không còn phương thức 2FA nào nên xác thực 2 lớp đã được tắt.',
                        severity='warning', type_='SECURITY')
    return {'two_fa_enabled': now, 'auto_disabled': auto_off,
            'message': ('Đã gỡ phương thức xác thực. Xác thực 2 lớp đã được tắt vì không còn phương thức nào.'
                        if auto_off else 'Đã gỡ phương thức xác thực.')}


def _web_only(request):
    if request.client_type != 'web':
        raise ApiError('WEB_ONLY', 'Passkey chỉ thiết lập được trên web.', 400)


@api('POST', auth='any')
def totp_begin(request):
    user = request.user
    if services.get_cfg(user).totp_confirmed:
        raise ApiError('ALREADY_SET', 'Google Authenticator đã được thiết lập. Hãy gỡ trước nếu muốn cài lại.', 409)
    secret = pyotp.random_base32()
    uri = pyotp.TOTP(secret).provisioning_uri(name=user.email, issuer_name=services.TOTP_ISSUER)
    token = signing.dumps({'uid': str(user.id), 'secret': secret}, salt=_SETUP_SALT)
    return ok({'setup_token': token, 'qr': _qr_data_uri(uri), 'otpauth_uri': uri,
               'secret': ' '.join(secret[i:i + 4] for i in range(0, len(secret), 4)),
               'expires_in': SETUP_TTL_SECONDS})


@api('POST', auth='any')
def totp_confirm(request):
    user, data = request.user, read_json(request)
    if _recent_fails(user, 'TWO_FACTOR_SETUP_FAILED') >= MAX_SETUP_FAILS:
        raise ApiError('RATE_LIMITED', 'Sai quá nhiều lần. Hãy bắt đầu thiết lập lại sau 15 phút.', 429)
    try:
        st = signing.loads(s(data, 'setup_token', 2000, required=True), salt=_SETUP_SALT, max_age=SETUP_TTL_SECONDS)
    except signing.SignatureExpired:
        raise ApiError('SETUP_EXPIRED', 'Phiên thiết lập đã hết hạn. Hãy bắt đầu lại.', 400)
    except signing.BadSignature:
        services.audit(request, 'TWO_FACTOR_SETUP_TOKEN_BAD', success=False, severity='warning', target_user=user)
        raise ApiError('SETUP_INVALID', 'Phiên thiết lập không hợp lệ. Hãy bắt đầu lại.', 400)
    if st.get('uid') != str(user.id):
        raise ApiError('SETUP_INVALID', 'Phiên thiết lập không hợp lệ. Hãy bắt đầu lại.', 400)

    code = services.digits(s(data, 'code', 20))
    totp = pyotp.TOTP(st['secret'])
    step_now = int(timezone.now().timestamp() // totp.interval)
    matched = None
    for offset in (-1, 0, 1):
        if len(code) == 6 and services.hmac.compare_digest(totp.at((step_now + offset) * totp.interval), code):
            matched = step_now + offset
    if matched is None:
        services.audit(request, 'TWO_FACTOR_SETUP_FAILED', success=False, severity='warning', target_user=user)
        raise ApiError('TWO_FACTOR_INVALID', 'Mã không đúng. Kiểm tra lại giờ trên điện thoại và thử lại.', 400)

    with transaction.atomic():
        cfg = TwoFactorConfig.objects.select_for_update().get_or_create(user=user)[0]
        cfg.set_totp_secret(st['secret'])
        cfg.totp_confirmed = True
        cfg.totp_last_step = matched
        if not cfg.preferred_method:
            cfg.preferred_method = TwoFactorConfig.METHOD_TOTP
        cfg.save()
    return ok(_after_added(request, user, 'totp'))


@api('POST', auth='any')
def email_send(request):
    user = request.user
    if not user.email_verified:
        raise ApiError('EMAIL_NOT_VERIFIED', 'Email chưa được xác thực.', 400)
    res = services.send_email_code(user, 'SETUP')
    if res == 'cooldown':
        raise ApiError('COOLDOWN', f'Vui lòng đợi {services.EMAIL_CODE_COOLDOWN} giây trước khi gửi lại.', 429,
                       retry_after_seconds=services.EMAIL_CODE_COOLDOWN)
    if res != 'sent':
        raise ApiError('MAIL_FAILED', 'Không gửi được email. Vui lòng thử lại sau.', 502)
    return ok({'sent': True, 'masked_email': services.mask_email(user.email),
               'expires_in': services.EMAIL_CODE_TTL_MIN * 60,
               'message': f'Đã gửi mã đến {services.mask_email(user.email)}.'})


@api('POST', auth='any')
def email_confirm(request):
    user, data = request.user, read_json(request)
    if not services.verify_email_code(user, s(data, 'code', 20), 'SETUP'):
        raise ApiError('TWO_FACTOR_INVALID', 'Mã không đúng hoặc đã hết hạn.', 400)
    with transaction.atomic():
        cfg = TwoFactorConfig.objects.select_for_update().get_or_create(user=user)[0]
        cfg.email_otp_enabled = True
        if not cfg.preferred_method:
            cfg.preferred_method = TwoFactorConfig.METHOD_EMAIL
        cfg.save()
    return ok(_after_added(request, user, 'email'))


@api('POST', auth='any')
def passkey_options(request):
    _web_only(request)
    user = request.user
    rp_id, _origin, rp_name = services.webauthn_rp(request)
    options = generate_registration_options(
        rp_id=rp_id, rp_name=rp_name, user_id=user.pk.bytes, user_name=user.email,
        user_display_name=user.full_name or user.username,
        exclude_credentials=[PublicKeyCredentialDescriptor(id=base64url_to_bytes(c.credential_id))
                             for c in Fido2Credential.objects.filter(user=user)],
        authenticator_selection=AuthenticatorSelectionCriteria(
            resident_key=ResidentKeyRequirement.PREFERRED,
            user_verification=UserVerificationRequirement.PREFERRED))
    request.session['webauthn_reg'] = {'challenge': bytes_to_base64url(options.challenge),
                                       'ts': int(timezone.now().timestamp())}
    return ok({'options': json.loads(options_to_json(options))})


@api('POST', auth='any')
def passkey_register(request):
    _web_only(request)
    user, data = request.user, read_json(request)
    state = request.session.pop('webauthn_reg', None)
    if not state or int(timezone.now().timestamp()) - int(state.get('ts', 0)) > services.WEBAUTHN_TTL:
        raise ApiError('PASSKEY_EXPIRED', 'Yêu cầu không hợp lệ hoặc đã hết hạn. Hãy thử lại.', 400)
    credential = data.get('credential') if isinstance(data.get('credential'), dict) else {}
    rp_id, origin, _name = services.webauthn_rp(request)
    try:
        v = verify_registration_response(credential=credential,
                                         expected_challenge=base64url_to_bytes(state['challenge']),
                                         expected_rp_id=rp_id, expected_origin=origin,
                                         require_user_verification=False)
    except Exception:
        raise ApiError('PASSKEY_INVALID', 'Không xác minh được passkey.', 400)
    cred_id = bytes_to_base64url(v.credential_id)
    if len(cred_id) > 512 or Fido2Credential.objects.filter(credential_id=cred_id).exists():
        raise ApiError('PASSKEY_EXISTS', 'Passkey này đã được đăng ký.', 409)
    transports = data.get('transports') if isinstance(data.get('transports'), list) else []
    try:
        with transaction.atomic():
            Fido2Credential.objects.create(
                user=user, credential_id=cred_id, public_key=v.credential_public_key, sign_count=v.sign_count,
                transports=[str(t)[:20] for t in transports][:8], name=s(data, 'name', 100) or 'Passkey')
    except IntegrityError:
        raise ApiError('PASSKEY_EXISTS', 'Passkey này đã được đăng ký.', 409)
    with transaction.atomic():
        cfg = services.get_cfg(user)
        if not cfg.preferred_method:
            cfg.preferred_method = TwoFactorConfig.METHOD_FIDO2
            cfg.save(update_fields=['preferred_method', 'updated_at'])
    return ok(_after_added(request, user, 'fido2'), 201)


@api('POST', auth='any')
def passkey_remove(request, cred_id):
    user, data = request.user, read_json(request)
    cfg = services.get_cfg(user)
    cred = Fido2Credential.objects.filter(pk=services.parse_uuid(cred_id), user=user).first()
    if not cred:
        raise ApiError('NOT_FOUND', 'Không tìm thấy passkey.', 404)
    _require_password(request, data)
    cred.delete()
    return ok(_after_removed(request, user, 'fido2'))


@api('POST', auth='any')
def method_remove(request, method):
    user, data = request.user, read_json(request)
    cfg = services.get_cfg(user)
    if method not in ('totp', 'email'):
        raise ApiError('BAD_METHOD', 'Phương thức không hợp lệ.', 400)
    active = cfg.totp_confirmed if method == 'totp' else cfg.email_otp_enabled
    if not active:
        raise ApiError('NOT_SET', 'Phương thức này chưa được thiết lập.', 409)
    _require_password(request, data)
    if method == 'totp':
        cfg.totp_secret_encrypted = ''
        cfg.totp_confirmed = False
        cfg.totp_last_step = 0
    else:
        cfg.email_otp_enabled = False
    cfg.save()
    return ok(_after_removed(request, user, method))
