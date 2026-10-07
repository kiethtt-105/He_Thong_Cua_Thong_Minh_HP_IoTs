"""Quản lý 2FA của tôi - /api/app/me/two-factor/...  (thay cho các view tf-* cũ trong views.py)

Dùng chung WEB (session cookie + X-CSRFToken) và APP (Bearer). Riêng passkey chỉ có ý nghĩa trên web
(cần RP/origin của trình duyệt). 2FA tự bật/tắt theo số phương thức đang có (models.sync_two_fa_flag):
thêm phương thức đầu tiên -> tự bật; gỡ hết phương thức (có nhập lại mật khẩu) -> tự tắt. Không còn nút bật/tắt thủ công.

Trạng thái thiết lập TOTP KHÔNG lưu trong session: `setup_token` là token đã ký (django.core.signing), nên app và
web dùng chung được và không phụ thuộc cookie.
"""
import base64
import io
import json
from datetime import timedelta

import pyotp
import qrcode
import qrcode.image.svg
from django.core import signing
from django.db import IntegrityError, transaction
from django.utils import timezone
from webauthn import generate_registration_options, options_to_json, verify_registration_response
from webauthn.helpers import base64url_to_bytes, bytes_to_base64url
from webauthn.helpers.structs import (
    AuthenticatorSelectionCriteria, PublicKeyCredentialDescriptor, ResidentKeyRequirement,
    UserVerificationRequirement,
)

from smartlock import services, twofa
from smartlock.api.common import api, ApiError, iso, ok, read_json, s
from smartlock.models import AuditLog, Fido2Credential, TwoFactorConfig, sync_two_fa_flag

_SETUP_SALT = 'smartlock.api.totp-setup.v1'
SETUP_TTL_SECONDS = 10 * 60
MAX_SETUP_FAILS = 5                     # sai quá 5 lần / 15 phút -> chặn tạm
MAX_PASSWORD_FAILS = 5


# ----------------------------------------------------------------------------------------------- helpers
def _qr_data_uri(text: str) -> str:
    """QR dạng SVG (không cần Pillow -> chạy được trên Vercel)."""
    img = qrcode.make(text, image_factory=qrcode.image.svg.SvgPathImage, box_size=10, border=2)
    buf = io.BytesIO()
    img.save(buf)
    return 'data:image/svg+xml;base64,' + base64.b64encode(buf.getvalue()).decode()


def _recent_fails(user, action) -> int:
    return AuditLog.objects.filter(action=action, actor_user=user,
                                   created_at__gte=timezone.now() - timedelta(minutes=15)).count()


def _require_password(request, data):
    """Nhập lại mật khẩu cho thao tác nhạy cảm (gỡ phương thức). Có giới hạn số lần sai."""
    user = request.user
    if _recent_fails(user, 'TWO_FACTOR_PASSWORD_FAILED') >= MAX_PASSWORD_FAILS:
        raise ApiError('RATE_LIMITED', 'Nhập sai mật khẩu quá nhiều lần. Thử lại sau 15 phút.', 429)
    if not user.check_password(str(data.get('password') or '')):
        services.audit(request, 'TWO_FACTOR_PASSWORD_FAILED', success=False, severity='warning', target_user=user)
        raise ApiError('WRONG_PASSWORD', 'Mật khẩu không đúng.', 400, field='password')


def _after_added(request, user, method) -> dict:
    """Ghi log + thông báo; phương thức ĐẦU TIÊN tự bật 2FA."""
    services.audit(request, 'TWO_FACTOR_METHOD_ADDED', target_user=user, severity='warning',
                   metadata={'method': method})
    services.notify(user, 'Đã thêm phương thức 2FA', f'Phương thức {method.upper()} vừa được thêm vào tài khoản.',
                    severity='info', type_='SECURITY')
    was = user.two_fa_enabled
    now = sync_two_fa_flag(user)
    auto = now and not was
    if auto:
        cfg = twofa.get_cfg(user)
        cfg.enabled_at = timezone.now()
        cfg.save(update_fields=['enabled_at', 'updated_at'])
        services.audit(request, 'TWO_FACTOR_ENABLED', target_user=user, severity='warning',
                       metadata={'method': method, 'auto': True})
    return {'two_fa_enabled': now, 'auto_enabled': auto,
            'message': ('Đã thêm phương thức xác thực và bật 2FA. Từ lần đăng nhập sau bạn sẽ được yêu cầu xác thực.'
                        if auto else 'Đã thêm phương thức xác thực.')}


def _after_removed(request, user, method) -> dict:
    cfg = twofa.get_cfg(user)
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
    if auto_off:                                      # gỡ phương thức cuối -> 2FA tự tắt
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


# ----------------------------------------------------------------------------------------------- TOTP
@api('POST', auth='any')
def totp_begin(request):
    """Bắt đầu thiết lập Google Authenticator: trả secret + QR + setup_token (đã ký, hạn 10 phút)."""
    user = request.user
    if twofa.get_cfg(user).totp_confirmed:
        raise ApiError('ALREADY_SET', 'Google Authenticator đã được thiết lập. Hãy gỡ trước nếu muốn cài lại.', 409)
    secret = pyotp.random_base32()
    uri = pyotp.TOTP(secret).provisioning_uri(name=user.email, issuer_name=twofa.TOTP_ISSUER)
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

    code = twofa.digits(s(data, 'code', 20))
    totp = pyotp.TOTP(st['secret'])
    step_now = int(timezone.now().timestamp() // totp.interval)
    matched = None
    for offset in (-1, 0, 1):
        if len(code) == 6 and twofa.hmac.compare_digest(totp.at((step_now + offset) * totp.interval), code):
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


# ----------------------------------------------------------------------------------------------- Email OTP
@api('POST', auth='any')
def email_send(request):
    user = request.user
    if not user.email_verified:
        raise ApiError('EMAIL_NOT_VERIFIED', 'Email chưa được xác thực.', 400)
    res = twofa.send_email_code(user, 'SETUP')
    if res == 'cooldown':
        raise ApiError('COOLDOWN', f'Vui lòng đợi {twofa.EMAIL_CODE_COOLDOWN} giây trước khi gửi lại.', 429,
                       retry_after_seconds=twofa.EMAIL_CODE_COOLDOWN)
    if res != 'sent':
        raise ApiError('MAIL_FAILED', 'Không gửi được email. Vui lòng thử lại sau.', 502)
    return ok({'sent': True, 'masked_email': services.mask_email(user.email),
               'expires_in': twofa.EMAIL_CODE_TTL_MIN * 60,
               'message': f'Đã gửi mã đến {services.mask_email(user.email)}.'})


@api('POST', auth='any')
def email_confirm(request):
    user, data = request.user, read_json(request)
    if not twofa.verify_email_code(user, s(data, 'code', 20), 'SETUP'):
        raise ApiError('TWO_FACTOR_INVALID', 'Mã không đúng hoặc đã hết hạn.', 400)
    with transaction.atomic():
        cfg = TwoFactorConfig.objects.select_for_update().get_or_create(user=user)[0]
        cfg.email_otp_enabled = True
        if not cfg.preferred_method:
            cfg.preferred_method = TwoFactorConfig.METHOD_EMAIL
        cfg.save()
    return ok(_after_added(request, user, 'email'))


# ----------------------------------------------------------------------------------------------- Passkey (web)
@api('POST', auth='any')
def passkey_options(request):
    _web_only(request)
    user = request.user
    rp_id, _origin, rp_name = twofa.webauthn_rp(request)
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
    if not state or int(timezone.now().timestamp()) - int(state.get('ts', 0)) > twofa.WEBAUTHN_TTL:
        raise ApiError('PASSKEY_EXPIRED', 'Yêu cầu không hợp lệ hoặc đã hết hạn. Hãy thử lại.', 400)
    credential = data.get('credential') if isinstance(data.get('credential'), dict) else {}
    rp_id, origin, _name = twofa.webauthn_rp(request)
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
        cfg = twofa.get_cfg(user)
        if not cfg.preferred_method:
            cfg.preferred_method = TwoFactorConfig.METHOD_FIDO2
            cfg.save(update_fields=['preferred_method', 'updated_at'])
    return ok(_after_added(request, user, 'fido2'), 201)


@api('POST', auth='any')
def passkey_remove(request, cred_id):
    user, data = request.user, read_json(request)
    cfg = twofa.get_cfg(user)
    cred = Fido2Credential.objects.filter(pk=services.parse_uuid(cred_id), user=user).first()
    if not cred:
        raise ApiError('NOT_FOUND', 'Không tìm thấy passkey.', 404)
    _require_password(request, data)
    cred.delete()
    return ok(_after_removed(request, user, 'fido2'))


# ----------------------------------------------------------------------------------------------- gỡ TOTP / Email
@api('POST', auth='any')
def method_remove(request, method):
    user, data = request.user, read_json(request)
    cfg = twofa.get_cfg(user)
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