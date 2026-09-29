# smartlock/api/mobile_auth.py
"""
Xác thực Bearer cho app Android, không cần thư viện ngoài.

  access token : chuỗi ký (django.core.signing) chứa session_id, sống ngắn (mặc định 15 phút).
                 Mỗi request đều tra MobileSession nên thu hồi phiên có hiệu lực ngay.
  refresh token: chuỗi ngẫu nhiên, DB chỉ lưu SHA-256, xoay vòng mỗi lần refresh (mặc định sống 30 ngày,
                 trượt theo lần dùng). Dùng lại token cũ => coi là bị lộ => huỷ phiên.
  pending token: chuỗi ký sống 10 phút cho bước 2FA sau khi mật khẩu đã đúng.

Cấu hình tuỳ chọn trong settings.py:
  MOBILE_ACCESS_TOKEN_SECONDS = 900
  MOBILE_REFRESH_TOKEN_DAYS   = 30
  MOBILE_MAX_SESSIONS_PER_USER = 10
"""
import hashlib
import secrets
from datetime import timedelta

from django.conf import settings
from django.core import signing
from django.core.cache import cache
from django.db import transaction
from django.utils import timezone
from rest_framework.authentication import BaseAuthentication, get_authorization_header
from rest_framework.exceptions import AuthenticationFailed

from ..models import MobileSession
from ..utils import SmartlockUtils as U

ACCESS_SALT = 'smartlock.mobile.access.v1'
PENDING_SALT = 'smartlock.mobile.2fa.v1'

ACCESS_TTL = int(getattr(settings, 'MOBILE_ACCESS_TOKEN_SECONDS', 15 * 60))
REFRESH_TTL = timedelta(days=int(getattr(settings, 'MOBILE_REFRESH_TOKEN_DAYS', 30)))
MAX_SESSIONS = int(getattr(settings, 'MOBILE_MAX_SESSIONS_PER_USER', 10))
PENDING_TTL = 10 * 60
MAX_PENDING_FAILS = 5
_TOUCH_EVERY = timedelta(minutes=5)


def _fail(detail, code):
    raise AuthenticationFailed({'detail': detail, 'code': code})


def _h(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def user_allowed(user) -> bool:
    """Cổng người dùng: tài khoản phải active và KHÔNG phải admin (admin chỉ dùng cổng manage_sys)."""
    return bool(user and user.is_active and not U.is_admin(user))


# ------------------------------------------------------------------ access / refresh
def make_access_token(session: MobileSession) -> str:
    return signing.dumps({'sid': str(session.id), 'uid': str(session.user_id)},
                         salt=ACCESS_SALT, compress=False)


def token_payload(session: MobileSession, refresh_token: str) -> dict:
    return {
        'token_type': 'Bearer',
        'access_token': make_access_token(session),
        'expires_in': ACCESS_TTL,
        'refresh_token': refresh_token,
        'session_id': str(session.id),
    }


def claim_fcm_token(session: MobileSession, fcm_token: str, enabled: bool = True):
    """1 FCM token chỉ thuộc 1 phiên: gỡ khỏi phiên khác (vd. cùng máy đổi tài khoản)."""
    fcm_token = (fcm_token or '').strip()[:512]
    if fcm_token:
        MobileSession.objects.filter(fcm_token=fcm_token).exclude(pk=session.pk).update(fcm_token='')
    session.fcm_token = fcm_token
    session.push_enabled = enabled
    session.save(update_fields=['fcm_token', 'push_enabled'])


def issue_session(request, user, *, device_name='', platform='android', app_version='', fcm_token=''):
    """Tạo phiên mới. Trả (session, payload có access_token + refresh_token)."""
    refresh = secrets.token_urlsafe(48)
    now = timezone.now()
    session = MobileSession.objects.create(
        user=user, refresh_hash=_h(refresh), device_name=(device_name or '')[:100],
        platform=(platform or 'android')[:20], app_version=(app_version or '')[:30],
        ip_address=U.client_ip(request), last_used_at=now, expires_at=now + REFRESH_TTL,
    )
    if fcm_token:
        claim_fcm_token(session, fcm_token)
    # Giới hạn số phiên đang sống: huỷ các phiên cũ nhất.
    active_ids = list(MobileSession.objects.filter(user=user, revoked_at__isnull=True,
                                                   expires_at__gt=now)
                      .order_by('-created_at').values_list('id', flat=True))
    for old in MobileSession.objects.filter(id__in=active_ids[MAX_SESSIONS:]):
        old.revoke()
    return session, token_payload(session, refresh)


def rotate_refresh(refresh_token: str):
    """Đổi refresh token lấy cặp token mới. Ném AuthenticationFailed nếu không hợp lệ."""
    h = _h(refresh_token or '')
    reuse_detected = False
    session = None
    with transaction.atomic():
        session = (MobileSession.objects.select_for_update().select_related('user')
                   .filter(refresh_hash=h).first())
        if session is None:
            reuse_detected = MobileSession.objects.filter(prev_refresh_hash=h,
                                                          revoked_at__isnull=True).exists()
        else:
            now = timezone.now()
            if session.revoked_at or session.expires_at <= now or not user_allowed(session.user):
                session = None
            else:
                new_refresh = secrets.token_urlsafe(48)
                session.prev_refresh_hash = h
                session.refresh_hash = _h(new_refresh)
                session.last_used_at = now
                session.expires_at = now + REFRESH_TTL
                session.save(update_fields=['prev_refresh_hash', 'refresh_hash', 'last_used_at',
                                            'expires_at'])
                return session, token_payload(session, new_refresh)
    # Ngoài transaction để lệnh huỷ không bị rollback cùng lỗi.
    if reuse_detected:
        for s in MobileSession.objects.filter(prev_refresh_hash=h, revoked_at__isnull=True):
            s.revoke()
    _fail('Phiên đăng nhập không còn hiệu lực. Vui lòng đăng nhập lại.', 'invalid_refresh')


def revoke_user_sessions(user, except_session=None) -> int:
    qs = MobileSession.objects.filter(user=user, revoked_at__isnull=True)
    if except_session is not None:
        qs = qs.exclude(pk=except_session.pk)
    n = 0
    for s in qs:
        s.revoke()
        n += 1
    return n


# ------------------------------------------------------------------ DRF authentication
class MobileTokenAuthentication(BaseAuthentication):
    """Authorization: Bearer <access_token>. Không có header Bearer -> bỏ qua để SessionAuthentication (web) xử lý."""

    def authenticate_header(self, request):
        return 'Bearer realm="smartlock"'

    def authenticate(self, request):
        auth = get_authorization_header(request).split()
        if not auth or auth[0].lower() != b'bearer':
            return None
        if len(auth) != 2:
            _fail('Header Authorization không hợp lệ.', 'bad_header')
        try:
            data = signing.loads(auth[1].decode(), salt=ACCESS_SALT, max_age=ACCESS_TTL)
        except signing.SignatureExpired:
            _fail('Access token đã hết hạn.', 'token_expired')
        except (signing.BadSignature, UnicodeDecodeError):
            _fail('Access token không hợp lệ.', 'token_invalid')

        now = timezone.now()
        session = (MobileSession.objects.select_related('user')
                   .filter(pk=data.get('sid'), revoked_at__isnull=True, expires_at__gt=now).first())
        if not session or str(session.user_id) != data.get('uid'):
            _fail('Phiên đăng nhập đã bị thu hồi.', 'session_revoked')
        if not user_allowed(session.user):
            _fail('Tài khoản không còn được phép truy cập.', 'account_disabled')
        if not session.last_used_at or now - session.last_used_at > _TOUCH_EVERY:
            MobileSession.objects.filter(pk=session.pk).update(last_used_at=now)
        return session.user, session


# ------------------------------------------------------------------ pending 2FA token
def make_pending_token(user) -> str:
    return signing.dumps({'uid': str(user.pk), 'jti': secrets.token_urlsafe(9)},
                         salt=PENDING_SALT, compress=False)


def _dead_key(jti):
    return f'mob2fa_dead:{jti}'


def kill_pending(jti: str):
    cache.set(_dead_key(jti), 1, PENDING_TTL + 60)


def read_pending_token(token: str):
    """Trả (user, jti) hoặc ném AuthenticationFailed."""
    from ..models import User
    try:
        data = signing.loads(token or '', salt=PENDING_SALT, max_age=PENDING_TTL)
    except signing.BadSignature:      # gồm cả SignatureExpired
        _fail('Phiên xác thực 2 lớp đã hết hạn. Vui lòng đăng nhập lại.', 'pending_expired')
    if cache.get(_dead_key(data['jti'])):
        _fail('Phiên xác thực 2 lớp đã hết hạn. Vui lòng đăng nhập lại.', 'pending_expired')
    user = User.objects.filter(pk=data['uid'], is_active=True).first()
    if not user_allowed(user):
        _fail('Phiên xác thực 2 lớp đã hết hạn. Vui lòng đăng nhập lại.', 'pending_expired')
    return user, data['jti']


def pending_fail_count(jti: str) -> int:
    key = f'mob2fa_fails:{jti}'
    cache.add(key, 0, PENDING_TTL)
    try:
        return cache.incr(key)
    except ValueError:
        cache.set(key, 1, PENDING_TTL)
        return 1