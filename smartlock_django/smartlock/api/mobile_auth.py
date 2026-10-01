# smartlock/api/mobile_auth.py
"""
Xác thực cho app di động.

  access token : chuỗi ký (django.core.signing), sống MOBILE_ACCESS_TOKEN_SECONDS (15 phút), kèm id phiên.
                 Mỗi request vẫn kiểm tra phiên trong DB -> thu hồi/đăng xuất có hiệu lực NGAY.
  refresh token: chuỗi ngẫu nhiên, DB chỉ lưu SHA-256. XOAY VÒNG mỗi lần refresh. Dùng lại token cũ
                 (ngoài khoảng ân hạn) = nghi bị đánh cắp -> thu hồi cả phiên.
"""
import hashlib
import secrets
from datetime import timedelta

from django.conf import settings
from django.core import signing
from django.db import transaction
from django.utils import timezone
from rest_framework.authentication import BaseAuthentication, get_authorization_header
from rest_framework.exceptions import AuthenticationFailed

from smartlock import services
from smartlock.models import MobileSession

ACCESS_SALT = 'smartlock.mobile.access.v1'
REFRESH_REUSE_GRACE_SECONDS = 10     # client gửi lại cùng refresh token do mạng chập chờn: không coi là bị đánh cắp
LAST_USED_WRITE_INTERVAL = 300       # chỉ ghi last_used_at tối đa 1 lần / 5 phút / phiên


def _h(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def _access_seconds() -> int:
    return int(getattr(settings, 'MOBILE_ACCESS_TOKEN_SECONDS', 900))


def _refresh_days() -> int:
    return int(getattr(settings, 'MOBILE_REFRESH_TOKEN_DAYS', 30))


def make_access_token(session: MobileSession) -> str:
    return signing.dumps({'u': str(session.user_id), 's': str(session.pk)}, salt=ACCESS_SALT, compress=False)


def _payload(session, refresh_plain):
    return {
        'access_token': make_access_token(session),
        'refresh_token': refresh_plain,
        'token_type': 'Bearer',
        'expires_in': _access_seconds(),
        'session_id': str(session.pk),
    }


def issue_session(request, user, *, device_name='', platform='android', app_version='', fcm_token=''):
    """Tạo phiên mới. Trả (session, payload token). Vượt MOBILE_MAX_SESSIONS_PER_USER thì thu hồi phiên cũ nhất."""
    platform = platform if platform in ('android', 'ios') else 'android'
    refresh_plain = secrets.token_urlsafe(48)
    now = timezone.now()
    with transaction.atomic():
        if fcm_token:   # 1 FCM token chỉ thuộc 1 phiên (tránh push nhầm người sau khi đổi tài khoản)
            MobileSession.objects.filter(fcm_token=fcm_token).update(fcm_token='')
        session = MobileSession.objects.create(
            user=user, refresh_hash=_h(refresh_plain), device_name=(device_name or '')[:100],
            platform=platform, app_version=(app_version or '')[:30], fcm_token=(fcm_token or '')[:512],
            ip_address=services.client_ip(request), last_used_at=now,
            expires_at=now + timedelta(days=_refresh_days()),
        )
        limit = int(getattr(settings, 'MOBILE_MAX_SESSIONS_PER_USER', 10))
        active = list(MobileSession.objects.filter(user=user, revoked_at__isnull=True, expires_at__gt=now)
                      .order_by('-created_at').values_list('pk', flat=True))
        if len(active) > limit:
            MobileSession.objects.filter(pk__in=active[limit:]).update(revoked_at=now, fcm_token='')
    _touch_last_login(user)
    return session, _payload(session, refresh_plain)


def _touch_last_login(user):
    type(user).objects.filter(pk=user.pk).update(last_login=timezone.now())


def rotate_refresh(request, refresh_plain: str):
    """Đổi refresh token lấy cặp token mới. Raise AuthenticationFailed nếu không hợp lệ."""
    if not refresh_plain or len(refresh_plain) > 200:
        raise AuthenticationFailed('Phiên đăng nhập không hợp lệ.', code='invalid_refresh')
    digest = _h(refresh_plain)
    now = timezone.now()
    with transaction.atomic():
        session = (MobileSession.objects.select_for_update().select_related('user')
                   .filter(refresh_hash=digest).first())
        if session is None:
            reused = (MobileSession.objects.select_for_update().select_related('user')
                      .filter(prev_refresh_hash=digest).first())
            if reused and reused.revoked_at is None:
                within_grace = (reused.last_used_at and
                                (now - reused.last_used_at).total_seconds() <= REFRESH_REUSE_GRACE_SECONDS)
                if not within_grace:
                    # Refresh token cũ bị dùng lại: có thể đã bị sao chép -> thu hồi cả phiên.
                    reused.revoked_at = now
                    reused.fcm_token = ''
                    reused.save(update_fields=['revoked_at', 'fcm_token'])
                    services.audit(request, 'MOBILE_REFRESH_REUSE', actor=reused.user, target_user=reused.user,
                                   success=False, severity='critical',
                                   metadata={'session_id': str(reused.pk)})
                    services.notify(reused.user, 'Phiên đăng nhập bị thu hồi',
                                    'Phát hiện token đăng nhập bị dùng lại trên một thiết bị. '
                                    'Phiên đó đã bị đăng xuất để bảo vệ tài khoản.',
                                    severity='critical', type_='SECURITY')
            raise AuthenticationFailed('Phiên đăng nhập không hợp lệ hoặc đã hết hạn.', code='invalid_refresh')
        if not session.is_active or not session.user.is_active or services.is_admin(session.user):
            raise AuthenticationFailed('Phiên đăng nhập đã hết hạn.', code='session_revoked')

        new_plain = secrets.token_urlsafe(48)
        session.prev_refresh_hash = session.refresh_hash
        session.refresh_hash = _h(new_plain)
        session.last_used_at = now
        session.expires_at = now + timedelta(days=_refresh_days())     # trượt hạn theo lần dùng
        session.ip_address = services.client_ip(request)
        session.save(update_fields=['prev_refresh_hash', 'refresh_hash', 'last_used_at', 'expires_at',
                                    'ip_address'])
    return session, _payload(session, new_plain)


def revoke_session(session: MobileSession):
    session.revoke()


def revoke_all_sessions(user, except_session_id=None) -> int:
    """Thu hồi mọi phiên app của user (đặt lại/đổi mật khẩu...). views.py (web) cũng gọi hàm này."""
    qs = MobileSession.objects.filter(user=user, revoked_at__isnull=True)
    if except_session_id:
        qs = qs.exclude(pk=except_session_id)
    return qs.update(revoked_at=timezone.now(), fcm_token='')


class MobileTokenAuthentication(BaseAuthentication):
    """Authorization: Bearer <access_token>"""
    keyword = b'bearer'

    def authenticate_header(self, request):
        return 'Bearer realm="smartlock"'

    def authenticate(self, request):
        parts = get_authorization_header(request).split()
        if not parts or parts[0].lower() != self.keyword:
            return None          # để authenticator kế tiếp (Session) thử
        if len(parts) != 2:
            raise AuthenticationFailed('Header Authorization không hợp lệ.', code='invalid_token')
        try:
            data = signing.loads(parts[1].decode(), salt=ACCESS_SALT, max_age=_access_seconds())
        except signing.SignatureExpired:
            raise AuthenticationFailed('Access token đã hết hạn.', code='token_expired')
        except (signing.BadSignature, UnicodeDecodeError):
            raise AuthenticationFailed('Access token không hợp lệ.', code='invalid_token')

        session = (MobileSession.objects.select_related('user')
                   .filter(pk=data.get('s'), user_id=data.get('u')).first())
        if session is None or not session.is_active:
            raise AuthenticationFailed('Phiên đăng nhập đã bị thu hồi hoặc hết hạn.', code='session_revoked')
        user = session.user
        if not user.is_active or services.is_admin(user):
            raise AuthenticationFailed('Tài khoản không được phép dùng ứng dụng.', code='account_disabled')

        now = timezone.now()
        if not session.last_used_at or (now - session.last_used_at).total_seconds() > LAST_USED_WRITE_INTERVAL:
            MobileSession.objects.filter(pk=session.pk).update(last_used_at=now)
        return user, session      # request.auth = MobileSession
