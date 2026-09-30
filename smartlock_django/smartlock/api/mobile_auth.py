# smartlock/api/mobile_auth.py
"""
Xác thực Bearer cho app di động.

- Access token: chuỗi ký (django.core.signing) chứa id phiên, sống MOBILE_ACCESS_TOKEN_SECONDS (15 phút).
  Mỗi request kiểm tra phiên còn hiệu lực -> thu hồi từ xa có tác dụng ngay.
- Refresh token: chuỗi ngẫu nhiên, DB chỉ lưu SHA-256, xoay vòng mỗi lần refresh.
  Dùng lại token cũ (ngoài khoảng ân hạn 10s) = nghi bị đánh cắp -> huỷ cả phiên.
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

from ..models import MobileSession

ACCESS_SALT = 'smartlock.mobile.access'
REUSE_GRACE_SECONDS = 10
TOUCH_INTERVAL = timedelta(minutes=5)


def _h(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def _access_seconds() -> int:
    return getattr(settings, 'MOBILE_ACCESS_TOKEN_SECONDS', 900)


def _refresh_days() -> int:
    return getattr(settings, 'MOBILE_REFRESH_TOKEN_DAYS', 30)


def _access_token(session: MobileSession) -> str:
    return signing.dumps({'sid': str(session.id), 'uid': str(session.user_id)}, salt=ACCESS_SALT)


def _token_payload(session: MobileSession, refresh: str) -> dict:
    return {'token_type': 'Bearer', 'access_token': _access_token(session),
            'expires_in': _access_seconds(), 'refresh_token': refresh}


def issue_session(user, *, ip=None, device_name='', platform='android', app_version='', fcm_token=''):
    """Tạo phiên mới + cặp token. Trả (session, payload)."""
    now = timezone.now()
    if fcm_token:  # 1 máy chỉ gắn với 1 phiên: gỡ token khỏi phiên cũ (vd. đổi tài khoản trên cùng máy)
        MobileSession.objects.filter(fcm_token=fcm_token).update(fcm_token='')

    limit = getattr(settings, 'MOBILE_MAX_SESSIONS_PER_USER', 10)
    active = list(MobileSession.objects.filter(user=user, revoked_at__isnull=True, expires_at__gt=now)
                  .order_by('created_at'))
    for old in active[:max(0, len(active) - (limit - 1))]:
        old.revoke()

    refresh = secrets.token_urlsafe(48)
    session = MobileSession.objects.create(
        user=user, refresh_hash=_h(refresh), device_name=(device_name or '')[:100],
        platform=(platform or 'android')[:20], app_version=(app_version or '')[:30],
        fcm_token=fcm_token or '', ip_address=ip, last_used_at=now,
        expires_at=now + timedelta(days=_refresh_days()),
    )
    return session, _token_payload(session, refresh)


def rotate_refresh(refresh_token: str, ip=None):
    """Đổi refresh token lấy cặp mới. Trả (session, payload) hoặc raise AuthenticationFailed."""
    from ..models import AuditLog
    h = _h(refresh_token or '')
    now = timezone.now()
    error = None
    result = None
    with transaction.atomic():
        session = (MobileSession.objects.select_for_update().select_related('user')
                   .filter(refresh_hash=h).first())
        if session is None:
            reused = MobileSession.objects.select_for_update().filter(prev_refresh_hash=h).first()
            if reused is None:
                error = ('invalid_refresh', 'Refresh token không hợp lệ.')
            elif reused.last_used_at and (now - reused.last_used_at).total_seconds() <= REUSE_GRACE_SECONDS:
                error = ('invalid_refresh', 'Refresh token đã được dùng, hãy dùng token mới.')
            else:
                reused.revoke()
                AuditLog.objects.create(
                    target_user=reused.user, action='MOBILE_REFRESH_REUSE', severity='critical',
                    success=False, ip_address=ip, metadata={'session_id': str(reused.id)})
                error = ('session_revoked', 'Phiên đã bị thu hồi vì phát hiện dùng lại token cũ.')
        elif not session.is_active or not session.user.is_active:
            error = ('session_revoked', 'Phiên đã hết hạn hoặc bị thu hồi.')
        else:
            new_refresh = secrets.token_urlsafe(48)
            session.prev_refresh_hash = session.refresh_hash
            session.refresh_hash = _h(new_refresh)
            session.last_used_at = now
            session.expires_at = now + timedelta(days=_refresh_days())
            if ip:
                session.ip_address = ip
            session.save(update_fields=['prev_refresh_hash', 'refresh_hash', 'last_used_at',
                                        'expires_at', 'ip_address'])
            result = (session, _token_payload(session, new_refresh))
    if error:
        raise AuthenticationFailed(error[1], code=error[0])
    return result


def revoke_all_sessions(user, except_session=None) -> int:
    qs = MobileSession.objects.filter(user=user, revoked_at__isnull=True)
    if except_session is not None:
        qs = qs.exclude(pk=except_session.pk)
    return qs.update(revoked_at=timezone.now(), fcm_token='')


class MobileTokenAuthentication(BaseAuthentication):
    """Authorization: Bearer <access_token>. request.auth = MobileSession hiện tại."""

    def authenticate(self, request):
        parts = get_authorization_header(request).split()
        if not parts or parts[0].lower() != b'bearer':
            return None  # để SessionAuthentication (web) xử lý
        if len(parts) != 2:
            raise AuthenticationFailed('Header Authorization không hợp lệ.', code='invalid_token')
        try:
            data = signing.loads(parts[1].decode(), salt=ACCESS_SALT, max_age=_access_seconds())
        except signing.SignatureExpired:
            raise AuthenticationFailed('Access token đã hết hạn.', code='token_expired')
        except (signing.BadSignature, UnicodeDecodeError):
            raise AuthenticationFailed('Access token không hợp lệ.', code='invalid_token')

        session = MobileSession.objects.select_related('user').filter(pk=data.get('sid')).first()
        if session is None or not session.is_active or not session.user.is_active:
            raise AuthenticationFailed('Phiên đăng nhập đã bị thu hồi.', code='session_revoked')
        now = timezone.now()
        if session.last_used_at is None or now - session.last_used_at > TOUCH_INTERVAL:
            MobileSession.objects.filter(pk=session.pk).update(last_used_at=now)
        return session.user, session

    def authenticate_header(self, request):
        return 'Bearer'
