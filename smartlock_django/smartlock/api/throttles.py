# smartlock/api/throttles.py
"""Throttle theo scope đã khai báo ở settings.REST_FRAMEWORK['DEFAULT_THROTTLE_RATES']."""
from rest_framework.throttling import SimpleRateThrottle


class _IPThrottle(SimpleRateThrottle):
    def get_cache_key(self, request, view):
        return self.cache_format % {'scope': self.scope, 'ident': self.get_ident(request)}


class _UserThrottle(SimpleRateThrottle):
    """Theo user đã đăng nhập; chưa đăng nhập thì theo IP."""
    def get_cache_key(self, request, view):
        user = getattr(request, 'user', None)
        ident = str(user.pk) if user is not None and user.is_authenticated else self.get_ident(request)
        return self.cache_format % {'scope': self.scope, 'ident': ident}


class AuthLoginThrottle(_IPThrottle):
    scope = 'auth_login'


class Auth2FAThrottle(_IPThrottle):
    scope = 'auth_2fa'


class AuthRegisterThrottle(_IPThrottle):
    scope = 'auth_register'


class AuthResetThrottle(_IPThrottle):
    scope = 'auth_reset'


class AuthRefreshThrottle(_IPThrottle):
    scope = 'auth_refresh'


class CommandThrottle(_UserThrottle):
    scope = 'command'


class RedeemThrottle(_UserThrottle):
    scope = 'redeem'
