# manage_sys/api/settings_api.py
import re

from django.db import transaction

from smartlock import services

from .. import views as legacy
from . import serializers as S
from .common import ApiError, ok, as_int, get_body, require_full_power, route


def get_settings(request):
    st = services.SystemSettings.objects.select_related('updated_by').get_or_create(pk=1)[0]
    return ok({**S.settings_item(st), 'can_edit': legacy.has_full_power(request.user)})


def update_settings(request):
    """PATCH: chỉ gửi trường cần đổi. Trường không gửi giữ nguyên."""
    require_full_power(request, 'update_settings')
    body = get_body(request)
    st = services.SystemSettings.objects.get_or_create(pk=1)[0]      # bản tươi, không dùng bản cache để sửa
    before = {'expiry': st.verification_token_expiry_minutes, 'share': st.share_code_expiry_minutes,
              'timeout': st.session_timeout_hours, 'stages': st.login_lockout_stage_minutes,
              'registration_enabled': st.registration_enabled}
    expiry = as_int(body.get('verification_token_expiry_minutes', before['expiry']),
                    'verification_token_expiry_minutes', lo=1, hi=10080)
    share = as_int(body.get('share_code_expiry_minutes', before['share']), 'share_code_expiry_minutes', lo=1, hi=1440)
    timeout = as_int(body.get('session_timeout_hours', before['timeout']), 'session_timeout_hours', lo=1, hi=720)
    stages = body.get('login_lockout_stage_minutes', before['stages'])
    if isinstance(stages, str):
        stages = [x for x in re.split(r'[,\s]+', stages.strip()) if x]
    if not isinstance(stages, (list, tuple)) or not 1 <= len(stages) <= 10:
        raise ApiError('validation_error', 'Lockout stages: 1–10 mốc.', 400, {'login_lockout_stage_minutes': 'length'})
    stages = [as_int(x, 'login_lockout_stage_minutes', lo=1, hi=10080) for x in stages]
    reg = body.get('registration_enabled', before['registration_enabled'])
    reg = reg if isinstance(reg, bool) else str(reg).lower() in ('1', 'true', 'yes', 'on')
    try:
        with transaction.atomic():
            st.registration_enabled, st.verification_token_expiry_minutes = reg, expiry
            st.share_code_expiry_minutes, st.session_timeout_hours = share, timeout
            st.login_lockout_stage_minutes, st.updated_by = stages, request.user
            st.save()
            services.invalidate_system_settings()
            legacy.audit(request, 'MANAGE_SETTINGS_UPDATED', severity='warning', strict=True,
                         metadata={'registration_enabled': [before['registration_enabled'], reg],
                                   'before': {k: before[k] for k in ('expiry', 'share', 'timeout', 'stages')},
                                   'after': {'expiry': expiry, 'share': share, 'timeout': timeout, 'stages': stages}})
    except services.AuditWriteError:
        raise ApiError('audit_failed', legacy.AUDIT_ERROR, 500)
    return ok(S.settings_item(st))


settings_view = route({'GET': get_settings, 'PATCH': update_settings, 'PUT': update_settings})
