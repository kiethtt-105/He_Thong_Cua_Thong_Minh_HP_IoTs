"""Khuôn mặt (app gửi vector đặc trưng, không gửi ảnh)."""
from smartlock import services
from smartlock.api.common import api, ApiError, iso, ok, read_json, s, uuid_or_404
from smartlock.models import FaceProfile

from .helpers import managed_device


def _face_json(f) -> dict:
    return {'id': str(f.id), 'device_id': str(f.device_id), 'name': f.name or '', 'user': f.user.username,
            'is_active': f.is_active, 'consent_confirmed': f.consent_confirmed, 'created_at': iso(f.created_at)}


@api('GET', 'POST')
def device_faces(request, device_id):
    device = managed_device(request, device_id, 'manage_face_profiles')
    user = request.user
    if request.method == 'POST':
        if len(request.body) > 64 * 1024:
            raise ApiError('PAYLOAD_TOO_LARGE', 'Dữ liệu quá lớn.', 413)
        data = read_json(request)
        if data.get('consent_confirmed') is not True:
            raise ApiError('CONSENT_REQUIRED',
                           'Cần xác nhận người được đăng ký đã đồng ý thu thập dữ liệu khuôn mặt.', 400)
        name = s(data, 'name', 100) or (user.full_name or user.username)[:100]
        try:
            profile = services.enroll_face(device, user, data.get('embeddings'), name=name, request=request)
        except services.FaceEnrollError as exc:
            services.audit(request, 'FACE_PROFILE_ENROLL_FAILED', device=device, success=False, severity='warning',
                           metadata={'code': exc.code})
            raise ApiError(exc.code, exc.message, 422)
        if device.owner_id != user.id:
            services.notify(device.owner, 'Có khuôn mặt mới trên khoá của bạn',
                            f'{user.username} vừa đăng ký khuôn mặt cho "{device.name}".', device=device, type_='FACE')
        return ok({'profile': _face_json(profile), 'message': 'Đã đăng ký khuôn mặt.'}, 201)
    qs = FaceProfile.objects.filter(device=device).select_related('user')
    if device.owner_id != user.id:
        qs = qs.filter(user=user)
    return ok({'profiles': [_face_json(f) for f in qs.order_by('-created_at')]})


@api('DELETE')
def face_delete(request, profile_id):
    profile = FaceProfile.objects.select_related('device', 'user').filter(pk=uuid_or_404(profile_id)).first()
    if profile and profile.user_id != request.user.id and profile.device.owner_id != request.user.id:
        profile = None
    if not profile:
        services.audit(request, 'FACE_PROFILE_DELETE_DENIED', success=False, severity='warning',
                       metadata={'profile_id': str(profile_id)[:64]})
        raise ApiError('NOT_FOUND', 'Không tìm thấy hồ sơ khuôn mặt.', 404)
    device, owner_of_profile, info = profile.device, profile.user, {'face_profile_id': str(profile.id)}
    profile.delete()
    services.audit(request, 'FACE_PROFILE_DELETED', device=device, target_user=owner_of_profile,
                   severity='warning', metadata=info)
    return ok()
