# manage_sys/api/announcements.py
from django.shortcuts import get_object_or_404

from smartlock.models import Announcement

from .. import views as legacy
from . import serializers as S
from .common import ApiError, ok, paginate, get_body, as_bool, route

LEVELS = ('info', 'warning', 'danger')


def list_ann(request):
    qs = Announcement.objects.select_related('created_by').order_by('-created_at')
    if request.GET.get('active') in ('0', '1', 'true', 'false'):
        qs = qs.filter(is_active=as_bool(request.GET['active']))
    items, meta = paginate(request, qs, S.announcement_item, per_page=request.GET.get('page_size') or 10)
    return ok(items, meta=meta)


def create_ann(request):
    body = get_body(request)
    title, text, level = str(body.get('title') or '').strip()[:200], str(body.get('body') or '').strip(), body.get('level')
    if not title or not text:
        raise ApiError('validation_error', 'Tiêu đề và nội dung không được để trống.', 400,
                       {k: 'required' for k, v in (('title', title), ('body', text)) if not v})
    if level not in LEVELS:
        raise ApiError('validation_error', 'Mức độ không hợp lệ.', 400, {'level': f'one of {LEVELS}'})
    ann = Announcement.objects.create(title=title, body=text, level=level, created_by=request.user)
    legacy.audit(request, 'MANAGE_ANNOUNCE_CREATED', metadata={'announcement_id': str(ann.id)})
    return ok(S.announcement_item(ann), status=201)


def _get(announcement_id):
    return get_object_or_404(Announcement.objects.select_related('created_by'), id=announcement_id)


def set_active(request, announcement_id):
    """Body {"is_active": true|false}; bỏ trống => đảo trạng thái (giống nút toggle của web)."""
    ann = _get(announcement_id)
    body = get_body(request)
    ann.is_active = as_bool(body['is_active']) if 'is_active' in body else not ann.is_active
    ann.save(update_fields=['is_active'])
    legacy.audit(request, 'MANAGE_ANNOUNCE_TOGGLED',
                 metadata={'announcement_id': str(ann.id), 'is_active': ann.is_active})
    return ok(S.announcement_item(ann))


def delete_ann(request, announcement_id):
    ann = _get(announcement_id)
    ann_id = str(ann.id)
    ann.delete()
    legacy.audit(request, 'MANAGE_ANNOUNCE_DELETED', severity='warning', metadata={'announcement_id': ann_id})
    return ok({'deleted': ann_id})


announcements_view = route({'GET': list_ann, 'POST': create_ann})
announcement_detail_view = route({'DELETE': delete_ann})
announcement_active_view = route({'POST': set_active})
