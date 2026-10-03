# smartlock/live.py  -  trang xem TRỰC TIẾP tình trạng khoá (poll JSON 2s/lần)
from django.http import Http404, JsonResponse
from django.contrib.auth.decorators import login_required
from django.shortcuts import render
from django.utils import timezone

from . import services
from .models import AccessEvent, DeviceCommand, DeviceStatusLog

auth_required = login_required(login_url='smartlock:login')


def _device_or_404(request, device_id):
    d = services.accessible_devices(request.user).filter(pk=device_id).first()
    if not d:
        raise Http404
    return d


@auth_required
def live_page(request, device_id):
    return render(request, 'account/live.html', {'device': _device_or_404(request, device_id)})


@auth_required
def live_data(request, device_id):
    d = _device_or_404(request, device_id)
    # .using('default'): đọc thẳng Supabase, tránh trễ của bản sao local (~2s)
    log = DeviceStatusLog.objects.using('default').filter(device=d).order_by('-recorded_at').first()
    link = services.link_status(d)
    events = (AccessEvent.objects.using('default').filter(device=d).select_related('user')
              .order_by('-created_at')[:8])
    cmds = DeviceCommand.objects.filter(device=d).order_by('-created_at')[:5]
    resp = JsonResponse({
        'name': d.name, 'code': d.device_code, 'now': timezone.now().isoformat(),
        'connected': link['connected'], 'seconds_ago': link['seconds_ago'],
        'lock_state': log.lock_state if log else 'unknown', 'tamper': bool(log and log.tamper_detected),
        'battery': d.battery_level, 'firmware': d.firmware_version,
        'locked_out': services.in_lockout(d),
        'events': [{'at': e.created_at.isoformat(), 'method': e.method, 'ok': e.success, 'reason': e.reason,
                    'who': (e.user.full_name or e.user.username) if e.user_id else ''} for e in events],
        'commands': [{'at': c.created_at.isoformat(), 'type': c.command_type, 'status': c.status} for c in cmds],
    })
    resp['Cache-Control'] = 'no-store'
    return resp
