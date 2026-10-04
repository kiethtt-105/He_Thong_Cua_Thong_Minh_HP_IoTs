"""Route của API cho KHOÁ - gắn dưới /api/v1/device/ (xem api/urls.py)."""
from django.urls import path

from . import access, commands, config, events, heartbeat

urlpatterns = [
    path('config/', config.config, name='dev-config'),
    path('heartbeat/', heartbeat.heartbeat, name='dev-heartbeat'),
    path('commands/', commands.commands, name='dev-commands'),
    path('ack/', commands.ack, name='dev-ack'),
    path('access/rfid/', access.access_rfid, name='dev-access-rfid'),
    path('access/pin/', access.access_pin, name='dev-access-pin'),
    path('access/face/', access.access_face, name='dev-access-face'),
    path('access/phone/', access.access_phone, name='dev-access-phone'),
    path('events/', events.event, name='dev-event'),
]
