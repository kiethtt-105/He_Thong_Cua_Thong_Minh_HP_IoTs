"""Route cho KHOÁ + webhook + system - ghép vào api/urls.py."""
from django.urls import path

from . import access, ops, system, webhooks

# /api/device/
device_patterns = [
    path('config/', ops.config, name='dev-config'),
    path('heartbeat/', ops.heartbeat, name='dev-heartbeat'),
    path('commands/', ops.commands, name='dev-commands'),
    path('ack/', ops.ack, name='dev-ack'),
    path('access/rfid/', access.access_rfid, name='dev-access-rfid'),
    path('access/pin/', access.access_pin, name='dev-access-pin'),
    path('access/face/', access.access_face, name='dev-access-face'),
    path('access/phone/', access.access_phone, name='dev-access-phone'),
    path('events/', ops.event, name='dev-event'),
]

# /api/webhooks/
webhook_patterns = [
    path('mqtt/auth/', webhooks.mqtt_auth, name='webhook-mqtt-auth'),
    path('mqtt/acl/', webhooks.mqtt_acl, name='webhook-mqtt-acl'),
]

# /api/system/
system_patterns = [
    path('health/', system.health, name='system-health'),
    path('config/', system.config, name='system-config'),
]
