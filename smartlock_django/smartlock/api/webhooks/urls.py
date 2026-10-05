"""Route webhook - gắn dưới /api/webhooks/ (xem api/urls.py)."""
from django.urls import path

from . import mqtt

urlpatterns = [
    path('mqtt/auth/', mqtt.mqtt_auth, name='webhook-mqtt-auth'),
    path('mqtt/acl/', mqtt.mqtt_acl, name='webhook-mqtt-acl'),
]
