"""Khoá + lệnh điều khiển - /api/app/devices/..., /api/app/commands/..."""
from django.urls import path

from . import commands, devices

urlpatterns = [
    path('devices/', devices.devices_list, name='devices'),
    path('devices/claim/', devices.device_claim, name='device-claim'),
    path('devices/<uuid:device_id>/', devices.device_detail, name='device-detail'),
    path('devices/<uuid:device_id>/live/', devices.device_live, name='device-live'),
    path('devices/<uuid:device_id>/commands/', commands.device_command, name='device-command'),            # POST gửi lệnh
    path('devices/<uuid:device_id>/commands/history/', commands.device_commands_list, name='device-commands'),
    path('commands/<uuid:command_id>/', commands.command_status, name='command-status'),
    path('devices/<uuid:device_id>/ble-ticket/', commands.device_ble_ticket, name='ble-ticket'),
    path('devices/<uuid:device_id>/nfc-ticket/', commands.device_nfc_ticket, name='nfc-ticket'),
]
