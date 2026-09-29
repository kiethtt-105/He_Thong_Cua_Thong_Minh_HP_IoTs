# smartlock/rules_engine.py
"""
Rule engine: đánh giá các AutomationRule do user cấu hình (ngưỡng nằm trong DB, không hard-code).

Điểm vào:
  - evaluate_device_status(device, status_log)  <- mqtt_subscriber gọi sau mỗi gói status
  - evaluate_failed_access_burst(device)        <- gọi sau khi có lần mở cửa thất bại (tuỳ chọn)
  - evaluate_offline_devices()                  <- mark_offline_devices gọi định kỳ

Mỗi lần luật kích hoạt: tôn trọng cooldown, tạo Notification cho owner, thực hiện action
(NOTIFY_ONLY / AUTO_LOCK / TEMP_BLOCK_ACCESS) và ghi AutomationRuleLog.
"""
import logging
from datetime import timedelta
from decimal import Decimal

from django.db.models import Q
from django.utils import timezone

from .models import (
    AccessEvent, AuditLog, AutomationRule, AutomationRuleLog, Device, DeviceStatusLog, Notification,
)

logger = logging.getLogger('smartlock.rules_engine')

DEFAULT_WINDOW_SECONDS = 60


# ------------------------------------------------------------------ helpers
def _rules_for(device: Device, trigger_type: str):
    if not device.owner_id:
        return AutomationRule.objects.none()
    return (AutomationRule.objects
            .filter(is_active=True, trigger_type=trigger_type, owner_id=device.owner_id)
            .filter(Q(device=device) | Q(device__isnull=True)))


def _do_action(rule: AutomationRule, device: Device):
    if rule.action_type == AutomationRule.ACTION_AUTO_LOCK:
        _send_lock(rule, device)
    elif rule.action_type == AutomationRule.ACTION_TEMP_BLOCK_ACCESS:
        # access_control coi bản ghi ACCESS_BURST_LOCKOUT gần nhất là "đang khoá tạm".
        AuditLog.objects.create(
            device=device, action='ACCESS_BURST_LOCKOUT', severity='critical', success=False,
            metadata={'source': 'automation_rule', 'rule_id': str(rule.id)},
        )


def _send_lock(rule: AutomationRule, device: Device):
    from datetime import timedelta as _td
    import hashlib
    import secrets
    from .models import DeviceCommand
    from .mqtt_client import MqttPublishError, publish_command

    cmd = DeviceCommand.objects.create(
        device=device, issued_by=rule.owner, command_type='LOCK', status='pending',
        command_token_hash=hashlib.sha256(secrets.token_urlsafe(32).encode()).hexdigest(),
        expires_at=timezone.now() + _td(seconds=120),
    )
    try:
        publish_command(device.device_code, {
            'command_id': str(cmd.id), 'command': 'LOCK', 'token': cmd.command_token_hash,
            'source': 'automation_rule',
        })
        cmd.status = 'sent'
    except MqttPublishError as e:
        cmd.status = 'failed'
        logger.warning('rules_engine: publish LOCK thất bại cho %s: %s', device.device_code, e)
    cmd.save(update_fields=['status'])


def _fire(rule: AutomationRule, device: Device, measured, title: str, message: str) -> bool:
    """Kích hoạt luật nếu không còn trong cooldown. Trả True nếu đã kích hoạt."""
    if rule.is_in_cooldown():
        return False
    rule.mark_triggered()
    notification = Notification.objects.create(
        user=rule.owner, device=device, type='AUTOMATION_RULE',
        title=title[:150], message=message, severity=rule.notify_severity,
    )
    try:
        _do_action(rule, device)
    except Exception:
        logger.exception('rules_engine: lỗi khi thực hiện action %s của luật %s', rule.action_type, rule.id)
    AutomationRuleLog.objects.create(
        rule=rule, device=device, action_taken=rule.action_type, notification=notification,
        measured_value=None if measured is None else Decimal(str(measured)).quantize(Decimal('0.01')),
    )
    logger.info('rules_engine: luật "%s" kích hoạt cho %s (giá trị=%s)', rule.name, device.device_code, measured)
    return True


# ------------------------------------------------------------------ status-based triggers
def evaluate_device_status(device: Device, status_log: DeviceStatusLog) -> int:
    """Đánh giá các luật dựa trên gói status mới nhất. Trả về số luật đã kích hoạt."""
    fired = 0

    for rule in _rules_for(device, AutomationRule.TRIGGER_BATTERY_LOW):
        if rule.threshold_value is not None and status_log.battery_level < rule.threshold_value:
            fired += _fire(rule, device, status_log.battery_level, f'Pin yếu: {device.name}',
                           f'Pin thiết bị "{device.name}" còn {status_log.battery_level}% '
                           f'(ngưỡng {rule.threshold_value}%).')

    for rule in _rules_for(device, AutomationRule.TRIGGER_TAMPER_DETECTED):
        if status_log.tamper_detected:
            fired += _fire(rule, device, None, f'Cảnh báo tác động vật lý: {device.name}',
                           f'Thiết bị "{device.name}" phát hiện bị tác động vật lý (tamper).')

    for rule in _rules_for(device, AutomationRule.TRIGGER_TEMPERATURE_OUT_OF_RANGE):
        temp = status_log.temperature
        if rule.threshold_value is not None and temp is not None and temp > rule.threshold_value:
            fired += _fire(rule, device, temp, f'Nhiệt độ cao: {device.name}',
                           f'Nhiệt độ thiết bị "{device.name}" là {temp}°C (ngưỡng {rule.threshold_value}°C).')

    if status_log.lock_state == 'unlocked':
        for rule in _rules_for(device, AutomationRule.TRIGGER_DOOR_OPEN_TOO_LONG):
            if rule.threshold_value is None:
                continue
            open_since = _unlocked_since(device, status_log)
            seconds_open = (timezone.now() - open_since).total_seconds()
            if seconds_open >= float(rule.threshold_value):
                fired += _fire(rule, device, seconds_open, f'Cửa mở quá lâu: {device.name}',
                               f'Cửa "{device.name}" đã mở khoảng {int(seconds_open)} giây '
                               f'(ngưỡng {rule.threshold_value} giây).')
    return fired


def _unlocked_since(device: Device, current: DeviceStatusLog):
    """Thời điểm bắt đầu chuỗi trạng thái 'unlocked' liên tục gần nhất."""
    last_locked = (DeviceStatusLog.objects
                   .filter(device=device, lock_state='locked', recorded_at__lt=current.recorded_at)
                   .order_by('-recorded_at').first())
    qs = DeviceStatusLog.objects.filter(device=device, lock_state='unlocked')
    if last_locked:
        qs = qs.filter(recorded_at__gt=last_locked.recorded_at)
    first_open = qs.order_by('recorded_at').first()
    return first_open.recorded_at if first_open else current.recorded_at


# ------------------------------------------------------------------ access-based trigger
def evaluate_failed_access_burst(device: Device) -> int:
    """Luật 'N lần thất bại trong X giây' (threshold_value = N, threshold_window_seconds = X)."""
    fired = 0
    for rule in _rules_for(device, AutomationRule.TRIGGER_FAILED_ACCESS_BURST):
        if rule.threshold_value is None:
            continue
        window = rule.threshold_window_seconds or DEFAULT_WINDOW_SECONDS
        since = timezone.now() - timedelta(seconds=window)
        count = (AccessEvent.objects.filter(device=device, success=False, created_at__gte=since)
                 .exclude(reason__in=('DEVICE_LOCKED_OUT', 'MQTT_PUBLISH_FAILED')).count())
        if count >= rule.threshold_value:
            fired += _fire(rule, device, count, f'Nhiều lần mở cửa sai: {device.name}',
                           f'Thiết bị "{device.name}" có {count} lần mở cửa thất bại trong {window} giây.')
    return fired


# ------------------------------------------------------------------ offline trigger
def evaluate_offline_devices() -> int:
    """Luật OFFLINE_TOO_LONG (threshold_value = số giây). Gọi định kỳ từ mark_offline_devices."""
    fired = 0
    now = timezone.now()
    rules = (AutomationRule.objects.filter(is_active=True, trigger_type=AutomationRule.TRIGGER_OFFLINE_TOO_LONG)
             .select_related('owner', 'device'))
    for rule in rules:
        if rule.threshold_value is None:
            continue
        devices = Device.objects.filter(owner_id=rule.owner_id, status='offline', last_seen_at__isnull=False)
        if rule.device_id:
            devices = devices.filter(pk=rule.device_id)
        for device in devices:
            offline_seconds = (now - device.last_seen_at).total_seconds()
            if offline_seconds >= float(rule.threshold_value):
                fired += _fire(rule, device, offline_seconds, f'Mất kết nối: {device.name}',
                               f'Thiết bị "{device.name}" đã mất kết nối khoảng {int(offline_seconds)} giây.')
    return fired