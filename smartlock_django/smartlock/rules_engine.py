# smartlock/rules_engine.py

import hashlib
import logging
import secrets
from datetime import timedelta

from django.db.models import Q
from django.utils import timezone

from .models import (
    AutomationRule, AutomationRuleLog, Device, DeviceCommand, DeviceStatusLog,
    NfcLog, Notification,
)
from .mqtt_client import publish_command, MqttPublishError

logger = logging.getLogger('smartlock.rules_engine')

# Thời hạn lệnh LOCK phát ra tự động từ rule engine, giống COMMAND_TTL_SECONDS trong
# views.py (không import trực tiếp từ views để tránh vòng lặp import views<->rules_engine).
AUTO_LOCK_COMMAND_TTL_SECONDS = 120


def _hash_token(token) -> str:
    return hashlib.sha256(str(token).encode()).hexdigest()


def _active_rules_for(device, trigger_types):
    """Luật đang active của đúng thiết bị này, HOẶC luật device=None (áp dụng cho mọi
    thiết bị của cùng 1 owner)."""
    return (
        AutomationRule.objects
        .filter(is_active=True, trigger_type__in=trigger_types)
        .filter(Q(device=device) | Q(device__isnull=True, owner=device.owner))
        .select_related('owner', 'device')
    )


def _apply_action(rule, device):
    """Thực hiện action_type của rule. Trả về action_taken để ghi vào AutomationRuleLog."""
    if rule.action_type == AutomationRule.ACTION_AUTO_LOCK:
        try:
            cmd = DeviceCommand.objects.create(
                device=device, issued_by=rule.owner, command_type='LOCK', status='pending',
                command_token_hash=_hash_token(secrets.token_urlsafe(32)),
                expires_at=timezone.now() + timedelta(seconds=AUTO_LOCK_COMMAND_TTL_SECONDS),
            )
            publish_command(device.device_code, {
                'command_id': str(cmd.id), 'command': 'LOCK', 'token': cmd.command_token_hash,
                'source': 'automation_rule', 'rule_id': str(rule.id),
            })
            cmd.status = 'sent'
            cmd.save(update_fields=['status'])
            return AutomationRule.ACTION_AUTO_LOCK
        except MqttPublishError as e:
            # MQTT lỗi thì không coi là thất bại toàn bộ - vẫn có Notification cảnh báo,
            # chỉ là không tự khoá được.
            logger.warning('automation_rule %s: AUTO_LOCK thất bại (mqtt): %s', rule.id, e)
            return AutomationRule.ACTION_NOTIFY_ONLY
    if rule.action_type == AutomationRule.ACTION_TEMP_BLOCK_ACCESS:
        # Tạm khoá NFC của thiết bị (field Device.nfc_enabled đã có sẵn) - chủ thiết bị
        # tự bật lại thủ công ở trang chi tiết thiết bị.
        Device.objects.filter(pk=device.pk).update(nfc_enabled=False, updated_at=timezone.now())
        return AutomationRule.ACTION_TEMP_BLOCK_ACCESS
    return AutomationRule.ACTION_NOTIFY_ONLY


def _fire(rule, device, measured_value, message):
    action_taken = _apply_action(rule, device)
    notif = Notification.objects.create(
        user=rule.owner, device=device, type='AUTOMATION_RULE',
        title=f'Luật "{rule.name}" đã kích hoạt'[:150], message=message, severity=rule.notify_severity,
    )
    AutomationRuleLog.objects.create(
        rule=rule, device=device, measured_value=measured_value,
        action_taken=action_taken, notification=notif,
    )
    rule.mark_triggered()
    logger.info('automation_rule fired: rule=%s device=%s action=%s', rule.id, device.id, action_taken)


def evaluate_device_status(device, status_log: DeviceStatusLog):
    """Chạy các luật dựa trên 1 bản ghi DeviceStatusLog vừa nhận được: pin yếu, tamper,
    nhiệt độ vượt ngưỡng, cửa mở quá lâu."""
    rules = _active_rules_for(device, [
        AutomationRule.TRIGGER_BATTERY_LOW,
        AutomationRule.TRIGGER_TAMPER_DETECTED,
        AutomationRule.TRIGGER_TEMPERATURE_OUT_OF_RANGE,
        AutomationRule.TRIGGER_DOOR_OPEN_TOO_LONG,
    ])
    for rule in rules:
        if rule.is_in_cooldown():
            continue

        if rule.trigger_type == AutomationRule.TRIGGER_BATTERY_LOW:
            if (status_log.battery_level is not None and rule.threshold_value is not None
                    and status_log.battery_level < rule.threshold_value):
                _fire(rule, device, status_log.battery_level,
                      f'Pin còn {status_log.battery_level}%, dưới ngưỡng {rule.threshold_value}%.')

        elif rule.trigger_type == AutomationRule.TRIGGER_TAMPER_DETECTED:
            if status_log.tamper_detected:
                _fire(rule, device, None, 'Phát hiện tác động vật lý lên thiết bị (tamper).')

        elif rule.trigger_type == AutomationRule.TRIGGER_TEMPERATURE_OUT_OF_RANGE:
            if (status_log.temperature is not None and rule.threshold_value is not None
                    and status_log.temperature > rule.threshold_value):
                _fire(rule, device, status_log.temperature,
                      f'Nhiệt độ {status_log.temperature}°C vượt ngưỡng {rule.threshold_value}°C.')

        elif rule.trigger_type == AutomationRule.TRIGGER_DOOR_OPEN_TOO_LONG:
            if status_log.lock_state == 'unlocked' and rule.threshold_window_seconds:
                # Tìm lần 'locked' gần nhất TRƯỚC bản ghi hiện tại để suy ra cửa đã mở
                # liên tục bao lâu.
                prev_locked = (
                    DeviceStatusLog.objects
                    .filter(device=device, lock_state='locked', recorded_at__lt=status_log.recorded_at)
                    .order_by('-recorded_at').first()
                )
                started_at = prev_locked.recorded_at if prev_locked else status_log.recorded_at
                elapsed = (status_log.recorded_at - started_at).total_seconds()
                if elapsed >= rule.threshold_window_seconds:
                    _fire(rule, device, elapsed,
                          f'Cửa mở liên tục {int(elapsed)}s, vượt ngưỡng {rule.threshold_window_seconds}s.')


def evaluate_failed_access_burst(device):
    """Chạy luật FAILED_ACCESS_BURST: đếm số NfcLog(event_type='TAP_FAILED') trong
    threshold_window_seconds gần nhất, so với threshold_value (số lần)."""
    rules = _active_rules_for(device, [AutomationRule.TRIGGER_FAILED_ACCESS_BURST])
    for rule in rules:
        if rule.is_in_cooldown() or not rule.threshold_value or not rule.threshold_window_seconds:
            continue
        since = timezone.now() - timedelta(seconds=rule.threshold_window_seconds)
        count = NfcLog.objects.filter(device=device, event_type='TAP_FAILED', created_at__gte=since).count()
        if count >= rule.threshold_value:
            _fire(rule, device, count,
                  f'{count} lần quẹt thẻ/nhập sai trong {rule.threshold_window_seconds}s.')


def evaluate_offline_devices():
    """Chạy luật OFFLINE_TOO_LONG cho mọi thiết bị đang có luật active - gọi định kỳ,
    KHÔNG cần status_log vì dựa vào Device.last_seen_at."""
    now = timezone.now()
    rules = (
        AutomationRule.objects
        .filter(is_active=True, trigger_type=AutomationRule.TRIGGER_OFFLINE_TOO_LONG)
        .select_related('device', 'owner')
    )
    for rule in rules:
        if rule.is_in_cooldown() or not rule.threshold_value:
            continue
        devices = [rule.device] if rule.device else list(Device.objects.filter(owner=rule.owner))
        for device in devices:
            if not device or not device.last_seen_at:
                continue
            offline_seconds = (now - device.last_seen_at).total_seconds()
            if offline_seconds >= float(rule.threshold_value):
                _fire(rule, device, offline_seconds,
                      f'Thiết bị mất kết nối {int(offline_seconds)}s, vượt ngưỡng {int(rule.threshold_value)}s.')