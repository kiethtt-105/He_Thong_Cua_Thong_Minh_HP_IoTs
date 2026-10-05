"""Webhook SERVER-TO-SERVER (broker MQTT gọi vào) - gắn dưới /api/webhooks/.

Không dành cho người dùng/app/firmware. Phải chặn ở tầng mạng/tường lửa, chỉ cho broker gọi,
và bắt buộc có header X-Webhook-Secret (settings.MQTT_WEBHOOK_SECRET).
"""
