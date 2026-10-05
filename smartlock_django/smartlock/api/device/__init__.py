"""API cho THIẾT BỊ (firmware ESP32...) qua HTTPS - gắn dưới /api/device/.

Xác thực: X-Device-Code + X-Device-Secret. Kênh thứ hai của thiết bị là MQTT
(xem smartlock/management/commands/mqtt_subscriber.py).
"""
