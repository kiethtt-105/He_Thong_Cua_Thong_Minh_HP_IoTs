"""API cho KHOÁ (firmware ESP32...) qua HTTPS - gắn dưới /api/device/.

Xác thực: X-Device-Code + X-Device-Secret. Kênh thứ hai của thiết bị là MQTT
(xem smartlock/management/commands/mqtt_subscriber.py).

    auth.py      xác thực thiết bị + hằng số + helper
    access.py    rfid / pin / face / phone
    ops.py       config · heartbeat · commands · ack · events
    webhooks.py  broker MQTT gọi vào (auth / acl)
    system.py    health · config công khai
"""
