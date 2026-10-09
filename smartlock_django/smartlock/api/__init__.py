"""API Smart Lock - 5 file, mỗi file một vai trò:

    urls.py     toàn bộ route (app + khoá + webhook + system)
    common.py   lõi: JSON chuẩn, @api, token/phiên, serializer, helper quyền
    account.py  NGƯỜI DÙNG: đăng ký/đăng nhập, 2FA, hồ sơ, phiên, push token
    locks.py    KHOÁ CỦA NGƯỜI DÙNG: thiết bị, lệnh, PIN/thẻ/mặt, chia sẻ, lịch sử, snapshot
    device.py   PHẦN CỨNG: firmware (config/heartbeat/ack/access/events) + webhook MQTT + system
"""
