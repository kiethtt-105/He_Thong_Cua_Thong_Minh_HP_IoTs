# Sửa nhỏ trong views.py: cho tài khoản server đăng nhập broker

Hiện `mqtt_auth_webhook` chỉ chấp nhận `username = device_code`, nên tài khoản `django-server`
(publisher + subscriber) sẽ bị từ chối ở bước xác thực, dù ACL đã tin nó. Thêm đoạn này ngay
sau khi kiểm tra `if not username or not password:` trong `mqtt_auth_webhook`:

```python
    # Tài khoản server (publisher/subscriber của Django): so với MQTT_PUBLISHER_PASSWORD.
    if username in getattr(dj_settings, 'MQTT_TRUSTED_USERNAMES', []):
        expected = services.MQTT_PUBLISHER_PASSWORD
        if expected and hmac.compare_digest(password, expected):
            return JsonResponse({'ok': True})
        _audit(request, 'MQTT_AUTH_DENIED', success=False, severity='warning',
               username_attempt=username[:150])
        return JsonResponse({'ok': False}, status=401)
```
