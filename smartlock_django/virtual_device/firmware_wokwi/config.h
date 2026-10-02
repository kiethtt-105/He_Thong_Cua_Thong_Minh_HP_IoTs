// Dán thông tin từ virtual_device/devices/<code>/device_info.txt (hoặc của khoá thật đã provisioning)
#pragma once
#define DEVICE_CODE   "DEV-XXXXXXXX"
#define SECRET        "dan-secret-vao-day"      // provisioning secret (chữ thường 32 ký tự hex)
#define FIRMWARE_VER  "1.0.0-wokwi"

#define WIFI_SSID     "Wokwi-GUEST"             // Wokwi: Wokwi-GUEST (không mật khẩu). Khoá thật: Wi-Fi nhà
#define WIFI_PASS     ""

// Wokwi chạy trên cloud => KHÔNG tới được localhost. Dùng broker public/VPS, hoặc Wokwi Private Gateway (VS Code, cổng 1883).
// Với Private Gateway: host.wokwi.internal (Wokwi) trỏ về máy bạn.
#define MQTT_HOST     "host.wokwi.internal"
#define MQTT_PORT     1883

#define RELOCK_MS     5000
#define STATUS_EVERY  30000UL
