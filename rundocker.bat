@echo off
title MQTT Mosquitto Auth Launcher

echo [1/3] Chuyen den thu muc du an...
cd /d D:\.GitHub\He_Thong_Cua_Thong_Minh_HP_IoTs

echo [2/3] Xoa container mqtt cu (neu co)...
docker rm -f mqtt 2>nul

echo [3/3] Khoi chay MQTT Container moi...
docker run -d ^
  --name mqtt ^
  --restart unless-stopped ^
  -p 1883:1883 ^
  -p 9001:9001 ^
  -v "%cd%\mosquitto.conf:/etc/mosquitto/mosquitto.conf" ^
  iegomez/mosquitto-go-auth

echo.
echo === KIEM TRA LOGS (Nhan Ctrl+C de thoát xem log) ===
docker logs -f mqtt

pause