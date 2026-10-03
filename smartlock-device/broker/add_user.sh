#!/bin/sh
# Thêm tài khoản vào broker DEV.   ./add_user.sh django <MQTT_PUBLISHER_PASSWORD>
#                                   ./add_user.sh LOCK-0001 <secret trong device.conf>
# (username khoá = device_code, password = secret GỐC, đúng như mqtt_auth_webhook)
[ $# -eq 2 ] || { echo "dùng: $0 <username> <password>"; exit 1; }
cd "$(dirname "$0")"
[ -f passwd ] || : > passwd
docker run --rm -v "$PWD:/w" eclipse-mosquitto:2 mosquitto_passwd -b /w/passwd "$1" "$2"
echo "đã thêm $1 - khởi động lại broker: docker compose restart mosquitto"
