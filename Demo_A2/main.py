import time
import network
import json
from umqtt.simple import MQTTClient
from machine import Pin, ADC, UART
import esp32

# ========================== CẤU HÌNH ==========================
SSID = "YOUR_WIFI_SSID"
PASSWORD = "YOUR_WIFI_PASSWORD"
MQTT_BROKER = "test.mosquitto.org"
MQTT_PORT = 1883
DEVICE_CODE = "ESP32_LOCK_01"   # backend sẽ sinh sau khi đăng ký

# ========================== GPIO ==========================
RELAY_PIN = 5
LED_PIN = 6
BUZZER_PIN = 7
BUTTON_PIN = 8
ADC_PIN = 0
UART_RX = 16
UART_TX = 17
UART_BAUD = 9600

# ========================== KHỞI TẠO ==========================
relay = Pin(RELAY_PIN, Pin.OUT, value=0)
led = Pin(LED_PIN, Pin.OUT, value=0)
buzzer = Pin(BUZZER_PIN, Pin.OUT, value=0)
button = Pin(BUTTON_PIN, Pin.IN, Pin.PULL_UP)
adc = ADC(ADC_PIN)

uart = UART(1, baudrate=UART_BAUD, tx=UART_TX, rx=UART_RX)

sta = network.WLAN(network.STA_IF)
sta.active(True)
sta.connect(SSID, PASSWORD)
while not sta.isconnected():
    time.sleep(0.5)

# MQTT Client
mqtt = MQTTClient(f"esp32-{DEVICE_CODE}", MQTT_BROKER, port=MQTT_PORT, keepalive=60)

def mqtt_callback(topic, msg):
    payload = json.loads(msg)
    if topic.decode().endswith("/cmd"):
        cmd = payload.get("command")
        if cmd == "LOCK":
            relay.value(0); led.value(0); buzzer.value(0)
        elif cmd == "UNLOCK":
            relay.value(1); led.value(1); buzzer.value(1)
            time.sleep(1.5)
            buzzer.value(0)
        ack = {"device_code": DEVICE_CODE, "command": cmd, "status": "executed", "timestamp": time.time()}
        mqtt.publish("smartlock/+/ack", json.dumps(ack))

mqtt.set_callback(mqtt_callback)
mqtt.connect()
mqtt.subscribe("smartlock/+/cmd")

# ====================== LOGIC OFFLINE + REPLAY ======================
last_seen = time.time()
offline_queue = []   # lưu lệnh khi mất WiFi

while True:
    try:
        # Trạng thái gửi lên backend (real-time)
        status = {
            "device_code": DEVICE_CODE,
            "is_on": bool(relay.value()),
            "battery": esp32.raw_temperature(),
            "rssi": sta.status("rssi"),
            "timestamp": time.time()
        }
        mqtt.publish("smartlock/+/status", json.dumps(status))

        # Nút bấm tay trên thiết bị
        if button.value() == 0:
            mqtt.publish("smartlock/+/cmd", json.dumps({"command": "TOGGLE"}))
            time.sleep(0.3)

        # Logic Offline (đề bài yêu cầu)
        if not sta.isconnected():
            if time.time() - last_seen > 10:
                print("🔴 OFFLINE - Xử lý mất mạng")
                last_seen = time.time()
        else:
            last_seen = time.time()

        # Đọc NFC (nếu có thẻ)
        if uart.any():
            card = uart.readline()
            if card:
                uid = card.decode().strip()
                print("✅ Đọc thẻ RFID:", uid)
                # Replay thông tin lên server + DB
                mqtt.publish("smartlock/+/cmd", json.dumps({
                    "command": "ADD_CARD",
                    "uid": uid,
                    "timestamp": time.time()
                }))

        time.sleep(1.5)

    except Exception as e:
        print("Error:", e)
        try: mqtt.reconnect()
        except: pass