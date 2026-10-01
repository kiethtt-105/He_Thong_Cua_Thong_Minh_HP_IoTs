#include <Arduino.h>
/*
 * SmartLock ESP32 firmware - chạy được trên Wokwi VÀ trên ESP32 thật.
 *
 * Giao thức MQTT (khớp mqtt_subscriber.py):
 *   Gửi:  smartlock/<DEVICE_CODE>/status  {battery_level, signal_strength, lock_state, tamper_detected}
 *         smartlock/<DEVICE_CODE>/event   {type: rfid_tap|pin_entry|ble_unlock, ...}
 *         smartlock/<DEVICE_CODE>/ack     {command_id, token, result}
 *   Nhận: smartlock/<DEVICE_CODE>/<command>  {action: unlock|lock|deny|status|reboot,
 *                                             command_id, token, duration(giây, tuỳ chọn)}
 *
 * Thiết bị KHÔNG tự mở cửa khi quẹt thẻ/nhập PIN: nó gửi event lên server,
 * server xác thực rồi gửi lệnh "unlock" xuống.
 *
 * Thư viện: PubSubClient, ArduinoJson (v7), ESP32Servo, Keypad
 * (+ MFRC522 nếu USE_MFRC522=1).
 */

// ======================= CẤU HÌNH (chỉ sửa phần này) =======================
#define DEVICE_CODE    "DEV-SIM-001"
#define DEVICE_SECRET  "test-secret-please-change"

#define WIFI_SSID      "Wokwi-GUEST"   // ESP32 thật: tên wifi của bạn
#define WIFI_PASS      ""              // ESP32 thật: mật khẩu wifi
#define WIFI_CHANNEL   6               // Wokwi: 6 (nhanh hơn). ESP32 thật: đổi thành 0

#define MQTT_HOST      "broker.hivemq.com"  // broker công khai chỉ để thử; dùng broker riêng có user/pass
#define MQTT_PORT      1883                 // TLS thường là 8883
#define USE_TLS        0                    // 1 = MQTT qua TLS (setInsecure, chỉ để test)

#define USE_MFRC522    0   // 1 = đầu đọc RFID RC522 thật (Wokwi không có RC522 -> dùng lệnh Serial "rfid ...")
#define USE_BLE        0   // 1 = nhận vé Bluetooth qua BLE (điện thoại ghi vé vào characteristic)
#define SIMULATE_BATTERY 1 // 1 = đọc pin từ biến trở (Wokwi). 0 = đọc cầu phân áp pin thật ở chân 34

// ======================= CHÂN =======================
#define PIN_SERVO      13
#define PIN_LED_G      4
#define PIN_LED_R      21
#define PIN_BUZZER     2
#define PIN_TAMPER     15   // công tắc chống phá: nối xuống GND = bị tác động
#define PIN_BATTERY    34
#define PIN_RFID_SS    5    // RC522: SCK=18, MISO=19, MOSI=23, RST=22
#define PIN_RFID_RST   22

#define ANGLE_LOCKED        0
#define ANGLE_UNLOCKED      90
#define DEFAULT_UNLOCK_MS   5000
#define STATUS_INTERVAL_MS  30000
#define PIN_TIMEOUT_MS      15000
#define PIN_MAX_LEN         16
// ===========================================================================

#include <WiFi.h>
#if USE_TLS
#include <WiFiClientSecure.h>
#endif
#include <PubSubClient.h>
#include <ArduinoJson.h>
#include <ESP32Servo.h>
#include <Keypad.h>
#include <time.h>

#if USE_MFRC522
#include <SPI.h>
#include <MFRC522.h>
MFRC522 rfid(PIN_RFID_SS, PIN_RFID_RST);
#endif

#if USE_BLE
#include <BLEDevice.h>
#include <BLEServer.h>
#include <BLEUtils.h>
#define BLE_SERVICE_UUID "6e400001-b5a3-f393-e0a9-e50e24dcca9e"
#define BLE_TICKET_UUID  "6e400002-b5a3-f393-e0a9-e50e24dcca9e"
volatile bool bleHasTicket = false;
String bleTicket;
class TicketCallbacks : public BLECharacteristicCallbacks {
  void onWrite(BLECharacteristic* c) override {
    auto v = c->getValue();
    bleTicket = String(v.c_str());
    bleHasTicket = true;
  }
};
#endif

// ---------------------------------------------------------------- keypad 4x4
const byte ROWS = 4, COLS = 4;
char keymap[ROWS][COLS] = {
  {'1', '2', '3', 'A'},
  {'4', '5', '6', 'B'},
  {'7', '8', '9', 'C'},
  {'*', '0', '#', 'D'}
};
byte rowPins[ROWS] = {32, 33, 25, 26};
byte colPins[COLS] = {27, 14, 16, 17};
Keypad keypad = Keypad(makeKeymap(keymap), rowPins, colPins, ROWS, COLS);

// ---------------------------------------------------------------- toàn cục
#if USE_TLS
WiFiClientSecure netClient;
#else
WiFiClient netClient;
#endif
PubSubClient mqtt(netClient);
Servo lockServo;

char T_STATUS[64], T_EVENT[64], T_ACK[64], T_SUB[64];
const char* lockState = "locked";
bool tamper = false;
uint32_t relockAt = 0;
uint32_t lastStatusAt = 0;
uint32_t lastKeyAt = 0;
String pinBuf;
bool ntpStarted = false;

// ---------------------------------------------------------------- tiện ích
void beep(uint16_t ms) {
  for (uint32_t i = 0; i < (uint32_t)ms * 2; i++) {
    digitalWrite(PIN_BUZZER, HIGH); delayMicroseconds(250);
    digitalWrite(PIN_BUZZER, LOW);  delayMicroseconds(250);
  }
}

uint32_t epochNow() {
  time_t t = time(nullptr);
  return t > 1700000000 ? (uint32_t)t : 0;
}

int readBattery() {
#if SIMULATE_BATTERY
  return constrain(map(analogRead(PIN_BATTERY), 0, 4095, 0, 100), 0, 100);
#else
  // Cầu phân áp 1:2 từ pin Li-ion 3.3V..4.2V vào chân 34. Chỉnh hệ số theo mạch thật.
  float v = analogReadMilliVolts(PIN_BATTERY) * 2.0f / 1000.0f;
  return constrain((int)((v - 3.3f) / (4.2f - 3.3f) * 100.0f), 0, 100);
#endif
}

bool publishJson(const char* topic, JsonDocument& d) {
  if (!mqtt.connected()) {
    Serial.println("[mqtt] chưa kết nối, bỏ qua bản tin");
    return false;
  }
  char buf[768];
  size_t n = serializeJson(d, buf, sizeof(buf));
  Serial.printf("[tx] %s %s\n", topic, buf);
  return mqtt.publish(topic, (const uint8_t*)buf, n, false);
}

void publishStatus() {
  JsonDocument d;
  d["battery_level"] = readBattery();
  d["signal_strength"] = WiFi.RSSI();
  d["lock_state"] = lockState;
  d["tamper_detected"] = tamper;
  publishJson(T_STATUS, d);
  lastStatusAt = millis();
}

void sendEvent(const char* type, const char* key, const String& val) {
  JsonDocument d;
  d["type"] = type;
  d[key] = val;
  if (!strcmp(type, "ble_unlock")) {
    uint32_t at = epochNow();
    if (at) d["at"] = at;
  }
  publishJson(T_EVENT, d);
}

// ---------------------------------------------------------------- khoá
void setLock(bool unlock, uint32_t holdMs = 0) {
  if (unlock) {
    lockServo.write(ANGLE_UNLOCKED);
    lockState = "unlocked";
    relockAt = millis() + (holdMs ? holdMs : DEFAULT_UNLOCK_MS);
    if (relockAt == 0) relockAt = 1;
    digitalWrite(PIN_LED_G, HIGH);
    digitalWrite(PIN_LED_R, LOW);
    beep(200);
  } else {
    lockServo.write(ANGLE_LOCKED);
    lockState = "locked";
    relockAt = 0;
    digitalWrite(PIN_LED_G, LOW);
    digitalWrite(PIN_LED_R, HIGH);
    beep(60);
  }
  Serial.printf("[lock] %s\n", lockState);
  publishStatus();
}

// ---------------------------------------------------------------- lệnh từ server
String getStr(JsonDocument& d, const char* k) {
  const char* s = d[k] | "";
  return String(s);
}

void handleCommand(JsonDocument& doc) {
  String action = getStr(doc, "action");
  if (!action.length()) action = getStr(doc, "command");
  if (!action.length()) action = getStr(doc, "type");
  action.toLowerCase();

  int dur = doc["duration"] | 0;
  if (!dur) dur = doc["duration_seconds"] | 0;

  bool ok = true;
  bool reboot = false;
  if (action.indexOf("unlock") >= 0 || action == "open") {
    setLock(true, dur > 0 ? (uint32_t)dur * 1000UL : 0);
  } else if (action.indexOf("lock") >= 0 || action == "close") {
    setLock(false);
  } else if (action.indexOf("deny") >= 0) {
    for (int i = 0; i < 3; i++) { digitalWrite(PIN_LED_R, LOW); beep(80); digitalWrite(PIN_LED_R, HIGH); delay(60); }
  } else if (action == "status" || action == "ping" || action == "status_request") {
    publishStatus();
  } else if (action == "reboot" || action == "restart") {
    reboot = true;
  } else {
    Serial.printf("[cmd] không hỗ trợ action=\"%s\"\n", action.c_str());
    ok = false;
  }

  if (!doc["command_id"].isNull()) {
    JsonDocument a;
    a["command_id"] = doc["command_id"];
    if (!doc["token"].isNull()) a["token"] = doc["token"];
    a["result"] = ok ? "ok" : "failed";
    publishJson(T_ACK, a);
  }
  if (reboot) { delay(300); ESP.restart(); }
}

void onMqtt(char* topic, byte* payload, unsigned int len) {
  String t(topic);
  String kind = t.substring(t.lastIndexOf('/') + 1);
  if (kind == "status" || kind == "event" || kind == "ack") return;  // bản tin do chính mình gửi
  Serial.printf("[rx] %s %.*s\n", topic, (int)len, (const char*)payload);
  JsonDocument doc;
  if (deserializeJson(doc, payload, len)) {
    Serial.println("[rx] không phải JSON hợp lệ");
    return;
  }
  handleCommand(doc);
}

// ---------------------------------------------------------------- mạng
void wifiEnsure() {
  static uint32_t last = 0;
  if (WiFi.status() == WL_CONNECTED) {
    if (!ntpStarted) {
      configTime(0, 0, "pool.ntp.org", "time.google.com");
      ntpStarted = true;
      Serial.printf("[wifi] đã kết nối, IP=%s\n", WiFi.localIP().toString().c_str());
    }
    return;
  }
  ntpStarted = false;
  if (last && millis() - last < 10000) return;
  last = millis();
  Serial.printf("[wifi] đang kết nối %s ...\n", WIFI_SSID);
  WiFi.disconnect();
  WiFi.begin(WIFI_SSID, WIFI_PASS, WIFI_CHANNEL);
}

void mqttEnsure() {
  if (mqtt.connected()) { mqtt.loop(); return; }
  if (WiFi.status() != WL_CONNECTED) return;
  static uint32_t last = 0;
  if (last && millis() - last < 5000) return;
  last = millis();
  Serial.printf("[mqtt] kết nối %s:%d ...\n", MQTT_HOST, MQTT_PORT);
  if (mqtt.connect(DEVICE_CODE, DEVICE_CODE, DEVICE_SECRET)) {
    mqtt.subscribe(T_SUB, 1);
    Serial.printf("[mqtt] OK, đã subscribe %s\n", T_SUB);
    publishStatus();
  } else {
    Serial.printf("[mqtt] lỗi rc=%d\n", mqtt.state());
  }
}

// ---------------------------------------------------------------- đầu vào
void keypadTask() {
  if (pinBuf.length() && millis() - lastKeyAt > PIN_TIMEOUT_MS) {
    pinBuf = "";
    Serial.println("[pin] hết thời gian, đã xoá");
  }
  char k = keypad.getKey();
  if (!k) return;
  lastKeyAt = millis();
  beep(20);
  if (k >= '0' && k <= '9') {
    if (pinBuf.length() < PIN_MAX_LEN) pinBuf += k;
    Serial.printf("[pin] đã nhập %d ký tự\n", (int)pinBuf.length());
  } else if (k == '*') {
    pinBuf = "";
    Serial.println("[pin] đã xoá");
  } else if (k == '#') {
    if (pinBuf.length()) {
      sendEvent("pin_entry", "pin", pinBuf);
      pinBuf = "";
      beep(80);
    }
  }
}

void sendRfid(String uid) {
  uid.trim();
  uid.replace(":", "");
  uid.replace(" ", "");
  uid.toUpperCase();
  if (!uid.length()) return;
  beep(40);
  sendEvent("rfid_tap", "uid", uid);
}

void rfidTask() {
#if USE_MFRC522
  static uint32_t lastTap = 0;
  if (!rfid.PICC_IsNewCardPresent() || !rfid.PICC_ReadCardSerial()) return;
  if (millis() - lastTap > 1500) {
    lastTap = millis();
    String uid;
    for (byte i = 0; i < rfid.uid.size; i++) {
      if (rfid.uid.uidByte[i] < 0x10) uid += "0";
      uid += String(rfid.uid.uidByte[i], HEX);
    }
    sendRfid(uid);
  }
  rfid.PICC_HaltA();
  rfid.PCD_StopCrypto1();
#endif
}

void bleTask() {
#if USE_BLE
  if (bleHasTicket) {
    bleHasTicket = false;
    String t = bleTicket;
    t.trim();
    if (t.length()) sendEvent("ble_unlock", "ticket", t);
  }
#endif
}

void tamperTask() {
  static uint32_t lastChange = 0;
  bool now = digitalRead(PIN_TAMPER) == LOW;
  if (now != tamper && millis() - lastChange > 50) {
    lastChange = millis();
    tamper = now;
    Serial.printf("[tamper] %s\n", tamper ? "BỊ TÁC ĐỘNG" : "bình thường");
    if (tamper) { beep(150); delay(80); beep(150); }
    publishStatus();
  }
}

// Mô phỏng qua Serial Monitor (hữu ích trên Wokwi, không có RC522 / BLE):
//   rfid A1B2C3D4 | pin 123456 | ble <ticket> | status
void serialTask() {
  if (!Serial.available()) return;
  String l = Serial.readStringUntil('\n');
  l.trim();
  if (!l.length()) return;
  if (l.startsWith("rfid "))      sendRfid(l.substring(5));
  else if (l.startsWith("pin "))  sendEvent("pin_entry", "pin", l.substring(4));
  else if (l.startsWith("ble "))  sendEvent("ble_unlock", "ticket", l.substring(4));
  else if (l == "status")         publishStatus();
  else Serial.println("Lệnh: rfid <uid> | pin <mã> | ble <vé> | status");
}

// ---------------------------------------------------------------- setup / loop
void setup() {
  Serial.begin(115200);
  Serial.setTimeout(50);
  delay(200);
  Serial.printf("\n=== SmartLock %s ===\n", DEVICE_CODE);

  pinMode(PIN_LED_G, OUTPUT);
  pinMode(PIN_LED_R, OUTPUT);
  pinMode(PIN_BUZZER, OUTPUT);
  pinMode(PIN_TAMPER, INPUT_PULLUP);
  analogReadResolution(12);

  ESP32PWM::allocateTimer(0);
  lockServo.setPeriodHertz(50);
  lockServo.attach(PIN_SERVO, 500, 2400);
  lockServo.write(ANGLE_LOCKED);
  digitalWrite(PIN_LED_R, HIGH);

  snprintf(T_STATUS, sizeof(T_STATUS), "smartlock/%s/status", DEVICE_CODE);
  snprintf(T_EVENT,  sizeof(T_EVENT),  "smartlock/%s/event",  DEVICE_CODE);
  snprintf(T_ACK,    sizeof(T_ACK),    "smartlock/%s/ack",    DEVICE_CODE);
  snprintf(T_SUB,    sizeof(T_SUB),    "smartlock/%s/#",      DEVICE_CODE);

#if USE_TLS
  netClient.setInsecure();  // test thôi; production nên dùng setCACert()
#endif
  mqtt.setServer(MQTT_HOST, MQTT_PORT);
  mqtt.setCallback(onMqtt);
  mqtt.setBufferSize(1024);
  mqtt.setKeepAlive(30);
  mqtt.setSocketTimeout(5);

#if USE_MFRC522
  SPI.begin();
  rfid.PCD_Init();
#endif

#if USE_BLE
  BLEDevice::init(DEVICE_CODE);
  BLEServer* server = BLEDevice::createServer();
  BLEService* svc = server->createService(BLE_SERVICE_UUID);
  BLECharacteristic* chr = svc->createCharacteristic(
      BLE_TICKET_UUID, BLECharacteristic::PROPERTY_WRITE | BLECharacteristic::PROPERTY_WRITE_NR);
  chr->setCallbacks(new TicketCallbacks());
  svc->start();
  BLEDevice::getAdvertising()->addServiceUUID(BLE_SERVICE_UUID);
  BLEDevice::startAdvertising();
#endif

  Serial.println("Serial: rfid <uid> | pin <mã> | ble <vé> | status");
}

void loop() {
  wifiEnsure();
  mqttEnsure();
  keypadTask();
  rfidTask();
  bleTask();
  tamperTask();
  serialTask();

  if (relockAt && (int32_t)(millis() - relockAt) >= 0) setLock(false);
  if (millis() - lastStatusAt > STATUS_INTERVAL_MS) publishStatus();
}