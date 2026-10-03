// ESP32 Smart Lock - cùng giao thức MQTT với khoá ảo (tools/virtual_lock.py, virtual_lock_3d.html).
// Thư viện (Library Manager): PubSubClient, ArduinoJson (v7), MFRC522, Keypad, ESP32Servo.
// Chọn board "ESP32 Dev Module". CHƯA biên dịch/thử trên phần cứng: kiểm tra chân GPIO theo mạch của bạn.
#include <WiFi.h>
#include <PubSubClient.h>
#include <ArduinoJson.h>
#include <SPI.h>
#include <MFRC522.h>
#include <Keypad.h>
#include <ESP32Servo.h>

// ====== CẤU HÌNH ======
const char* WIFI_SSID = "TEN_WIFI";
const char* WIFI_PASS = "MAT_KHAU_WIFI";
const char* MQTT_HOST = "192.168.1.10";     // IP máy chạy broker (KHÔNG dùng localhost)
const int   MQTT_PORT = 1883;
const char* DEVICE_CODE = "SL-DEMO-DEV-001"; // = username MQTT
const char* DEVICE_SECRET = "SECRET_GOC";    // = password MQTT (provisioning secret gốc)
const char* FW = "esp32-1.0.0";
const unsigned long RELOCK_MS = 5000, STATUS_MS = 30000;

// ====== CHÂN (chỉnh theo mạch) ======
#define PIN_SERVO 13
#define PIN_LED_R 25
#define PIN_LED_G 26
#define PIN_BUZZ  27
#define PIN_TAMPER 34            // công tắc/rung: LOW = bị tác động
#define RC_SS 5
#define RC_RST 22
const byte ROWS = 4, COLS = 3;
char KEYS[ROWS][COLS] = {{'1','2','3'},{'4','5','6'},{'7','8','9'},{'*','0','#'}};
byte rowPins[ROWS] = {32, 33, 14, 12}, colPins[COLS] = {15, 4, 16};
#define SERVO_LOCKED 0
#define SERVO_OPEN 90

Keypad keypad(makeKeymap(KEYS), rowPins, colPins, ROWS, COLS);
MFRC522 rfid(RC_SS, RC_RST);
Servo servo;
WiFiClient net;
PubSubClient mqtt(net);
String tCmd, tAck, tStatus, tEvent, pinBuf;
bool unlocked = false;
unsigned long relockAt = 0, lastStatus = 0, lastRfid = 0;

void setLock(bool open) {
  unlocked = open;
  servo.write(open ? SERVO_OPEN : SERVO_LOCKED);
  digitalWrite(PIN_LED_G, open); digitalWrite(PIN_LED_R, !open);
  relockAt = open ? millis() + RELOCK_MS : 0;
}
void beep(int ms) { digitalWrite(PIN_BUZZ, HIGH); delay(ms); digitalWrite(PIN_BUZZ, LOW); }

void publishJson(const String& topic, JsonDocument& d, bool retain = false) {
  String out; serializeJson(d, out); mqtt.publish(topic.c_str(), out.c_str(), retain);
}
void sendStatus() {
  JsonDocument d;
  d["lock_state"] = unlocked ? "unlocked" : "locked";
  d["battery"] = 100;
  d["tamper"] = digitalRead(PIN_TAMPER) == LOW;
  d["rssi"] = WiFi.RSSI();
  d["firmware"] = FW;
  publishJson(tStatus, d);
  lastStatus = millis();
}
void sendEvent(const char* type, const char* key = nullptr, const String& val = "") {
  JsonDocument d; d["type"] = type;
  if (key) d[key] = val;
  if (!strcmp(type, "boot")) d["firmware"] = FW;
  publishJson(tEvent, d);
}

void onMessage(char* topic, byte* payload, unsigned int len) {
  JsonDocument d;
  if (deserializeJson(d, payload, len)) return;
  const char* cmd = d["command"] | "";
  bool ok = true;
  if (!strcmp(cmd, "UNLOCK")) setLock(true);
  else if (!strcmp(cmd, "LOCK")) setLock(false);
  else if (!strcmp(cmd, "BUZZER_ALERT")) { for (int i = 0; i < 5; i++) { beep(150); delay(100); } return; } // không ack
  else if (!strcmp(cmd, "REBOOT")) { /* ack trước rồi mới khởi động lại */ }
  else if (strcmp(cmd, "PING")) ok = false;
  if (d["command_id"].is<const char*>()) {
    JsonDocument a; a["command_id"] = d["command_id"]; a["token"] = d["token"]; a["ok"] = ok;
    publishJson(tAck, a);
  }
  sendStatus();
  if (!strcmp(cmd, "REBOOT")) { delay(300); ESP.restart(); }
}

void connectWifi() {
  WiFi.mode(WIFI_STA); WiFi.begin(WIFI_SSID, WIFI_PASS);
  while (WiFi.status() != WL_CONNECTED) delay(300);
}
bool connectMqtt() {
  String lwt = "{\"state\":\"offline\"}";
  if (!mqtt.connect((String("esp-") + DEVICE_CODE).c_str(), DEVICE_CODE, DEVICE_SECRET,
                    tStatus.c_str(), 1, false, lwt.c_str())) return false;
  mqtt.subscribe(tCmd.c_str(), 1);
  sendEvent("boot"); sendStatus();
  return true;
}

void setup() {
  pinMode(PIN_LED_R, OUTPUT); pinMode(PIN_LED_G, OUTPUT); pinMode(PIN_BUZZ, OUTPUT);
  pinMode(PIN_TAMPER, INPUT_PULLUP);
  servo.attach(PIN_SERVO); setLock(false);
  SPI.begin(); rfid.PCD_Init();
  String base = String("smartlock/") + DEVICE_CODE + "/";
  tCmd = base + "cmd"; tAck = base + "ack"; tStatus = base + "status"; tEvent = base + "event";
  connectWifi();
  mqtt.setServer(MQTT_HOST, MQTT_PORT); mqtt.setCallback(onMessage); mqtt.setBufferSize(1024); mqtt.setKeepAlive(30);
}

void loop() {
  if (WiFi.status() != WL_CONNECTED) connectWifi();
  if (!mqtt.connected()) { if (!connectMqtt()) { delay(2000); return; } }
  mqtt.loop();

  if (unlocked && relockAt && millis() > relockAt) { setLock(false); sendStatus(); }
  if (millis() - lastStatus > STATUS_MS) sendStatus();

  char k = keypad.getKey();                       // PIN: nhập số rồi bấm #, * để xoá
  if (k) {
    beep(30);
    if (k == '*') pinBuf = "";
    else if (k == '#') { if (pinBuf.length() >= 4) sendEvent("pin", "pin", pinBuf); pinBuf = ""; }
    else if (pinBuf.length() < 8) pinBuf += k;
  }

  if (millis() - lastRfid > 1500 && rfid.PICC_IsNewCardPresent() && rfid.PICC_ReadCardSerial()) {
    String uid;
    for (byte i = 0; i < rfid.uid.size; i++) { if (rfid.uid.uidByte[i] < 16) uid += "0"; uid += String(rfid.uid.uidByte[i], HEX); }
    uid.toUpperCase();
    sendEvent("rfid", "uid", uid);                // server tự so khớp, đúng thì gửi lệnh UNLOCK về
    rfid.PICC_HaltA(); lastRfid = millis(); beep(60);
  }
}
