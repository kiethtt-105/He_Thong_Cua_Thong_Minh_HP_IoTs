// SmartLock - ESP32 chạy trong Wokwi. Cùng giao thức MQTT với firmware Python và mqtt_subscriber.py:
//   khoá -> server : smartlock/<CODE>/status | event | ack      server -> khoá : smartlock/<CODE>/cmd
#include <Arduino.h>
#include <WiFi.h>
#include <PubSubClient.h>
#include <ArduinoJson.h>
#include <Keypad.h>
#include <ESP32Servo.h>
#include <Wire.h>
#include <LiquidCrystal_I2C.h>

// ====================== CẤU HÌNH (sửa cho khớp khoá bạn đã tạo trong tab "Tạo khoá") ======================
#define LOCK_CODE   "LOCK-WOKWI"
#define LOCK_SECRET "doi-secret-o-day"            // = secret sinh ra khi tạo khoá (dùng làm mật khẩu MQTT)
#define MQTT_HOST   "test.mosquitto.org"          // broker CÔNG KHAI, chỉ để thử. Wokwi miễn phí KHÔNG nối được localhost.
#define MQTT_PORT   1883                          // Muốn nối broker máy bạn: gói Wokwi Club + private gateway -> "host.wokwi.internal"
#define FIRMWARE    "1.0.0-wokwi"
#define STANDALONE_PIN "123456"                   // chỉ dùng khi KHÔNG có MQTT (chế độ lab độc lập)
#define UNLOCK_MS   5000
#define FAIL_MAX    3
#define LOCKOUT_MS  60000UL

const byte ROWS = 4, COLS = 4;
char keys[ROWS][COLS] = {{'1','2','3','A'},{'4','5','6','B'},{'7','8','9','C'},{'*','0','#','D'}};
byte rowPins[ROWS] = {13, 12, 14, 27};
byte colPins[COLS] = {26, 25, 33, 32};
Keypad keypad = Keypad(makeKeymap(keys), rowPins, colPins, ROWS, COLS);

const int PIN_SERVO = 15, PIN_LED_OK = 4, PIN_LED_ERR = 16, PIN_BUZZ = 23, PIN_KNOB = 18, PIN_TAMPER = 19;      // 21/22 dành cho LCD I2C
Servo servo;
LiquidCrystal_I2C lcd(0x27, 16, 2);
String msg = "San sang";
unsigned long msgUntil = 0;
WiFiClient net;
PubSubClient mqtt(net);

String lockState = "locked", keybuf, tCmd, tStatus, tEvent, tAck;
bool tamper = false;
int fails = 0, battery = 100;
unsigned long relockAt = 0, lockoutUntil = 0, lastKey = 0, lastStatus = 0, lastTry = 0;

void lcdShow() {                                  // dòng 1: trạng thái + mạng, dòng 2: PIN đang gõ hoặc thông báo
  static String last;
  String l1 = (lockState == "unlocked" ? "MO  " : "KHOA") + String(tamper ? " !CAY" : "") + (mqtt.connected() ? "  MQTT" : "  OFFL");
  String l2 = msg;
  if (keybuf.length()) { l2 = ""; for (size_t i = 0; i < keybuf.length(); i++) l2 += '*'; }
  else if (millis() > msgUntil) { msg = "Nhap PIN + #"; l2 = msg; }
  l1 = l1.substring(0, 16); l2 = l2.substring(0, 16);
  String now = l1 + "|" + l2; if (now == last) return; last = now;
  lcd.setCursor(0, 0); lcd.print(l1 + "                ");
  lcd.setCursor(0, 1); lcd.print(l2 + "                ");
}
void say(const String& s) { msg = s; msgUntil = millis() + 3000; }

void beep(int ms, int times = 1) { for (int i = 0; i < times; i++) { digitalWrite(PIN_BUZZ, HIGH); delay(ms); digitalWrite(PIN_BUZZ, LOW); if (times > 1) delay(ms); } }

void publishJson(const String& topic, JsonDocument& d, bool retain = false) {
  char buf[512]; size_t n = serializeJson(d, buf, sizeof(buf));
  mqtt.publish(topic.c_str(), (const uint8_t*)buf, n, retain);
}

void sendStatus() {
  if (!mqtt.connected()) return;
  StaticJsonDocument<384> d;
  d["lock_state"] = lockState; d["battery"] = battery; d["tamper"] = tamper;
  d["rssi"] = WiFi.RSSI(); d["firmware"] = FIRMWARE; d["mac"] = WiFi.macAddress(); d["uptime"] = millis() / 1000;
  publishJson(tStatus, d);
}

void sendEvent(const char* type, const char* field = nullptr, const char* value = nullptr) {
  if (!mqtt.connected()) return;
  StaticJsonDocument<192> d; d["type"] = type; if (field) d[field] = value;
  publishJson(tEvent, d);
}

void setLock(bool open, const char* why) {
  servo.write(open ? 90 : 0);
  lockState = open ? "unlocked" : "locked";
  digitalWrite(PIN_LED_OK, open); 
  relockAt = open ? millis() + UNLOCK_MS : 0;
  if (open) { fails = 0; beep(80); say("Da mo khoa"); } else say("Da khoa");
  Serial.printf("[lock] %s (%s)\n", lockState.c_str(), why);
  sendStatus();
}

void deny(const char* reason) {
  Serial.printf("[deny] %s\n", reason); say("Tu choi");
  digitalWrite(PIN_LED_ERR, HIGH); beep(150, 2); digitalWrite(PIN_LED_ERR, LOW);
  if (++fails >= FAIL_MAX) { fails = 0; lockoutUntil = millis() + LOCKOUT_MS; beep(100, 10); Serial.println("[lock] sai liên tiếp: khoá tạm 60s"); say("Khoa tam 60s"); }
}

void onCommand(char* topic, byte* payload, unsigned int len) {
  StaticJsonDocument<384> d;
  if (deserializeJson(d, payload, len)) return;
  String cmd = d["command"] | "";  cmd.toUpperCase();
  bool ok = true; String err;
  if (cmd == "UNLOCK") setLock(true, "lệnh server");
  else if (cmd == "LOCK") setLock(false, "lệnh server");
  else if (cmd == "PING") {}
  else if (cmd == "REBOOT") { ok = true; }
  else if (cmd == "BUZZER_ALERT") beep(120, 20);
  else { ok = false; err = "unsupported:" + cmd; }
  StaticJsonDocument<256> a;                        // ack: gửi lại ĐÚNG token của lệnh
  a["command_id"] = d["command_id"]; a["token"] = d["token"]; a["ok"] = ok;
  a["status"] = ok ? "acknowledged" : "failed"; a["lock_state"] = lockState; if (!ok) a["error"] = err;
  publishJson(tAck, a);
  if (cmd == "REBOOT") { delay(300); ESP.restart(); }
}

void submitPin(const String& pin) {
  if (millis() < lockoutUntil) { beep(100, 2); Serial.println("[lock] đang khoá tạm"); return; }
  if (pin.length() < 4) return deny("PIN quá ngắn");
  if (mqtt.connected()) { sendEvent("pin", "pin", pin.c_str()); Serial.println("[pin] đã gửi server, chờ lệnh UNLOCK..."); say("Cho server..."); }
  else if (pin == STANDALONE_PIN) setLock(true, "PIN độc lập");
  else deny("PIN sai (offline)");
}

void connectNet() {
  if (WiFi.status() != WL_CONNECTED) { WiFi.begin("Wokwi-GUEST", "", 6); return; }
  if (mqtt.connected() || millis() - lastTry < 5000) return;
  lastTry = millis();
  String will = "{\"state\":\"offline\",\"online\":false}";                       // LWT -> server đánh dấu offline ngay
  if (mqtt.connect(LOCK_CODE, LOCK_CODE, LOCK_SECRET, tStatus.c_str(), 1, false, will.c_str())) {
    mqtt.subscribe(tCmd.c_str(), 1);
    Serial.println("[mqtt] đã kết nối"); sendEvent("boot", "firmware", FIRMWARE); sendStatus();
  } else Serial.printf("[mqtt] lỗi rc=%d\n", mqtt.state());
}

void setup() {
  Serial.begin(115200);
  Wire.begin(21, 22); lcd.init(); lcd.backlight(); lcd.print("SmartLock Lab");
  pinMode(PIN_LED_OK, OUTPUT); pinMode(PIN_LED_ERR, OUTPUT); pinMode(PIN_BUZZ, OUTPUT);
  pinMode(PIN_KNOB, INPUT_PULLUP); pinMode(PIN_TAMPER, INPUT_PULLUP);
  servo.setPeriodHertz(50); servo.attach(PIN_SERVO, 500, 2400); servo.write(0);
  String base = String("smartlock/") + LOCK_CODE;
  tCmd = base + "/cmd"; tStatus = base + "/status"; tEvent = base + "/event"; tAck = base + "/ack";
  mqtt.setServer(MQTT_HOST, MQTT_PORT); mqtt.setCallback(onCommand); mqtt.setBufferSize(1024); mqtt.setKeepAlive(30);
  Serial.println("SmartLock Wokwi sẵn sàng. Phím: số = PIN, # = xác nhận, * = xoá");
}

void loop() {
  connectNet(); mqtt.loop(); lcdShow();
  char k = keypad.getKey();
  if (k) {
    lastKey = millis(); beep(15);
    if (isDigit(k)) { if (keybuf.length() < 8) keybuf += k; }
    else if (k == '*') keybuf = "";
    else if (k == '#') { String p = keybuf; keybuf = ""; submitPin(p); }
  }
  if (keybuf.length() && millis() - lastKey > 10000) keybuf = "";
  static bool knobPrev = true;
  bool knob = digitalRead(PIN_KNOB);
  if (!knob && knobPrev) setLock(lockState != "unlocked", "nút trong nhà");
  knobPrev = knob;
  bool t = !digitalRead(PIN_TAMPER);
  if (t != tamper) { tamper = t; if (t) { Serial.println("[tamper] PHÁT HIỆN CẠY PHÁ"); beep(100, 15); } sendStatus(); }
  if (lockState == "unlocked" && relockAt && millis() > relockAt) setLock(false, "tự khoá lại");
  if (millis() - lastStatus > 30000) { lastStatus = millis(); sendStatus(); }
}
