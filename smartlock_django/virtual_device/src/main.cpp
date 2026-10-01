#include <Arduino.h>
/*
 * SmartLock ESP32 firmware v1.2 - chạy được trên Wokwi (VS Code) VÀ trên ESP32 thật.
 *
 * Giao thức MQTT (khớp mqtt_subscriber.py):
 *   Gửi:  smartlock/<DEVICE_CODE>/status  {battery_level, signal_strength, lock_state, tamper_detected, ...}
 *         smartlock/<DEVICE_CODE>/event   {type: rfid_tap|pin_entry|face_result|ble_unlock, ...}
 *         smartlock/<DEVICE_CODE>/ack     {command_id, token, result: ok|failed}
 *   Nhận: smartlock/<DEVICE_CODE>/cmd  {command: UNLOCK|LOCK|REBOOT|BUZZER_ALERT|RESET,
 *                                       command_id, token, source, reason}
 *   (ACL của broker: thiết bị chỉ được subscribe đúng topic .../cmd, và chỉ ghi status/event/ack)
 *
 * DEVICE_SECRET = provisioning secret gốc (hiện 1 lần khi thêm thiết bị trên web). Dùng làm
 * password MQTT và để tự kiểm tra vé Bluetooth OFFLINE (key = HMAC(sha256hex(secret), "ble-ticket-v1")).
 *
 * Nguyên tắc: thiết bị KHÔNG tự quyết mở cửa. Quẹt thẻ / PIN / khuôn mặt / Bluetooth
 * chỉ gửi event lên server; server xác thực rồi gửi lệnh "unlock" xuống.
 *
 * lock_state: locked | unlocked | jammed  (jammed = chốt bị kẹt, đọc từ công tắc chân 35)
 */

// ======================= CẤU HÌNH (chỉ sửa phần này) =======================
#define DEVICE_CODE    "DEV-SIM-001"
#define DEVICE_SECRET  "test-secret-please-change"   // ESP32 thật: provisioning secret (32 ký tự hex) của thiết bị

#define WIFI_SSID      "Wokwi-GUEST"   // ESP32 thật: tên wifi của bạn
#define WIFI_PASS      ""              // ESP32 thật: mật khẩu wifi
#define WIFI_CHANNEL   6               // Wokwi: 6. ESP32 thật: đổi thành 0

#define MQTT_HOST      "broker.hivemq.com"  // chỉ để thử; dùng broker riêng có user/password
#define MQTT_PORT      1883                 // TLS thường là 8883
#define USE_TLS        0                    // 1 = MQTT qua TLS (setInsecure, chỉ để test)

#define USE_MFRC522    0   // 1 = đầu đọc RFID RC522 thật (Wokwi không có -> dùng Serial "rfid ...")
#define USE_BLE        0   // 1 = nhận vé Bluetooth qua BLE
#define SIMULATE_BATTERY 1 // 1 = pin từ biến trở (Wokwi). 0 = cầu phân áp pin thật ở chân 34

#define FW_VERSION     "1.2"
// ======================= CHÂN =======================
#define PIN_SERVO      13
#define PIN_LED_G      4
#define PIN_LED_R      21
#define PIN_BUZZER     2
#define PIN_TAMPER     15   // công tắc chống phá: nối GND = bị tác động
#define PIN_BATTERY    34
#define PIN_JAM        35   // HIGH = chốt bị kẹt/vướng (chân chỉ-đọc, ESP32 thật cần điện trở kéo xuống)
#define PIN_RFID_SS    5    // RC522: SCK=18, MISO=19, MOSI=23, RST=22
#define PIN_RFID_RST   22

#define ANGLE_LOCKED        0
#define ANGLE_UNLOCKED      90
#define SERVO_MOVE_MS       500
#define DEFAULT_UNLOCK_MS   5000
#define MAX_UNLOCK_SEC      300
#define STATUS_INTERVAL_MS  30000
#define PIN_TIMEOUT_MS      15000
#define PIN_MAX_LEN         16
#define PIN_MIN_INTERVAL_MS 1000
#define LOW_BATTERY_PCT     15
#define FACE_MAX            512
#define MQTT_BUFFER         8192
#define LOCKOUT_LOCAL_MS    60000   // khoá bàn phím/thẻ cục bộ sau BUZZER_ALERT(ACCESS_BURST); server vẫn quyết định mức khoá thật
#define BLE_QUEUE           10      // số sự kiện BLE giữ lại khi mất mạng (RAM)
#define BLE_MIN_INTERVAL_MS 1000
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
#include "mbedtls/md.h"

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

char T_STATUS[64], T_EVENT[64], T_ACK[64], T_CMD[64];
const char* lockState = "locked";
bool tamper = false;
uint32_t relockAt = 0;
uint32_t lastStatusAt = 0;
uint32_t lastKeyAt = 0;
uint32_t lastPinAt = 0;
String pinBuf;
bool ntpStarted = false;

// ---------------------------------------------------------------- tiện ích
void beep(uint16_t ms) {
  for (uint32_t i = 0; i < (uint32_t)ms * 2; i++) {
    digitalWrite(PIN_BUZZER, HIGH); delayMicroseconds(250);
    digitalWrite(PIN_BUZZER, LOW);  delayMicroseconds(250);
  }
}

void showLockLeds() {
  bool open = strcmp(lockState, "unlocked") == 0;
  digitalWrite(PIN_LED_G, open ? HIGH : LOW);
  digitalWrite(PIN_LED_R, open ? LOW : HIGH);
}

void errorBeep() {
  for (int i = 0; i < 3; i++) {
    digitalWrite(PIN_LED_R, LOW); beep(60);
    digitalWrite(PIN_LED_R, HIGH); delay(60);
  }
  showLockLeds();
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

// logBody=false cho event/ack: không in PIN, UID thẻ, vé, token ra Serial.
bool publishJson(const char* topic, JsonDocument& d, bool logBody) {
  if (!mqtt.connected()) return false;
  size_t n = measureJson(d);
  char* buf = (char*)malloc(n + 1);
  if (!buf) { Serial.println("[mqtt] hết bộ nhớ"); return false; }
  serializeJson(d, buf, n + 1);
  if (logBody) Serial.printf("[tx] %s %s\n", topic, buf);
  else         Serial.printf("[tx] %s (%u byte)\n", topic, (unsigned)n);
  bool ok = mqtt.publish(topic, (const uint8_t*)buf, n, false);
  free(buf);
  if (!ok) Serial.println("[mqtt] publish thất bại (bản tin quá lớn?)");
  return ok;
}

void publishStatus() {
  JsonDocument d;
  d["battery_level"] = readBattery();
  d["signal_strength"] = WiFi.RSSI();
  d["lock_state"] = lockState;
  d["tamper_detected"] = tamper;
  d["fw"] = FW_VERSION;
  d["mac"] = WiFi.macAddress();
  d["uptime_s"] = millis() / 1000;
  publishJson(T_STATUS, d, true);
  lastStatusAt = millis();
}

bool blockActive = false;
uint32_t blockEnd = 0;

bool inputBlocked() {
  if (blockActive && (int32_t)(millis() - blockEnd) >= 0) blockActive = false;
  return blockActive;
}

// Server quyết định mở cửa, nên khi mất mạng thì từ chối ngay và báo lỗi (không xếp hàng, không phát lại).
bool linkOk() {
  if (mqtt.connected()) return true;
  Serial.println("[mqtt] đang offline -> không gửi được, báo lỗi");
  errorBeep();
  return false;
}

void sendEvent(const char* type, const char* key, const String& val) {
  if (inputBlocked()) { Serial.println("[lockout] đang khoá tạm cục bộ"); errorBeep(); return; }
  if (!linkOk()) return;
  JsonDocument d;
  d["type"] = type;
  d[key] = val;
  publishJson(T_EVENT, d, false);
}

void sendRfid(String uid) {
  static String lastUid;
  static uint32_t lastAt = 0;
  uid.trim();
  uid.replace(":", "");
  uid.replace(" ", "");
  uid.toUpperCase();
  if (!uid.length()) return;
  if (uid == lastUid && millis() - lastAt < 1500) return;   // chống quẹt lặp
  lastUid = uid; lastAt = millis();
  beep(40);
  sendEvent("rfid_tap", "uid", uid);
}

// Gọi hàm này từ pipeline nhận diện khuôn mặt (ESP32-CAM). Embedding 1..512 số thực.
void sendFace(const float* emb, int n, const char* snapshotUrl = "") {
  if (n <= 0 || n > FACE_MAX) { Serial.println("[face] embedding không hợp lệ"); return; }
  if (inputBlocked()) { Serial.println("[lockout] đang khoá tạm cục bộ"); errorBeep(); return; }
  if (!linkOk()) return;
  JsonDocument d;
  d["type"] = "face_result";
  JsonArray a = d["embedding"].to<JsonArray>();
  for (int i = 0; i < n; i++) a.add(emb[i]);
  if (snapshotUrl && *snapshotUrl) d["snapshot_url"] = snapshotUrl;
  beep(40);
  publishJson(T_EVENT, d, false);
}

// ---------------------------------------------------------------- khoá
bool moveLock(bool unlock) {
  lockServo.write(unlock ? ANGLE_UNLOCKED : ANGLE_LOCKED);
  delay(SERVO_MOVE_MS);
  if (digitalRead(PIN_JAM) == HIGH) {            // chốt vướng: trả servo về vị trí cũ
    lockServo.write(unlock ? ANGLE_LOCKED : ANGLE_UNLOCKED);
    return false;
  }
  return true;
}

bool setLock(bool unlock, uint32_t holdMs = 0) {
  if (!moveLock(unlock)) {
    lockState = "jammed";
    relockAt = 0;
    Serial.println("[lock] KẸT chốt!");
    errorBeep();
    publishStatus();
    return false;
  }
  lockState = unlock ? "unlocked" : "locked";
  relockAt = unlock ? millis() + (holdMs ? holdMs : DEFAULT_UNLOCK_MS) : 0;
  if (unlock && relockAt == 0) relockAt = 1;
  showLockLeds();
  beep(unlock ? 200 : 60);
  Serial.printf("[lock] %s\n", lockState);
  publishStatus();
  return true;
}

void jamTask() {   // hết kẹt thì tự khoá lại
  static uint32_t last = 0;
  if (strcmp(lockState, "jammed") != 0) return;
  if (millis() - last < 1000) return;
  last = millis();
  if (digitalRead(PIN_JAM) == LOW) {
    Serial.println("[lock] hết kẹt, thử khoá lại");
    setLock(false);
  }
}

// ---------------------------------------------------------------- Bluetooth: tự kiểm tra vé OFFLINE
// Vé = "<user_hex>.<exp>.<sig>"; sig = HMAC_SHA256(key, "<device_code>|<user_hex>|<exp>") hex 32 ký tự đầu
// key = HMAC_SHA256(key = sha256_hex(secret) [chuỗi ASCII], msg = "ble-ticket-v1")  (xem services.py)
uint8_t bleKey[32];

void hmacSha256(const uint8_t* key, size_t klen, const uint8_t* msg, size_t mlen, uint8_t out[32]) {
  mbedtls_md_hmac(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), key, klen, msg, mlen, out);
}

void initBleKey() {
  uint8_t h[32];
  char hex[65];
  mbedtls_md(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), (const uint8_t*)DEVICE_SECRET, strlen(DEVICE_SECRET), h);
  for (int i = 0; i < 32; i++) sprintf(hex + 2 * i, "%02x", h[i]);
  hmacSha256((const uint8_t*)hex, 64, (const uint8_t*)"ble-ticket-v1", 13, bleKey);
}

// 0 = hợp lệ, 1 = sai định dạng/chữ ký, 2 = hết hạn, 3 = chưa có giờ (chưa đồng bộ NTP)
int verifyBleTicket(const String& ticket) {
  int d1 = ticket.indexOf('.');
  int d2 = d1 < 0 ? -1 : ticket.indexOf('.', d1 + 1);
  if (d1 <= 0 || d2 <= d1 + 1 || ticket.indexOf('.', d2 + 1) >= 0) return 1;
  String userHex = ticket.substring(0, d1);
  String expS = ticket.substring(d1 + 1, d2);
  String sig = ticket.substring(d2 + 1);
  if (sig.length() != 32 || expS.length() < 1 || expS.length() > 10 || userHex.length() > 40) return 1;
  for (size_t i = 0; i < expS.length(); i++) if (!isDigit(expS[i])) return 1;
  uint32_t expT = strtoul(expS.c_str(), nullptr, 10);

  String msg = String(DEVICE_CODE) + "|" + userHex + "|" + String((unsigned long)expT);
  uint8_t mac[32];
  hmacSha256(bleKey, 32, (const uint8_t*)msg.c_str(), msg.length(), mac);
  char hex[65];
  for (int i = 0; i < 32; i++) sprintf(hex + 2 * i, "%02x", mac[i]);
  uint8_t diff = 0;                                   // so sánh hằng-thời-gian
  for (int i = 0; i < 32; i++) diff |= (uint8_t)(sig[i] ^ hex[i]);
  if (diff) return 1;

  uint32_t now = epochNow();
  if (!now) return 3;
  return expT < now ? 2 : 0;
}

struct BleEv { String ticket; bool ok; const char* reason; uint32_t at; };
BleEv bleQ[BLE_QUEUE];
int bleHead = 0, bleCount = 0;

bool publishBle(const BleEv& e) {
  JsonDocument d;
  d["type"] = "ble_unlock";
  d["ticket"] = e.ticket;
  d["result"] = e.ok ? "ok" : "failed";
  if (e.reason) d["reason"] = e.reason;
  if (e.at) d["at"] = e.at;                          // giờ xảy ra thật (server nhận sự kiện trễ tới 7 ngày)
  return publishJson(T_EVENT, d, false);
}

void reportBle(const String& ticket, bool ok, const char* reason, uint32_t at) {
  BleEv e = {ticket, ok, reason, at};
  if (bleCount == 0 && publishBle(e)) return;
  if (bleCount == BLE_QUEUE) { bleHead = (bleHead + 1) % BLE_QUEUE; bleCount--; }   // đầy: bỏ cái cũ nhất
  bleQ[(bleHead + bleCount) % BLE_QUEUE] = e;
  bleCount++;
  Serial.printf("[ble] mất mạng, giữ lại %d sự kiện chờ gửi\n", bleCount);
}

void bleFlushTask() {
  if (!bleCount || !mqtt.connected()) return;
  if (publishBle(bleQ[bleHead])) { bleHead = (bleHead + 1) % BLE_QUEUE; bleCount--; }
}

// Điện thoại đưa vé qua BLE (hoặc Serial "ble <vé>"): thiết bị TỰ quyết định mở, rồi báo server ghi log.
void handleBleTicket(String t) {
  static uint32_t lastAt = 0;
  t.trim();
  if (!t.length() || t.length() > 200) return;
  if (lastAt && millis() - lastAt < BLE_MIN_INTERVAL_MS) return;
  lastAt = millis();
  uint32_t at = epochNow();
  int r = verifyBleTicket(t);
  if (r == 0) {
    Serial.println("[ble] vé hợp lệ -> mở cửa cục bộ");
    bool ok = setLock(true);
    reportBle(t, ok, ok ? nullptr : "BLE_JAMMED", at);
  } else {
    Serial.printf("[ble] vé bị từ chối (mã %d)\n", r);
    errorBeep();
    reportBle(t, false, r == 2 ? "BLE_TICKET_EXPIRED" : r == 3 ? "BLE_NO_TIME" : "BLE_INVALID_TICKET", at);
  }
}

// ---------------------------------------------------------------- lệnh từ server (topic .../cmd)
struct SeenCmd { String id; bool ok; };
SeenCmd seenCmds[8];
uint8_t seenN = 0;

int findSeen(const String& id) {
  for (int i = 0; i < 8; i++) if (seenCmds[i].id == id) return i;
  return -1;
}

void sendAck(JsonDocument& cmd, bool ok, const char* reason = nullptr) {
  JsonDocument a;
  a["command_id"] = cmd["command_id"];
  if (!cmd["token"].isNull()) a["token"] = cmd["token"];   // server so token này với command_token_hash
  a["result"] = ok ? "ok" : "failed";
  if (reason) a["reason"] = reason;
  publishJson(T_ACK, a, false);
}

String getStr(JsonDocument& d, const char* k) {
  const char* s = d[k] | "";
  return String(s);
}

void alarm() {
  for (int i = 0; i < 4; i++) {
    digitalWrite(PIN_LED_R, LOW); beep(300);
    digitalWrite(PIN_LED_R, HIGH); delay(150);
  }
  showLockLeds();
}

void handleCommand(JsonDocument& doc) {
  bool hasId = !doc["command_id"].isNull();
  String cid = hasId ? doc["command_id"].as<String>() : String("");

  // MQTT QoS1 có thể giao lặp: đã xử lý thì chỉ ack lại, không chạy lại lệnh.
  if (hasId) {
    int k = findSeen(cid);
    if (k >= 0) {
      Serial.printf("[cmd] lệnh %s đã xử lý, chỉ ack lại\n", cid.c_str());
      sendAck(doc, seenCmds[k].ok);
      return;
    }
  }

  String name = getStr(doc, "command");
  if (!name.length()) name = getStr(doc, "action");
  name.toUpperCase();
  String source = getStr(doc, "source");
  Serial.printf("[cmd] %s (nguồn: %s)\n", name.c_str(), source.length() ? source.c_str() : "-");

  int dur = doc["duration"] | 0;
  if (dur < 0) dur = 0;
  if (dur > MAX_UNLOCK_SEC) dur = MAX_UNLOCK_SEC;

  bool ok = true, reboot = false;
  const char* reason = nullptr;

  if (name == "UNLOCK") {
    ok = setLock(true, (uint32_t)dur * 1000UL);
    if (!ok) reason = "jammed";
  } else if (name == "LOCK") {
    ok = setLock(false);
    if (!ok) reason = "jammed";
  } else if (name == "BUZZER_ALERT") {                       // server gửi khi khoá tạm do nhập sai nhiều lần
    alarm();
    if (getStr(doc, "reason") == "ACCESS_BURST") {
      blockActive = true;
      blockEnd = millis() + LOCKOUT_LOCAL_MS;
      Serial.println("[lockout] khoá tạm bàn phím/thẻ cục bộ");
    }
  } else if (name == "REBOOT" || name == "RESET") {
    reboot = true;
  } else if (name == "STATUS" || name == "PING") {
    publishStatus();
  } else {                                                   // ADD_CARD, REMOVE_CARD, OTA_UPDATE, ...
    Serial.printf("[cmd] chưa hỗ trợ: %s\n", name.c_str());
    ok = false;
    reason = "unsupported";
  }

  if (hasId) {                                               // BUZZER_ALERT không kèm command_id nên không ack
    seenCmds[seenN % 8].id = cid;
    seenCmds[seenN % 8].ok = ok;
    seenN++;
    sendAck(doc, ok, reason);
  }
  if (reboot) { delay(300); ESP.restart(); }
}

void onMqtt(char* topic, byte* payload, unsigned int len) {
  Serial.printf("[rx] %s (%u byte)\n", topic, len);
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
    mqtt.subscribe(T_CMD, 1);
    Serial.printf("[mqtt] OK, đã subscribe %s\n", T_CMD);
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
    if (!pinBuf.length()) return;
    if (millis() - lastPinAt < PIN_MIN_INTERVAL_MS) {   // chống dò PIN bằng cách bấm dồn dập
      pinBuf = "";
      errorBeep();
      return;
    }
    lastPinAt = millis();
    sendEvent("pin_entry", "pin", pinBuf);
    pinBuf = "";
    beep(80);
  }
}

void rfidTask() {
#if USE_MFRC522
  if (!rfid.PICC_IsNewCardPresent() || !rfid.PICC_ReadCardSerial()) return;
  String uid;
  for (byte i = 0; i < rfid.uid.size; i++) {
    if (rfid.uid.uidByte[i] < 0x10) uid += "0";
    uid += String(rfid.uid.uidByte[i], HEX);
  }
  sendRfid(uid);
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
    if (t.length()) handleBleTicket(t);
  }
#endif
}

void tamperTask() {   // có chống dội 50ms
  static bool lastRaw = false;
  static uint32_t rawAt = 0;
  bool raw = digitalRead(PIN_TAMPER) == LOW;
  if (raw != lastRaw) { lastRaw = raw; rawAt = millis(); }
  if (millis() - rawAt > 50 && raw != tamper) {
    tamper = raw;
    Serial.printf("[tamper] %s\n", tamper ? "BỊ TÁC ĐỘNG" : "bình thường");
    if (tamper) { beep(150); delay(80); beep(150); }
    publishStatus();
  }
}

void batteryTask() {
  static uint32_t last = 0;
  if (millis() - last < 60000) return;
  last = millis();
  if (readBattery() <= LOW_BATTERY_PCT) {
    Serial.println("[battery] pin yếu!");
    beep(40); delay(80); beep(40);
  }
}

// Mô phỏng qua Serial Monitor (Wokwi không có RC522 / BLE / camera):
//   rfid <uid> | pin <mã> | ble <vé> | face <v1,v2,...> | status
void serialTask() {
  if (!Serial.available()) return;
  String l = Serial.readStringUntil('\n');
  l.trim();
  if (!l.length()) return;
  if (l.startsWith("rfid "))      sendRfid(l.substring(5));
  else if (l.startsWith("pin "))  sendEvent("pin_entry", "pin", l.substring(4));
  else if (l.startsWith("ble "))  handleBleTicket(l.substring(4));
  else if (l.startsWith("face ")) {
    static float emb[FACE_MAX];
    int n = 0, start = 5;
    while (start <= (int)l.length() && n < FACE_MAX) {
      int c = l.indexOf(',', start);
      String tok = c < 0 ? l.substring(start) : l.substring(start, c);
      tok.trim();
      if (tok.length()) emb[n++] = tok.toFloat();
      if (c < 0) break;
      start = c + 1;
    }
    sendFace(emb, n);
  }
  else if (l == "status")         publishStatus();
  else Serial.println("Lệnh: rfid <uid> | pin <mã> | ble <vé> | face <v1,v2,...> | status");
}

// ---------------------------------------------------------------- setup / loop
void setup() {
  Serial.setRxBufferSize(8192);
  Serial.begin(115200);
  Serial.setTimeout(50);
  delay(200);
  Serial.printf("\n=== SmartLock %s fw %s ===\n", DEVICE_CODE, FW_VERSION);

  pinMode(PIN_LED_G, OUTPUT);
  pinMode(PIN_LED_R, OUTPUT);
  pinMode(PIN_BUZZER, OUTPUT);
  pinMode(PIN_TAMPER, INPUT_PULLUP);
  pinMode(PIN_JAM, INPUT);
  analogReadResolution(12);

  ESP32PWM::allocateTimer(0);
  lockServo.setPeriodHertz(50);
  lockServo.attach(PIN_SERVO, 500, 2400);
  lockServo.write(ANGLE_LOCKED);
  showLockLeds();

  snprintf(T_STATUS, sizeof(T_STATUS), "smartlock/%s/status", DEVICE_CODE);
  snprintf(T_EVENT,  sizeof(T_EVENT),  "smartlock/%s/event",  DEVICE_CODE);
  snprintf(T_ACK,    sizeof(T_ACK),    "smartlock/%s/ack",    DEVICE_CODE);
  snprintf(T_CMD,    sizeof(T_CMD),    "smartlock/%s/cmd",    DEVICE_CODE);

  initBleKey();
  WiFi.mode(WIFI_STA);
#if USE_TLS
  netClient.setInsecure();  // test thôi; production nên dùng setCACert()
#endif
  mqtt.setServer(MQTT_HOST, MQTT_PORT);
  mqtt.setCallback(onMqtt);
  mqtt.setBufferSize(MQTT_BUFFER);
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

  Serial.println("Serial: rfid <uid> | pin <mã> | ble <vé> | face <v1,v2,...> | status");
}

void loop() {
  wifiEnsure();
  mqttEnsure();
  keypadTask();
  rfidTask();
  bleTask();
  bleFlushTask();
  tamperTask();
  jamTask();
  batteryTask();
  serialTask();

  if (relockAt && (int32_t)(millis() - relockAt) >= 0) { relockAt = 0; setLock(false); }
  if (millis() - lastStatusAt > STATUS_INTERVAL_MS) publishStatus();
}