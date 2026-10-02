// Smart Lock firmware (ESP32) - cùng giao thức với virtual_device.py và Django smartlock.
// Wokwi: RFID/BLE/NFC/mặt nhập qua Serial Monitor (xem HELP). Phần cứng thật: bật USE_RC522 / USE_BLE.
#include <WiFi.h>
#include <PubSubClient.h>
#include <ArduinoJson.h>
#include <ESP32Servo.h>
#include <Keypad.h>
#include <time.h>
#include "mbedtls/md.h"
#include "config.h"
// #define USE_RC522      // bỏ comment khi có module MFRC522 (thư viện MFRC522)
// #define USE_BLE        // bỏ comment khi chạy khoá thật: nhận vé qua GATT characteristic

#ifdef USE_RC522
  #include <SPI.h>
  #include <MFRC522.h>
  MFRC522 rfid(21, 22);   // SS, RST
#endif
#ifdef USE_BLE
  #include <BLEDevice.h>
  #include <BLEServer.h>
#endif

const int PIN_SERVO = 13, PIN_BUZZ = 12, PIN_LED_R = 26, PIN_LED_G = 27;
byte rowPins[4] = {19, 18, 5, 17}, colPins[4] = {16, 4, 2, 15};
char keys[4][4] = {{'1','2','3','A'},{'4','5','6','B'},{'7','8','9','C'},{'*','0','#','D'}};
Keypad kp = Keypad(makeKeymap(keys), rowPins, colPins, 4, 4);

WiFiClient net; PubSubClient mqtt(net); Servo servo;
String tCmd, tStatus, tEvent, tAck, secretHash, pinBuf;
bool unlocked = false; unsigned long relockAt = 0, buzzUntil = 0, lastStatus = 0, lastTry = 0;
int battery = 100; bool tamper = false;
String pending[8]; int pendingN = 0;     // sự kiện BLE/NFC offline, gửi bù khi có mạng

// ---------------------------------------------------------------- crypto (giống services._ticket_sig)
String toHex(const uint8_t* d, size_t n) { String s; char b[3]; for (size_t i = 0; i < n; i++) { sprintf(b, "%02x", d[i]); s += b; } return s; }
void hmac256(const uint8_t* key, size_t kl, const uint8_t* msg, size_t ml, uint8_t out[32]) {
  mbedtls_md_context_t c; mbedtls_md_init(&c);
  mbedtls_md_setup(&c, mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), 1);
  mbedtls_md_hmac_starts(&c, key, kl); mbedtls_md_hmac_update(&c, msg, ml); mbedtls_md_hmac_finish(&c, out); mbedtls_md_free(&c);
}
String sha256Hex(const String& s) {
  uint8_t o[32]; mbedtls_md(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), (const uint8_t*)s.c_str(), s.length(), o); return toHex(o, 32);
}
// vé = "<user_hex>.<exp>.<sig>"; kind: "ble-ticket-v1" | "nfc-phone-ticket-v1". Trả null nếu hợp lệ, ngược lại mã lý do.
const char* checkTicket(String t, const char* label, const char* prefix, char* reason) {
  t.trim(); int a = t.indexOf('.'), b = t.indexOf('.', a + 1);
  if (a < 0 || b < 0) { sprintf(reason, "%s_INVALID_TICKET", prefix); return reason; }
  String user = t.substring(0, a), expS = t.substring(a + 1, b), sig = t.substring(b + 1);
  uint8_t k[32], m[32];
  hmac256((const uint8_t*)secretHash.c_str(), secretHash.length(), (const uint8_t*)label, strlen(label), k);
  String msg = String(DEVICE_CODE) + "|" + user + "|" + expS;
  hmac256(k, 32, (const uint8_t*)msg.c_str(), msg.length(), m);
  if (sig != toHex(m, 32).substring(0, 32)) { sprintf(reason, "%s_INVALID_TICKET", prefix); return reason; }
  time_t now = time(nullptr);
  if (now < 1700000000 || (long long)expS.toInt() < (long long)now) { sprintf(reason, "%s_TICKET_EXPIRED", prefix); return reason; }  // chưa đồng bộ giờ => từ chối
  return nullptr;
}

// ---------------------------------------------------------------- phần cứng
void setLock(bool open, bool autoRelock) {
  unlocked = open; servo.write(open ? 90 : 0);
  digitalWrite(PIN_LED_G, open); digitalWrite(PIN_LED_R, !open);
  relockAt = (open && autoRelock) ? millis() + RELOCK_MS : 0;
  Serial.println(open ? "[lock] MO CUA" : "[lock] KHOA CUA");
}
void buzz(unsigned ms) { digitalWrite(PIN_BUZZ, HIGH); buzzUntil = millis() + ms; }

// ---------------------------------------------------------------- MQTT
bool publishJson(const String& topic, JsonDocument& d) { String s; serializeJson(d, s); return mqtt.connected() && mqtt.publish(topic.c_str(), s.c_str()); }
void publishStatus() {
  StaticJsonDocument<256> d; d["battery_level"] = battery; d["lock_state"] = unlocked ? "unlocked" : "locked";
  d["signal_strength"] = WiFi.RSSI(); d["tamper_detected"] = tamper; d["firmware"] = FIRMWARE_VER; d["mac"] = WiFi.macAddress();
  publishJson(tStatus, d);
}
void sendEvent(JsonDocument& d, bool queue) {
  if (publishJson(tEvent, d)) return;
  if (queue && pendingN < 8) { serializeJson(d, pending[pendingN++]); Serial.println("[evt] offline, luu hang doi"); }
  else if (!queue) { Serial.println("[evt] offline: can server xac thuc"); buzz(300); }
}
void flushPending() { for (int i = 0; i < pendingN; i++) mqtt.publish(tEvent.c_str(), pending[i].c_str()); pendingN = 0; }

void phoneUnlock(const String& ticket, bool ble) {
  char reason[32]; const char* r = ble ? checkTicket(ticket, "ble-ticket-v1", "BLE", reason)
                                       : checkTicket(ticket, "nfc-phone-ticket-v1", "NFC_PHONE", reason);
  StaticJsonDocument<384> d; d["type"] = ble ? "ble_unlock" : "nfc_unlock"; d["ticket"] = ticket.substring(0, 200);
  d["result"] = r ? "denied" : "ok"; d["at"] = (long)time(nullptr); if (r) d["reason"] = r;
  if (r) { Serial.printf("[phone] tu choi: %s\n", r); buzz(300); } else setLock(true, true);
  sendEvent(d, true);
}
void onMsg(char* topic, byte* pl, unsigned len) {
  StaticJsonDocument<512> d; if (deserializeJson(d, pl, len)) return;
  String cmd = d["command"] | ""; cmd.toUpperCase(); const char* res = "ok";
  if (cmd == "UNLOCK") setLock(true, true);
  else if (cmd == "LOCK") setLock(false, false);
  else if (cmd == "PING") Serial.println("[cmd] PING");
  else if (cmd == "BUZZER_ALERT") buzz(10000);
  else if (cmd == "REBOOT") { Serial.println("[cmd] REBOOT"); delay(200); ESP.restart(); }
  else res = "failed";
  const char* id = d["command_id"] | nullptr;
  if (id) { StaticJsonDocument<256> a; a["command_id"] = id; a["token"] = d["token"] | ""; a["result"] = res; publishJson(tAck, a); }
  publishStatus();
}
void ensureMqtt() {
  if (WiFi.status() != WL_CONNECTED || mqtt.connected() || millis() - lastTry < 3000) return;
  lastTry = millis();
  if (mqtt.connect(DEVICE_CODE, DEVICE_CODE, SECRET)) {      // user = device_code, password = provisioning secret
    mqtt.subscribe(tCmd.c_str(), 1); Serial.println("[mqtt] connected"); publishStatus(); flushPending();
  } else Serial.printf("[mqtt] that bai rc=%d (4=sai user/secret, 5=ACL)\n", mqtt.state());
}

// ---------------------------------------------------------------- nhập liệu
void sendPin() {
  if (!pinBuf.length()) return;
  StaticJsonDocument<128> d; d["type"] = "pin_entry"; d["pin"] = pinBuf; pinBuf = ""; sendEvent(d, false);
}
void sendRfid(const String& uid) { StaticJsonDocument<128> d; d["type"] = "rfid_tap"; d["uid"] = uid; sendEvent(d, false); }
void sendFace(const String& json) {   // json = mảng 128 số do ESP32-CAM / dịch vụ nhận diện tính
  StaticJsonDocument<3072> d; d["type"] = "face_result"; DynamicJsonDocument e(3072);
  if (deserializeJson(e, json)) { Serial.println("[face] JSON sai"); return; } d["embedding"] = e.as<JsonArray>(); d["snapshot_url"] = ""; sendEvent(d, false);
}
void handleSerial() {
  if (!Serial.available()) return;
  String l = Serial.readStringUntil('\n'); l.trim(); int sp = l.indexOf(' '); String c = sp < 0 ? l : l.substring(0, sp), a = sp < 0 ? "" : l.substring(sp + 1);
  if (c == "rfid") sendRfid(a); else if (c == "ble") phoneUnlock(a, true); else if (c == "nfc") phoneUnlock(a, false);
  else if (c == "face") sendFace(a); else if (c == "tamper") { tamper = !tamper; if (tamper) buzz(5000); publishStatus(); }
  else if (c == "battery") { battery = constrain(a.toInt(), 0, 100); publishStatus(); }
  else Serial.println("HELP: rfid <UID> | ble <ticket> | nfc <ticket> | face [128 so] | tamper | battery <0-100> ; ban phim 4x4: so + # gui PIN, * xoa");
}

#ifdef USE_BLE
class TicketCb : public BLECharacteristicCallbacks { void onWrite(BLECharacteristic* c) override { phoneUnlock(String(c->getValue().c_str()), true); } };
void initBle() {
  BLEDevice::init(("SmartLock-" + String(DEVICE_CODE).substring(strlen(DEVICE_CODE) - 4)).c_str());
  BLEServer* s = BLEDevice::createServer(); BLEService* sv = s->createService("6e400001-b5a3-f393-e0a9-e50e24dcca9e");
  BLECharacteristic* ch = sv->createCharacteristic("6e400002-b5a3-f393-e0a9-e50e24dcca9e", BLECharacteristic::PROPERTY_WRITE);
  ch->setCallbacks(new TicketCb()); sv->start(); BLEDevice::getAdvertising()->addServiceUUID(sv->getUUID()); BLEDevice::startAdvertising();
}
#endif

void setup() {
  Serial.begin(115200);
  pinMode(PIN_BUZZ, OUTPUT); pinMode(PIN_LED_R, OUTPUT); pinMode(PIN_LED_G, OUTPUT);
  servo.attach(PIN_SERVO); setLock(false, false);
  secretHash = sha256Hex(SECRET);
  tCmd = String("smartlock/") + DEVICE_CODE + "/cmd"; tStatus = String("smartlock/") + DEVICE_CODE + "/status";
  tEvent = String("smartlock/") + DEVICE_CODE + "/event"; tAck = String("smartlock/") + DEVICE_CODE + "/ack";
  WiFi.begin(WIFI_SSID, WIFI_PASS); Serial.print("[wifi] ket noi");
  while (WiFi.status() != WL_CONNECTED) { delay(300); Serial.print("."); } Serial.println(" OK");
  configTime(7 * 3600, 0, "pool.ntp.org", "time.google.com");   // cần giờ thật để kiểm hạn vé
  mqtt.setServer(MQTT_HOST, MQTT_PORT); mqtt.setCallback(onMsg); mqtt.setBufferSize(4096);
#ifdef USE_RC522
  SPI.begin(); rfid.PCD_Init();
#endif
#ifdef USE_BLE
  initBle();
#endif
  Serial.println("San sang. Go 'help' de xem lenh Serial.");
}

void loop() {
  ensureMqtt(); mqtt.loop(); handleSerial();
  char k = kp.getKey();
  if (k) { if (k == '#') sendPin(); else if (k == '*') pinBuf = ""; else if (isDigit(k) && pinBuf.length() < 16) pinBuf += k; }
#ifdef USE_RC522
  if (rfid.PICC_IsNewCardPresent() && rfid.PICC_ReadCardSerial()) {
    String uid; for (byte i = 0; i < rfid.uid.size; i++) { char b[3]; sprintf(b, "%02X", rfid.uid.uidByte[i]); uid += b; }
    rfid.PICC_HaltA(); sendRfid(uid);
  }
#endif
  if (relockAt && millis() > relockAt) setLock(false, false), publishStatus();
  if (buzzUntil && millis() > buzzUntil) { digitalWrite(PIN_BUZZ, LOW); buzzUntil = 0; }
  if (millis() - lastStatus > STATUS_EVERY) { lastStatus = millis(); publishStatus(); }
}
