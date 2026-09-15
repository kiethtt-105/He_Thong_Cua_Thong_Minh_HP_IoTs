-- =====================================================================
--  SMART LOCK IoT — SUPABASE DATABASE SCHEMA 
-- =====================================================================

CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- =====================================================================
-- NHÓM A. NGƯỜI DÙNG & XÁC THỰC (AUTH / 2FA)
-- =====================================================================

-- ---------------------------------------------------------------------
-- A1. USERS 
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS "public"."users" (
  "id"               uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  "email"            varchar(255) UNIQUE NOT NULL,
  "password_hash"    varchar(255) NOT NULL,
  "full_name"        varchar(100),
  "phone"            varchar(20),
  "avatar_url"       varchar(512),
  "is_admin"         boolean NOT NULL DEFAULT false,
  "is_owner"         boolean NOT NULL DEFAULT false,
  "is_active"        boolean NOT NULL DEFAULT false,
  "email_verified"   boolean NOT NULL DEFAULT false,
  "two_fa_enabled"   boolean NOT NULL DEFAULT false,
  "totp_enabled"     boolean NOT NULL DEFAULT false,
  "hotp_enabled"     boolean NOT NULL DEFAULT false,   
  "fido2_enabled"    boolean NOT NULL DEFAULT false,
  "force_disable_2fa" boolean NOT NULL DEFAULT false,
  "is_2fa_required"  boolean NOT NULL DEFAULT false,
  "force_logout"     boolean NOT NULL DEFAULT false,
  "allow_push_auth"  boolean NOT NULL DEFAULT true,
  "created_at"       timestamptz NOT NULL DEFAULT now(),
  "updated_at"       timestamptz NOT NULL DEFAULT now()
);

-- COMMENT ON TABLE  "public"."users" IS 'Tài khoản hệ thống duy nhất...';
COMMENT ON TABLE  "public"."users" IS 'Tài khoản hệ thống duy nhất. is_admin và is_owner là 2 CỜ độc lập, không phải role loại trừ nhau.';
COMMENT ON COLUMN "public"."users"."is_owner" IS 'KHÔNG được client set trực tiếp. Được duy trì tự động bởi trigger fn_maintain_is_owner() dựa trên devices.owner_id.';
COMMENT ON COLUMN "public"."users"."is_admin" IS 'Admin đầu tiên bootstrap thủ công lúc khởi tạo hệ thống. is_admin KHÔNG đồng nghĩa có quyền can thiệp trực tiếp mọi device (xem support_requests).';
COMMENT ON COLUMN "public"."users"."two_fa_enabled" IS 'Cờ bật/tắt xác thực bằng EMAIL OTP cụ thể (không phải cờ tổng quát). Xem thêm totp_enabled, hotp_enabled, fido2_enabled cho các phương thức còn lại — user có thể bật đồng thời nhiều phương thức.';
COMMENT ON COLUMN "public"."users"."totp_enabled" IS 'Bật/tắt xác thực bằng ứng dụng Authenticator (Google Authenticator, Authy...). Độc lập với two_fa_enabled và hotp_enabled.';
COMMENT ON COLUMN "public"."users"."hotp_enabled" IS 'Bật/tắt xác thực HOTP (mã theo bộ đếm, thường dùng cho token cứng/khoá vật lý). Tách riêng khỏi TOTP để tránh xung đột khi user bật cả hai (tương ứng otp_secret/hotp_secret tách biệt bên Django).';
COMMENT ON COLUMN "public"."users"."force_disable_2fa" IS 'Admin cưỡng chế tắt toàn bộ 2FA của user (dùng khi user bị khoá thiết bị/mất quyền truy cập). Khi true, is_2fa_active (suy ra từ các cờ *_enabled) luôn coi như false ở tầng backend.';
COMMENT ON COLUMN "public"."users"."is_2fa_required" IS 'Admin/chính sách hệ thống bắt buộc user này phải bật ít nhất 1 phương thức 2FA mới được dùng đầy đủ chức năng.';
COMMENT ON COLUMN "public"."users"."allow_push_auth" IS 'Cho phép nhận yêu cầu xác nhận đăng nhập (push) từ thiết bị tin cậy khác. Chỉ có tác dụng khi user có ít nhất 1 phương thức 2FA đang bật.';

-- ---------------------------------------------------------------------
-- A2. SESSIONS — phiên đăng nhập / refresh token
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS "public"."sessions" (
  "id"                  uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  "user_id"             uuid NOT NULL REFERENCES "public"."users"(id) ON DELETE CASCADE,
  "refresh_token_hash"  varchar(255) UNIQUE NOT NULL,
  "device_info"         text,
  "ip_address"          varchar(45),
  "is_revoked"          boolean NOT NULL DEFAULT false,
  "expires_at"          timestamptz NOT NULL,
  "created_at"          timestamptz NOT NULL DEFAULT now(),
  "last_active_at"      timestamptz NOT NULL DEFAULT now()
);
COMMENT ON COLUMN "public"."sessions"."refresh_token_hash" IS 'Chỉ lưu HASH của refresh token, không lưu token gốc.';

-- ---------------------------------------------------------------------
-- A3. WEBAUTHN_CREDENTIALS — FIDO2 / Passkey
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS "public"."webauthn_credentials" (
  "id"             uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  "user_id"        uuid NOT NULL REFERENCES "public"."users"(id) ON DELETE CASCADE,
  "credential_id"  varchar(512) UNIQUE NOT NULL,
  "public_key"     text NOT NULL,
  "sign_count"     bigint NOT NULL DEFAULT 0,
  "transports"     text[],
  "aaguid"         varchar(36),
  "created_at"     timestamptz NOT NULL DEFAULT now(),
  "last_used_at"   timestamptz
);
COMMENT ON COLUMN "public"."webauthn_credentials"."public_key" IS 'CHỈ lưu Public Key. Private key tuyệt đối không xuất hiện trên server (nằm ở Secure Enclave/TPM/khoá bảo mật của client).';
COMMENT ON COLUMN "public"."webauthn_credentials"."sign_count" IS 'Dùng để phát hiện replay attack: sign_count mới phải luôn > sign_count đã lưu.';

-- ---------------------------------------------------------------------
-- A4. PENDING_REGISTRATIONS — đăng ký tạm chờ xác thực OTP email
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS "public"."pending_registrations" (
  "id"             uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  "email"          varchar(255) UNIQUE NOT NULL,
  "otp_code_hash"  varchar(64) NOT NULL,
  "temp_data"      jsonb NOT NULL DEFAULT '{}'::jsonb,
  "is_used"        boolean NOT NULL DEFAULT false,
  "expires_at"     timestamptz NOT NULL DEFAULT (now() + interval '10 minutes'),
  "created_at"     timestamptz NOT NULL DEFAULT now()
);
COMMENT ON TABLE  "public"."pending_registrations" IS 'Lưu thông tin đăng ký TẠM THỜI trước khi user xác thực OTP email thành công. Chưa có bản ghi trong "users" ở giai đoạn này.';
COMMENT ON COLUMN "public"."pending_registrations"."otp_code_hash" IS 'SHA-256 hex (64 ký tự) của mã OTP — không bao giờ lưu plaintext.';
COMMENT ON COLUMN "public"."pending_registrations"."temp_data" IS 'Chứa các trường chờ tạo user (email, họ tên, password_hash đã hash sẵn ở backend bằng Argon2id...). KHÔNG BAO GIỜ lưu password plaintext trong JSON này.';
COMMENT ON COLUMN "public"."pending_registrations"."expires_at" IS 'Mặc định hết hạn sau 10 phút kể từ khi tạo — trùng OTP_EXPIRY_MINUTES phía backend.';

-- ---------------------------------------------------------------------
-- A5. EMAIL_OTP_CHALLENGES — OTP qua email (2FA / verify / support...)
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS "public"."email_otp_challenges" (
  "id"             uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  "user_id"        uuid NOT NULL REFERENCES "public"."users"(id) ON DELETE CASCADE,
  "purpose"        varchar(50) NOT NULL
                     CHECK (purpose IN ('EMAIL_VERIFY','LOGIN_2FA','SUPPORT_AUTH','PASSWORD_RESET','RECOVERY_CONFIRM','UPDATE_INFO','DISABLE_2FA')),
  "otp_code_hash"  varchar(255) NOT NULL,
  "attempts"       int NOT NULL DEFAULT 0,
  "max_attempts"   int NOT NULL DEFAULT 3,
  "is_used"        boolean NOT NULL DEFAULT false,
  "used_at"        timestamptz,
  "expires_at"     timestamptz NOT NULL,
  "created_at"     timestamptz NOT NULL DEFAULT now()
);
COMMENT ON COLUMN "public"."email_otp_challenges"."otp_code_hash" IS 'OTP chuẩn: 6 chữ số. TTL khuyến nghị 3-5 phút. Chỉ lưu hash (SHA-256/Argon2id).';
COMMENT ON COLUMN "public"."email_otp_challenges"."purpose" IS 'UPDATE_INFO/DISABLE_2FA bổ sung so với bản gốc để bao phủ toàn bộ ACTION_CHOICES của EmailOTP bên Django (register/login_2fa/setup_2fa/update_info/disable_2fa), gộp chung với các purpose xác thực khác của hệ khoá cửa.';

-- ---------------------------------------------------------------------
-- A6. TOTP_CREDENTIALS — secret ứng dụng Authenticator (1 user = 1 secret)
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS "public"."totp_credentials" (
  "id"                 uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  "user_id"            uuid UNIQUE NOT NULL REFERENCES "public"."users"(id) ON DELETE CASCADE,
  "secret_encrypted"   text NOT NULL,
  "algorithm"          varchar(10) NOT NULL DEFAULT 'SHA1' CHECK (algorithm IN ('SHA1','SHA256','SHA512')),
  "digits"             int NOT NULL DEFAULT 6 CHECK (digits IN (6,8)),
  "period_seconds"     int NOT NULL DEFAULT 30 CHECK (period_seconds > 0),
  "is_active"          boolean NOT NULL DEFAULT false,
  "created_at"         timestamptz NOT NULL DEFAULT now(),
  "activated_at"       timestamptz,
  "last_used_at"       timestamptz
);
COMMENT ON TABLE  "public"."totp_credentials" IS 'Secret TOTP dùng cho Google Authenticator/Authy. Chỉ có 1 secret trên mỗi user tại một thời điểm (tương ứng UserProfile.otp_secret bên Django).';
COMMENT ON COLUMN "public"."totp_credentials"."secret_encrypted" IS 'MÃ HOÁ (Fernet/AES-256-GCM) bằng khoá KMS/ENV ở backend — KHÔNG hash, vì backend cần giải mã để tự tính mã OTP so khớp. Secret gốc plaintext KHÔNG BAO GIỜ ghi log/lưu nơi khác.';
COMMENT ON COLUMN "public"."totp_credentials"."is_active" IS 'false ngay sau khi tạo (chờ user quét QR + nhập đúng 1 mã để xác nhận sở hữu thiết bị) → true sau khi verify thành công lần đầu.';

-- ---------------------------------------------------------------------
-- A7. HOTP_CREDENTIALS — secret HOTP tách riêng khỏi TOTP
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS "public"."hotp_credentials" (
  "id"                 uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  "user_id"            uuid UNIQUE NOT NULL REFERENCES "public"."users"(id) ON DELETE CASCADE,
  "secret_encrypted"   text NOT NULL,
  "counter"            bigint NOT NULL DEFAULT 0,
  "digits"             int NOT NULL DEFAULT 6 CHECK (digits IN (6,8)),
  "is_active"          boolean NOT NULL DEFAULT false,
  "created_at"         timestamptz NOT NULL DEFAULT now(),
  "activated_at"       timestamptz,
  "last_used_at"       timestamptz
);
COMMENT ON TABLE  "public"."hotp_credentials" IS 'Tương ứng UserProfile.hotp_secret + hotp_counter bên Django. Tách bảng riêng (không dùng chung totp_credentials) để user bật đồng thời cả TOTP lẫn HOTP mà không xung đột.';
COMMENT ON COLUMN "public"."hotp_credentials"."secret_encrypted" IS 'MÃ HOÁ (không hash) — lý do giống totp_credentials.secret_encrypted: backend cần giải mã để tự tính lại mã HOTP theo counter.';
COMMENT ON COLUMN "public"."hotp_credentials"."counter" IS 'Bộ đếm phía SERVER. Sau mỗi lần verify thành công phải tăng +1. Đồng bộ lệch counter giữa server/token cứng xử lý bằng cửa sổ look-ahead ở tầng backend, không ở DB.';

-- ---------------------------------------------------------------------
-- A8. ACCOUNT_BACKUP_CODES — mã dự phòng dùng 1 lần cho tài khoản
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS "public"."account_backup_codes" (
  "id"           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  "user_id"      uuid NOT NULL REFERENCES "public"."users"(id) ON DELETE CASCADE,
  "code_hash"    varchar(255) NOT NULL,
  "is_used"      boolean NOT NULL DEFAULT false,
  "used_at"      timestamptz,
  "created_at"   timestamptz NOT NULL DEFAULT now()
);
COMMENT ON TABLE "public"."account_backup_codes" IS 'Tương ứng model BackupCode bên Django: mã dự phòng CHUNG cho tài khoản (dùng được khi mất App OTP/HOTP/thiết bị FIDO2), KHÔNG ràng buộc riêng vào TOTP. Mỗi lần (tái) tạo: xoá hết mã cũ của user, sinh 8 mã mới dạng "xxxx-xxxx", chỉ hiển thị plaintext đúng 1 lần cho user, DB chỉ lưu SHA-256 hash.';

-- ---------------------------------------------------------------------
-- A9. TRUSTED_LOGIN_DEVICES — thiết bị đăng nhập tin cậy của user
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS "public"."trusted_login_devices" (
  "id"            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  "user_id"       uuid NOT NULL REFERENCES "public"."users"(id) ON DELETE CASCADE,
  "device_uid"    uuid UNIQUE NOT NULL DEFAULT gen_random_uuid(),
  "session_key"   varchar(40),
  "name"          varchar(255) NOT NULL DEFAULT 'Thiết bị không xác định',
  "user_agent"    text,
  "ip_address"    varchar(45),
  "is_active"     boolean NOT NULL DEFAULT true,
  "is_trusted"    boolean NOT NULL DEFAULT false,
  "last_seen_at"  timestamptz NOT NULL DEFAULT now(),
  "created_at"    timestamptz NOT NULL DEFAULT now()
);
COMMENT ON TABLE  "public"."trusted_login_devices" IS 'Tương ứng model TrustedDevice bên Django: thiết bị (điện thoại/app) mà user đã đăng nhập, dùng để nhận & xử lý yêu cầu xác nhận đăng nhập (push auth) từ thiết bị khác. KHÔNG liên quan tới bảng "devices" (khoá cửa vật lý/giả lập).';
COMMENT ON COLUMN "public"."trusted_login_devices"."device_uid" IS 'Định danh thiết bị phía client (lưu local trên app/trình duyệt), dùng để nhận diện lại thiết bị ở các lần đăng nhập sau.';
COMMENT ON COLUMN "public"."trusted_login_devices"."is_trusted" IS 'Chỉ thiết bị is_trusted=true mới được chọn làm target_device_id trong remote_auth_requests (ép buộc bởi trigger fn_check_target_device_trusted).';

-- ---------------------------------------------------------------------
-- A10. REMOTE_AUTH_REQUESTS 
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS "public"."remote_auth_requests" (
  "id"                      uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  "user_id"                 uuid NOT NULL REFERENCES "public"."users"(id) ON DELETE CASCADE,
  "session_key"             varchar(40) NOT NULL,
  "target_device_id"        uuid REFERENCES "public"."trusted_login_devices"(id) ON DELETE SET NULL,
  "device_info"             varchar(255) NOT NULL,
  "status"                  varchar(20) NOT NULL DEFAULT 'pending'
                              CHECK (status IN ('pending','approved','denied')),
  "expires_at"              timestamptz,
  "created_at"              timestamptz NOT NULL DEFAULT now()
);
COMMENT ON TABLE  "public"."remote_auth_requests" IS 'Tương ứng model RemoteAuthRequest bên Django: thiết bị mới xin xác nhận đăng nhập từ một thiết bị tin cậy đang online (push-auth). expires_at tự set = created_at + 120 giây nếu không truyền (trigger fn_set_remote_auth_expiry).';
COMMENT ON COLUMN "public"."remote_auth_requests"."target_device_id" IS 'Trỏ đúng 1 thiết bị tin cậy sẽ nhận popup xác nhận — KHÔNG broadcast cho tất cả thiết bị của user.';
COMMENT ON COLUMN "public"."remote_auth_requests"."session_key" IS 'Session của thiết bị/trình duyệt ĐANG XIN xác thực (chưa đăng nhập xong), dùng để poll trạng thái approved/denied.';

-- ---------------------------------------------------------------------
-- A11. LOGIN_OTP_ATTEMPTS — rate limit chống brute-force OTP/đăng nhập
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS "public"."login_otp_attempts" (
  "id"          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  "user_id"     uuid REFERENCES "public"."users"(id) ON DELETE CASCADE,
  "ip_address"  varchar(45) NOT NULL DEFAULT '',
  "action"      varchar(20) NOT NULL DEFAULT 'LOGIN_2FA'
                  CHECK (action IN ('LOGIN_2FA','EMAIL_OTP','TOTP','HOTP','BACKUP_CODE')),
  "created_at"  timestamptz NOT NULL DEFAULT now()
);
COMMENT ON TABLE  "public"."login_otp_attempts" IS 'Tương ứng model OTPAttempt/HOTPAttempt bên Django: mỗi bản ghi = 1 LẦN NHẬP SAI. Backend đếm số bản ghi trong cửa sổ thời gian (VD 5 lần sai / 10 phút cho OTP thường, 5 lần sai / 30 phút cho HOTP — HOTPAttempt là proxy dùng chung bảng này với action=''HOTP'') để khoá tạm user/IP. Dọn bản ghi cũ định kỳ qua cron/Edge Function, KHÔNG dọn trong request.';

-- ---------------------------------------------------------------------
-- A12. SYSTEM_SETTINGS — cấu hình hệ thống dạng singleton (chỉ 1 dòng)
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS "public"."system_settings" (
  "id"                     smallint PRIMARY KEY DEFAULT 1 CHECK (id = 1),
  "registration_enabled"   boolean NOT NULL DEFAULT true,
  "require_2fa_all"        boolean NOT NULL DEFAULT false,
  "otp_expiry_minutes"     int NOT NULL DEFAULT 5,
  "otp_max_retry"          int NOT NULL DEFAULT 5,
  "session_timeout_hours"  int NOT NULL DEFAULT 24,
  "ip_whitelist"           text NOT NULL DEFAULT '',
  "ip_blacklist"           text NOT NULL DEFAULT '',
  "updated_at"             timestamptz NOT NULL DEFAULT now(),
  "updated_by"             uuid REFERENCES "public"."users"(id) ON DELETE SET NULL
);
COMMENT ON TABLE "public"."system_settings" IS 'Luôn chỉ có đúng 1 dòng (id=1), ép buộc bằng CHECK (id = 1) thay cho get_or_create() ở tầng ORM.';

-- ---------------------------------------------------------------------
-- A13. ANNOUNCEMENTS — thông báo hệ thống gửi tới toàn bộ user
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS "public"."announcements" (
  "id"          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  "title"       varchar(200) NOT NULL,
  "body"        text NOT NULL,
  "level"       varchar(10) NOT NULL DEFAULT 'info' CHECK (level IN ('info','warning','danger')),
  "created_by"  uuid REFERENCES "public"."users"(id) ON DELETE SET NULL,
  "is_active"   boolean NOT NULL DEFAULT true,
  "created_at"  timestamptz NOT NULL DEFAULT now()
);
COMMENT ON TABLE "public"."announcements" IS 'Banner/thông báo toàn hệ thống do Admin tạo (info/warning/danger).';

-- =====================================================================
-- NHÓM B. THIẾT BỊ (DEVICES) — VẬT LÝ + GIẢ LẬP  
-- =====================================================================

-- ---------------------------------------------------------------------
-- B1. DEVICES
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS "public"."devices" (
  "id"                        uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  "device_code"               varchar(50) UNIQUE NOT NULL,
  "provisioning_secret_hash"  varchar(255) NOT NULL,
  "device_mode"               varchar(20) NOT NULL DEFAULT 'physical'
                                CHECK (device_mode IN ('physical','simulated')),
  "owner_id"                  uuid REFERENCES "public"."users"(id) ON DELETE RESTRICT,
  "name"                      varchar(100) NOT NULL,
  "mac_address"               varchar(17),
  "firmware_version"          varchar(30),
  "status"                    varchar(20) NOT NULL DEFAULT 'provisioning'
                                CHECK (status IN ('online','offline','maintenance','provisioning')),
  "battery_level"             int NOT NULL DEFAULT 100 CHECK (battery_level BETWEEN 0 AND 100),
  "location"                  varchar(255),
  "last_seen_at"              timestamptz,
  "bluetooth_enabled"         boolean NOT NULL DEFAULT true,
  "wifi_enabled"              boolean NOT NULL DEFAULT true,
  "nfc_enabled"               boolean NOT NULL DEFAULT true,
  "created_at"                timestamptz NOT NULL DEFAULT now(),
  "updated_at"                timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT chk_devices_owner_vs_status CHECK (
       (status = 'provisioning' AND owner_id IS NULL)
    OR (status <> 'provisioning' AND owner_id IS NOT NULL)
  )
);

COMMENT ON TABLE  "public"."devices" IS 'Một device chỉ có duy nhất 1 owner tại một thời điểm. Đổi owner bắt buộc qua quy trình RESET (owner_id -> NULL, status -> provisioning) rồi mới cho claim mới.';
COMMENT ON COLUMN "public"."devices"."device_code" IS 'Mã định danh in trên tem/QR vật lý của thiết bị (hoặc mã cấu hình của bộ giả lập). Dùng để claim/pair, KHÔNG chứa bí mật.';
COMMENT ON COLUMN "public"."devices"."provisioning_secret_hash" IS
  'HASH của "provisioning secret" — bí mật gốc (root of trust) cao nhất của thiết bị, do nhà sản xuất/hệ thống cấp cùng lúc với device_code (VD: in ở mặt sau tem, hoặc issue key khi khởi tạo bộ giả lập). '
  'Bắt buộc phải xuất trình đúng secret này (kèm device_code) khi: (1) CLAIM thiết bị lần đầu, (2) RESET/factory-reset, (3) RECOVERY, (4) TRANSFER OWNER. '
  'ADMIN dù is_admin = TRUE cũng KHÔNG thể bỏ qua bước xác minh secret này — đây là nguyên tắc "mã thiết bị có quyền cao nhất", độc lập với quyền tài khoản.';
COMMENT ON COLUMN "public"."devices"."device_mode" IS
  '''physical''  = thiết bị khoá Druino BLK Plus thật, giao tiếp qua NFC/BLE/Wi-Fi module thật. '
  '''simulated'' = thiết bị mô phỏng bằng phần mềm (dùng khi demo/đồ án không có đủ phần cứng); backend/simulator service đóng vai trò firmware, dùng lại NGUYÊN VẸN luồng device_commands / device_status_logs như thiết bị thật.';
COMMENT ON COLUMN "public"."devices"."status" IS '''provisioning'' = thiết bị chưa có owner (mới xuất xưởng hoặc vừa reset), chờ được claim.';

-- ---------------------------------------------------------------------
-- B2. DEVICE_STATUS_LOGS — telemetry định kỳ (pin, RSSI, nhiệt độ, ...)
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS "public"."device_status_logs" (
  "id"                uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  "device_id"         uuid NOT NULL REFERENCES "public"."devices"(id) ON DELETE CASCADE,
  "battery_level"     int NOT NULL CHECK (battery_level BETWEEN 0 AND 100),
  "signal_strength"   int,
  "lock_state"        varchar(20) NOT NULL CHECK (lock_state IN ('locked','unlocked','jammed','unknown')),
  "tamper_detected"   boolean NOT NULL DEFAULT false,
  "temperature"       numeric(4,1),
  "raw_payload"       jsonb,
  "recorded_at"       timestamptz NOT NULL DEFAULT now()
);

-- ---------------------------------------------------------------------
-- B3. DEVICE_COMMANDS — hàng chờ lệnh Backend -> Device 
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS "public"."device_commands" (
  "id"                  uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  "device_id"           uuid NOT NULL REFERENCES "public"."devices"(id) ON DELETE CASCADE,
  "issued_by"           uuid NOT NULL REFERENCES "public"."users"(id) ON DELETE RESTRICT,
  "command_type"        varchar(50) NOT NULL
                          CHECK (command_type IN ('UNLOCK','LOCK','ADD_CARD','REMOVE_CARD','RESET','OTA_UPDATE','REBOOT')),
  "payload"             jsonb,
  "status"              varchar(20) NOT NULL DEFAULT 'pending'
                          CHECK (status IN ('pending','sent','acknowledged','failed','expired')),
  "command_token_hash"  varchar(255) NOT NULL,
  "expires_at"          timestamptz NOT NULL,
  "created_at"          timestamptz NOT NULL DEFAULT now(),
  "acknowledged_at"     timestamptz
);
COMMENT ON COLUMN "public"."device_commands"."command_token_hash" IS 'Token chống replay: device chỉ chấp nhận thực thi 1 lần cho mỗi token, kể cả với device_mode = simulated.';

-- =====================================================================
-- NHÓM C. QUYỀN & CHIA SẺ KHÓA (GRANULAR PERMISSIONS)
-- =====================================================================

-- ---------------------------------------------------------------------
-- C1. PERMISSIONS — danh mục quyền
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS "public"."permissions" (
  "id"            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  "code"          varchar(50) UNIQUE NOT NULL,
  "name"          varchar(100) NOT NULL,
  "description"   text,
  "is_sensitive"  boolean NOT NULL DEFAULT false
);

INSERT INTO "public"."permissions" (code, name, is_sensitive, description) VALUES
  ('device.view',            'Xem thông tin khoá',        false, 'Xem trạng thái, thông tin cơ bản của khoá'),
  ('device.unlock',          'Mở khoá',                    false, 'Thực hiện lệnh unlock qua NFC/BLE/Remote'),
  ('device.lock',            'Khoá',                       false, 'Thực hiện lệnh lock qua NFC/BLE/Remote'),
  ('device.view_logs',       'Xem lịch sử ra vào',         false, 'Xem device_status_logs / audit liên quan đến khoá'),
  ('device.manage_users',    'Quản lý người được chia sẻ', true,  'Thêm/sửa/thu hồi device_access của user khác'),
  ('device.manage_cards',    'Quản lý thẻ NFC',            true,  'Thêm/gỡ card_device_access cho khoá'),
  ('device.manage_pin',      'Quản lý mã PIN khoá',        true,  'Thiết lập/đổi mã PIN vật lý (nếu phần cứng hỗ trợ)'),
  ('device.manage_schedule', 'Quản lý lịch tự động',       true,  'Đặt lịch tự động khoá/mở'),
  ('device.configure',       'Cấu hình thiết bị',          true,  'Đổi tên, vị trí, bật/tắt BLE/Wi-Fi/NFC module'),
  ('device.create_support',  'Tạo yêu cầu hỗ trợ Admin',   false, 'Sinh support request + authorization/recovery code'),
  ('device.reset',           'Reset khoá',                  true,  'Đưa khoá về trạng thái provisioning'),
  ('device.recovery',        'Khôi phục khoá',              true,  'Quy trình recovery khi mất quyền truy cập'),
  ('device.transfer_owner',  'Chuyển nhượng chủ sở hữu',    true,  'Đổi owner_id sau khi reset'),
  ('device.ota',             'Cập nhật firmware (OTA)',     true,  'Đẩy firmware mới xuống thiết bị')
ON CONFLICT (code) DO NOTHING;

-- ---------------------------------------------------------------------
-- C2. DEVICE_ACCESS — user nào có quyền gì trên device nào, thời hạn bao lâu
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS "public"."device_access" (
  "id"               uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  "device_id"        uuid NOT NULL REFERENCES "public"."devices"(id) ON DELETE CASCADE,
  "user_id"          uuid NOT NULL REFERENCES "public"."users"(id) ON DELETE CASCADE,
  "permissions"      text[] NOT NULL,
  "share_code_hash"  varchar(255),
  "valid_from"       timestamptz NOT NULL DEFAULT now(),
  "expires_at"       timestamptz,
  "is_active"        boolean NOT NULL DEFAULT true,
  "accepted"         boolean NOT NULL DEFAULT false,
  "created_by"       uuid NOT NULL REFERENCES "public"."users"(id) ON DELETE RESTRICT,
  "created_at"       timestamptz NOT NULL DEFAULT now(),
  "revoked_at"       timestamptz,
  CONSTRAINT chk_device_access_expiry CHECK (expires_at IS NULL OR expires_at > valid_from)
);
COMMENT ON COLUMN "public"."device_access"."share_code_hash" IS 'Chuẩn: SHARE CODE = 6 CHỮ SỐ ngẫu nhiên (000000-999999). Chỉ lưu hash; user phải ACCEPT + nhập đúng code thì accepted mới chuyển true.';

-- =====================================================================
-- NHÓM D. THẺ NFC & PHẦN CỨNG ĐẦU ĐỌC (Druino BLK Plus: Master + Head)
-- =====================================================================

-- ---------------------------------------------------------------------
-- D1. ACCESS_CARDS — danh mục thẻ NFC
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS "public"."access_cards" (
  "id"              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  "card_uid_hash"   varchar(255) UNIQUE NOT NULL,
  "label"           varchar(100),
  "card_type"       varchar(30) NOT NULL DEFAULT 'mifare_s50'
                      CHECK (card_type IN ('mifare_s50','mifare_desfire','ntag213','ntag215','ntag216','other')),
  "key_a"           varchar(255),
  "manufacturer"    varchar(100),
  "status"          varchar(20) NOT NULL DEFAULT 'active' CHECK (status IN ('active','revoked','lost')),
  "registered_by"   uuid NOT NULL REFERENCES "public"."users"(id) ON DELETE RESTRICT,
  "registered_at"   timestamptz NOT NULL DEFAULT now(),
  "revoked_at"      timestamptz
);
COMMENT ON TABLE  "public"."access_cards" IS 'Danh mục thẻ NFC TOÀN HỆ THỐNG, đăng ký qua Master Reader (máy tổng) TRƯỚC khi được cấp cho bất kỳ device nào.';
COMMENT ON COLUMN "public"."access_cards"."card_uid_hash" IS 'HASH của UID thẻ, không lưu UID gốc dạng plaintext.';
COMMENT ON COLUMN "public"."access_cards"."key_a" IS 'Tham chiếu/khoá xác thực mật mã (VD Mifare Key A) khi phần cứng hỗ trợ challenge-response; KHÔNG lưu secret gốc dạng plaintext.';

-- ---------------------------------------------------------------------
-- D2. CARD_DEVICE_ACCESS — thẻ nào mở được khoá nào
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS "public"."card_device_access" (
  "id"               uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  "access_card_id"   uuid NOT NULL REFERENCES "public"."access_cards"(id) ON DELETE CASCADE,
  "device_id"        uuid NOT NULL REFERENCES "public"."devices"(id) ON DELETE CASCADE,
  "granted_by"       uuid NOT NULL REFERENCES "public"."users"(id) ON DELETE RESTRICT,
  "valid_from"       timestamptz NOT NULL DEFAULT now(),
  "expires_at"       timestamptz,
  "is_active"        boolean NOT NULL DEFAULT true,
  "created_at"       timestamptz NOT NULL DEFAULT now(),
  "revoked_at"       timestamptz,
  CONSTRAINT chk_card_device_access_expiry CHECK (expires_at IS NULL OR expires_at > valid_from)
);

-- ---------------------------------------------------------------------
-- D3. NFC_READERS — phần cứng đầu đọc: MASTER (máy tổng) / HEAD (gắn khoá)
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS "public"."nfc_readers" (
  "id"                uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  "device_id"         uuid REFERENCES "public"."devices"(id) ON DELETE CASCADE,
  "name"              text NOT NULL,
  "type"              text NOT NULL CHECK (type IN ('master','head')),
  "reader_mode"       varchar(20) NOT NULL DEFAULT 'physical'
                        CHECK (reader_mode IN ('physical','simulated')),
  "serial_number"     text UNIQUE,
  "firmware_version"  text,
  "last_connected"    timestamptz,
  "created_at"        timestamptz NOT NULL DEFAULT now(),
  "updated_at"        timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT chk_nfc_readers_type_device CHECK (
       (type = 'master' AND device_id IS NULL)
    OR (type = 'head'   AND device_id IS NOT NULL)
  )
);
COMMENT ON TABLE  "public"."nfc_readers" IS 'MASTER = máy tổng đăng ký thẻ, đứng độc lập (device_id NULL). HEAD = đầu đọc NFC gắn liền trên một khoá cụ thể (device_id bắt buộc).';
COMMENT ON COLUMN "public"."nfc_readers"."reader_mode" IS '''physical'' = đầu đọc NFC thật (module Druino BLK Plus). ''simulated'' = giả lập tap thẻ bằng phần mềm/app khi demo không có phần cứng.';

-- ---------------------------------------------------------------------
-- D4. NFC_READER_CONFIGS — cấu hình auto-register cho Master Reader
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS "public"."nfc_reader_configs" (
  "id"                uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  "reader_id"         uuid UNIQUE NOT NULL REFERENCES "public"."nfc_readers"(id) ON DELETE CASCADE,
  "auto_register"     boolean NOT NULL DEFAULT false,
  "grant_permission"  text[],
  "valid_from"        timestamptz NOT NULL DEFAULT now(),
  "expires_at"        timestamptz,
  "created_at"        timestamptz NOT NULL DEFAULT now()
);
COMMENT ON COLUMN "public"."nfc_reader_configs"."auto_register" IS 'Chỉ hợp lệ khi reader tương ứng có type = master (được ép buộc bởi trigger fn_check_reader_config_master).';

-- ---------------------------------------------------------------------
-- D5. NFC_SESSIONS — phiên giao tiếp giữa reader và thẻ/thiết bị
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS "public"."nfc_sessions" (
  "id"               uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  "reader_id"        uuid NOT NULL REFERENCES "public"."nfc_readers"(id) ON DELETE CASCADE,
  "nfc_tag_id"       uuid REFERENCES "public"."access_cards"(id) ON DELETE SET NULL,
  "device_id"        uuid REFERENCES "public"."devices"(id) ON DELETE SET NULL,
  "user_id"          uuid REFERENCES "public"."users"(id) ON DELETE SET NULL,
  "session_token"    text UNIQUE NOT NULL,
  "started_at"       timestamptz NOT NULL DEFAULT now(),
  "ended_at"         timestamptz,
  "success"          boolean NOT NULL DEFAULT false,
  "payload"          jsonb,
  CONSTRAINT chk_nfc_sessions_time CHECK (ended_at IS NULL OR ended_at >= started_at)
);

-- ---------------------------------------------------------------------
-- D6. NFC_LOGS — nhật ký sự kiện tap/kết nối reader (bảo mật, KHÔNG cascade)
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS "public"."nfc_logs" (
  "id"           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  "reader_id"    uuid REFERENCES "public"."nfc_readers"(id) ON DELETE SET NULL,
  "nfc_tag_id"   uuid REFERENCES "public"."access_cards"(id) ON DELETE SET NULL,
  "device_id"    uuid REFERENCES "public"."devices"(id) ON DELETE SET NULL,
  "user_id"      uuid REFERENCES "public"."users"(id) ON DELETE SET NULL,
  "event_type"   text NOT NULL
                   CHECK (event_type IN ('TAP_SUCCESS','TAP_FAILED','CARD_REGISTER','READER_CONNECTED','READER_DISCONNECTED','CONFIG_UPDATED','SESSION_TIMEOUT')),
  "success"      boolean NOT NULL DEFAULT true,
  "ip_address"   text,
  "user_agent"   text,
  "metadata"     jsonb,
  "created_at"   timestamptz NOT NULL DEFAULT now()
);
COMMENT ON TABLE "public"."nfc_logs" IS 'Log bảo mật lớp NFC — cố ý dùng ON DELETE SET NULL (không CASCADE) để giữ vết lịch sử kể cả khi reader/card/device bị xoá.';

-- =====================================================================
-- NHÓM E. HỖ TRỢ KỸ THUẬT, THÔNG BÁO & NHẬT KÝ AN NINH
-- =====================================================================

-- ---------------------------------------------------------------------
-- E1. SUPPORT_REQUESTS — Owner nhờ Admin xử lý thao tác nhạy cảm (scoped)
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS "public"."support_requests" (
  "id"                        uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  "device_id"                 uuid NOT NULL REFERENCES "public"."devices"(id) ON DELETE CASCADE,
  "requested_by"              uuid NOT NULL REFERENCES "public"."users"(id) ON DELETE RESTRICT,
  "action"                    varchar(50) NOT NULL
                                CHECK (action IN ('ADD_CARD','REMOVE_CARD','CHANGE_PERMISSION','RESET_REMOTE','RECOVERY','TRANSFER_OWNER','OTA_SENSITIVE','OTHER')),
  "scope"                     varchar(100) NOT NULL,
  "authorization_code_hash"   varchar(255) NOT NULL,
  "recovery_code_hash"        varchar(255),
  "status"                    varchar(20) NOT NULL DEFAULT 'pending'
                                CHECK (status IN ('pending','approved','executed','expired','rejected','cancelled')),
  "expires_at"                timestamptz NOT NULL,
  "processed_by"              uuid REFERENCES "public"."users"(id) ON DELETE SET NULL,
  "created_at"                timestamptz NOT NULL DEFAULT now(),
  "completed_at"              timestamptz,
  CONSTRAINT chk_support_requires_recovery CHECK (
    (action IN ('RESET_REMOTE','RECOVERY','TRANSFER_OWNER') AND recovery_code_hash IS NOT NULL)
    OR (action NOT IN ('RESET_REMOTE','RECOVERY','TRANSFER_OWNER'))
  )
);
COMMENT ON COLUMN "public"."support_requests"."authorization_code_hash" IS 'Chuẩn: AUTHORIZATION CODE = 6 KÝ TỰ chữ-số (A-Z, 0-9, bỏ ký tự dễ nhầm O/0, I/1). Owner tạo, chỉ lưu hash, có TTL + scope hạn chế đúng 1 action.';
COMMENT ON COLUMN "public"."support_requests"."recovery_code_hash" IS 'Chuẩn: RECOVERY CODE = 10 KÝ TỰ chữ-số, quyền hạn CAO HƠN authorization_code. Bắt buộc phải có với action RESET_REMOTE / RECOVERY / TRANSFER_OWNER (ép buộc bằng CHECK constraint).';
COMMENT ON COLUMN "public"."support_requests"."scope" IS 'Mã quyền cụ thể ADMIN được phép dùng (VD: device.manage_cards) — Admin không được vượt quá scope này dù có authorization_code hợp lệ.';

-- ---------------------------------------------------------------------
-- E2. NOTIFICATIONS
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS "public"."notifications" (
  "id"          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  "user_id"     uuid NOT NULL REFERENCES "public"."users"(id) ON DELETE CASCADE,
  "device_id"   uuid REFERENCES "public"."devices"(id) ON DELETE SET NULL,
  "type"        varchar(50) NOT NULL,
  "title"       varchar(150) NOT NULL,
  "message"     text NOT NULL,
  "severity"    varchar(20) NOT NULL DEFAULT 'info' CHECK (severity IN ('info','warning','critical')),
  "is_read"     boolean NOT NULL DEFAULT false,
  "created_at"  timestamptz NOT NULL DEFAULT now(),
  "read_at"     timestamptz
);
COMMENT ON COLUMN "public"."notifications"."type" IS 'Quy ước gợi ý: SECURITY_ALERT, UNLOCK_SUCCESS, UNLOCK_FAILED, TAMPER, LOW_BATTERY, DEVICE_OFFLINE, DEVICE_ONLINE, SHARE_REQUEST, SHARE_ACCEPTED, PERMISSION_GRANTED, PERMISSION_REVOKED, SUPPORT_REQUEST, DEVICE_RESET, SYSTEM_ALERT, PUSH_AUTH_REQUEST, ANNOUNCEMENT.';

-- ---------------------------------------------------------------------
-- E3. AUDIT_LOGS — nhật ký bảo mật DUY NHẤT, APPEND-ONLY
--     (dùng chung cho cả hoạt động của USER lẫn hành động của ADMIN —
--      thay thế cho ActivityLog + AdminAuditLog tách rời bên Django,
--      phân biệt bằng actor_user_id/target_user_id + action)
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS "public"."audit_logs" (
  "id"              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  "actor_user_id"   uuid REFERENCES "public"."users"(id) ON DELETE SET NULL,
  "target_user_id"  uuid REFERENCES "public"."users"(id) ON DELETE SET NULL,
  "device_id"       uuid REFERENCES "public"."devices"(id) ON DELETE SET NULL,
  "action"          varchar(50) NOT NULL,
  "username_attempt" varchar(150),
  "severity"        varchar(20) NOT NULL DEFAULT 'info' CHECK (severity IN ('info','warning','critical')),
  "success"         boolean NOT NULL DEFAULT true,
  "ip_address"      varchar(45),
  "user_agent"      text,
  "metadata"        jsonb,
  "created_at"      timestamptz NOT NULL DEFAULT now()
);
COMMENT ON TABLE "public"."audit_logs" IS
  'Quy ước action gợi ý — nhóm khoá cửa: REGISTER, LOGIN, LOGOUT, EMAIL_VERIFY, EMAIL_2FA_SUCCESS/FAILED, FIDO2_REGISTER/LOGIN, DEVICE_CLAIM, DEVICE_RESET, DEVICE_TRANSFER, CARD_REGISTER/ADD/REMOVE, SHARE_CREATE/ACCEPT/REJECT/REVOKE, PERMISSION_GRANT/REVOKE, SUPPORT_CREATE/AUTH/EXECUTE, RECOVERY_START/SUCCESS/FAILED, UNLOCK, LOCK, OTA_UPDATE. '
  'Nhóm 2FA/tài khoản (thay ActivityLog bên Django): LOGIN_FAILED, LOGIN_LOCKED_ATTEMPT, FORCE_LOGOUT, OTP_FAIL, OTP_SUCCESS, TWOFA_ENABLE, TWOFA_DISABLE, PUSH_AUTH_REQUEST, PUSH_AUTH_APPROVED, PUSH_AUTH_DENIED, BACKUP_CODE_USED, BACKUP_CODE_REGENERATED. '
  'Nhóm quản trị (thay AdminAuditLog bên Django): ACCOUNT_TOGGLE, ADMIN_FORCE_LOGOUT, ADMIN_FORCE_DISABLE_2FA, SYSTEM_SETTINGS_UPDATE, ANNOUNCEMENT_CREATE, ANNOUNCEMENT_DEACTIVATE. '
  'Bảng append-only, xem trigger fn_block_audit_mutation.';
COMMENT ON COLUMN "public"."audit_logs"."username_attempt" IS 'Lưu tên đăng nhập/email được thử khi actor_user_id chưa xác định được user thật (VD: login sai username) — tương ứng ActivityLog.username_attempt bên Django.';

-- =====================================================================
-- INDEXES
-- =====================================================================
CREATE INDEX IF NOT EXISTS idx_users_email                     ON "public"."users"(email);

CREATE INDEX IF NOT EXISTS idx_sessions_user_id                ON "public"."sessions"(user_id);
CREATE INDEX IF NOT EXISTS idx_webauthn_user_id                ON "public"."webauthn_credentials"(user_id);

CREATE INDEX IF NOT EXISTS idx_pending_reg_email               ON "public"."pending_registrations"(email);
CREATE INDEX IF NOT EXISTS idx_pending_reg_expiry               ON "public"."pending_registrations"(is_used, expires_at);

CREATE INDEX IF NOT EXISTS idx_otp_user_id                     ON "public"."email_otp_challenges"(user_id);
CREATE INDEX IF NOT EXISTS idx_otp_verify                      ON "public"."email_otp_challenges"(user_id, purpose, is_used, expires_at);

CREATE INDEX IF NOT EXISTS idx_totp_credentials_user_id        ON "public"."totp_credentials"(user_id);
CREATE INDEX IF NOT EXISTS idx_hotp_credentials_user_id        ON "public"."hotp_credentials"(user_id);
CREATE INDEX IF NOT EXISTS idx_account_backup_codes_user_id    ON "public"."account_backup_codes"(user_id, is_used);

CREATE INDEX IF NOT EXISTS idx_trusted_devices_user_active     ON "public"."trusted_login_devices"(user_id, is_active);
CREATE INDEX IF NOT EXISTS idx_trusted_devices_trusted         ON "public"."trusted_login_devices"(user_id, is_active, is_trusted);
CREATE INDEX IF NOT EXISTS idx_trusted_devices_session         ON "public"."trusted_login_devices"(session_key);

CREATE INDEX IF NOT EXISTS idx_remote_auth_session_exp         ON "public"."remote_auth_requests"(session_key, expires_at);
CREATE INDEX IF NOT EXISTS idx_remote_auth_target_status       ON "public"."remote_auth_requests"(target_device_id, status);

CREATE INDEX IF NOT EXISTS idx_login_otp_attempts_user         ON "public"."login_otp_attempts"(user_id, action, created_at);
CREATE INDEX IF NOT EXISTS idx_login_otp_attempts_ip           ON "public"."login_otp_attempts"(ip_address, action, created_at);

CREATE INDEX IF NOT EXISTS idx_announcements_active            ON "public"."announcements"(is_active, created_at);

CREATE INDEX IF NOT EXISTS idx_devices_owner_id                ON "public"."devices"(owner_id);
CREATE INDEX IF NOT EXISTS idx_devices_device_mode             ON "public"."devices"(device_mode);
CREATE INDEX IF NOT EXISTS idx_devices_status                  ON "public"."devices"(status);
CREATE INDEX IF NOT EXISTS idx_device_status_logs_device_id    ON "public"."device_status_logs"(device_id);
CREATE INDEX IF NOT EXISTS idx_device_commands_device_id       ON "public"."device_commands"(device_id);
CREATE INDEX IF NOT EXISTS idx_device_commands_status          ON "public"."device_commands"(status);

CREATE INDEX IF NOT EXISTS idx_device_access_device_id         ON "public"."device_access"(device_id);
CREATE INDEX IF NOT EXISTS idx_device_access_user_id           ON "public"."device_access"(user_id);
CREATE INDEX IF NOT EXISTS idx_device_access_active             ON "public"."device_access"(is_active, expires_at);

CREATE INDEX IF NOT EXISTS idx_access_cards_card_uid_hash      ON "public"."access_cards"(card_uid_hash);
CREATE INDEX IF NOT EXISTS idx_card_device_access_card_id      ON "public"."card_device_access"(access_card_id);
CREATE INDEX IF NOT EXISTS idx_card_device_access_device_id    ON "public"."card_device_access"(device_id);

CREATE INDEX IF NOT EXISTS idx_nfc_readers_device_id           ON "public"."nfc_readers"(device_id);
CREATE INDEX IF NOT EXISTS idx_nfc_readers_reader_mode         ON "public"."nfc_readers"(reader_mode);
CREATE INDEX IF NOT EXISTS idx_nfc_sessions_token              ON "public"."nfc_sessions"(session_token);
CREATE INDEX IF NOT EXISTS idx_nfc_sessions_reader_id          ON "public"."nfc_sessions"(reader_id);
CREATE INDEX IF NOT EXISTS idx_nfc_logs_device_id              ON "public"."nfc_logs"(device_id);
CREATE INDEX IF NOT EXISTS idx_nfc_logs_created_at             ON "public"."nfc_logs"(created_at);

CREATE INDEX IF NOT EXISTS idx_support_requests_device_id      ON "public"."support_requests"(device_id);
CREATE INDEX IF NOT EXISTS idx_support_requests_status         ON "public"."support_requests"(status);

CREATE INDEX IF NOT EXISTS idx_notifications_user_id           ON "public"."notifications"(user_id, is_read);
CREATE INDEX IF NOT EXISTS idx_audit_logs_actor_user_id        ON "public"."audit_logs"(actor_user_id);
CREATE INDEX IF NOT EXISTS idx_audit_logs_target_user_id       ON "public"."audit_logs"(target_user_id);
CREATE INDEX IF NOT EXISTS idx_audit_logs_device_id            ON "public"."audit_logs"(device_id);
CREATE INDEX IF NOT EXISTS idx_audit_logs_action_created       ON "public"."audit_logs"(action, created_at);
CREATE INDEX IF NOT EXISTS idx_audit_logs_created_at           ON "public"."audit_logs"(created_at);

-- =====================================================================
-- TRIGGER FUNCTIONS — hoá nghiệp vụ quan trọng ngay trong DB
-- =====================================================================

-- ---------------------------------------------------------------------
-- 1) Tự động cập nhật updated_at
-- ---------------------------------------------------------------------
CREATE OR REPLACE FUNCTION public.fn_set_updated_at()
RETURNS trigger AS $$
BEGIN
  NEW.updated_at = now();
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_users_updated_at ON "public"."users";
CREATE TRIGGER trg_users_updated_at
  BEFORE UPDATE ON "public"."users"
  FOR EACH ROW EXECUTE FUNCTION public.fn_set_updated_at();

DROP TRIGGER IF EXISTS trg_devices_updated_at ON "public"."devices";
CREATE TRIGGER trg_devices_updated_at
  BEFORE UPDATE ON "public"."devices"
  FOR EACH ROW EXECUTE FUNCTION public.fn_set_updated_at();

DROP TRIGGER IF EXISTS trg_nfc_readers_updated_at ON "public"."nfc_readers";
CREATE TRIGGER trg_nfc_readers_updated_at
  BEFORE UPDATE ON "public"."nfc_readers"
  FOR EACH ROW EXECUTE FUNCTION public.fn_set_updated_at();

DROP TRIGGER IF EXISTS trg_system_settings_updated_at ON "public"."system_settings";
CREATE TRIGGER trg_system_settings_updated_at
  BEFORE UPDATE ON "public"."system_settings"
  FOR EACH ROW EXECUTE FUNCTION public.fn_set_updated_at();

-- ---------------------------------------------------------------------
-- 2) Duy trì users.is_owner tự động theo devices.owner_id (không cho
--    client tự set is_owner)
-- ---------------------------------------------------------------------
CREATE OR REPLACE FUNCTION public.fn_maintain_is_owner()
RETURNS trigger AS $$
DECLARE
  v_old_owner uuid;
  v_new_owner uuid;
BEGIN
  IF TG_OP = 'DELETE' THEN
    v_old_owner := OLD.owner_id;
    v_new_owner := NULL;
  ELSIF TG_OP = 'UPDATE' THEN
    v_old_owner := OLD.owner_id;
    v_new_owner := NEW.owner_id;
  ELSE
    v_old_owner := NULL;
    v_new_owner := NEW.owner_id;
  END IF;

  IF v_old_owner IS NOT NULL AND v_old_owner IS DISTINCT FROM v_new_owner THEN
    UPDATE public.users
       SET is_owner = EXISTS (SELECT 1 FROM public.devices WHERE owner_id = v_old_owner)
     WHERE id = v_old_owner;
  END IF;

  IF v_new_owner IS NOT NULL THEN
    UPDATE public.users
       SET is_owner = TRUE
     WHERE id = v_new_owner AND is_owner = FALSE;
  END IF;

  RETURN NULL;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_devices_maintain_is_owner ON "public"."devices";
CREATE TRIGGER trg_devices_maintain_is_owner
  AFTER INSERT OR UPDATE OF owner_id OR DELETE ON "public"."devices"
  FOR EACH ROW EXECUTE FUNCTION public.fn_maintain_is_owner();

-- ---------------------------------------------------------------------
-- 3) audit_logs là bảng APPEND-ONLY: chặn UPDATE/DELETE ở tầng DB
-- ---------------------------------------------------------------------
CREATE OR REPLACE FUNCTION public.fn_block_audit_mutation()
RETURNS trigger AS $$
BEGIN
  RAISE EXCEPTION 'audit_logs là bảng append-only: không được UPDATE/DELETE bản ghi audit.';
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_audit_logs_block_update ON "public"."audit_logs";
CREATE TRIGGER trg_audit_logs_block_update
  BEFORE UPDATE ON "public"."audit_logs"
  FOR EACH ROW EXECUTE FUNCTION public.fn_block_audit_mutation();

DROP TRIGGER IF EXISTS trg_audit_logs_block_delete ON "public"."audit_logs";
CREATE TRIGGER trg_audit_logs_block_delete
  BEFORE DELETE ON "public"."audit_logs"
  FOR EACH ROW EXECUTE FUNCTION public.fn_block_audit_mutation();

-- ---------------------------------------------------------------------
-- 4) Thẻ NFC phải đang active mới được cấp (is_active=true) cho device
-- ---------------------------------------------------------------------
CREATE OR REPLACE FUNCTION public.fn_check_card_active()
RETURNS trigger AS $$
DECLARE
  v_status text;
BEGIN
  SELECT status INTO v_status FROM public.access_cards WHERE id = NEW.access_card_id;
  IF v_status IS NULL THEN
    RAISE EXCEPTION 'access_card % không tồn tại trong hệ thống.', NEW.access_card_id;
  ELSIF v_status <> 'active' THEN
    RAISE EXCEPTION 'access_card % đang ở trạng thái "%", không thể cấp quyền cho device.', NEW.access_card_id, v_status;
  END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_card_device_access_check_active ON "public"."card_device_access";
CREATE TRIGGER trg_card_device_access_check_active
  BEFORE INSERT OR UPDATE OF access_card_id, is_active ON "public"."card_device_access"
  FOR EACH ROW WHEN (NEW.is_active = TRUE)
  EXECUTE FUNCTION public.fn_check_card_active();

-- ---------------------------------------------------------------------
-- 5) auto_register trong nfc_reader_configs chỉ hợp lệ với reader type=master
-- ---------------------------------------------------------------------
CREATE OR REPLACE FUNCTION public.fn_check_reader_config_master()
RETURNS trigger AS $$
DECLARE
  v_type text;
BEGIN
  IF NEW.auto_register = TRUE THEN
    SELECT type INTO v_type FROM public.nfc_readers WHERE id = NEW.reader_id;
    IF v_type IS DISTINCT FROM 'master' THEN
      RAISE EXCEPTION 'auto_register chỉ được bật cho nfc_readers.type = master (reader_id=%).', NEW.reader_id;
    END IF;
  END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_nfc_reader_configs_check_master ON "public"."nfc_reader_configs";
CREATE TRIGGER trg_nfc_reader_configs_check_master
  BEFORE INSERT OR UPDATE ON "public"."nfc_reader_configs"
  FOR EACH ROW EXECUTE FUNCTION public.fn_check_reader_config_master();

-- ---------------------------------------------------------------------
-- 6) remote_auth_requests.expires_at tự set = created_at + 120 giây
--    (đủ để user mở app, đọc và bấm xác nhận) nếu không truyền sẵn
-- ---------------------------------------------------------------------
CREATE OR REPLACE FUNCTION public.fn_set_remote_auth_expiry()
RETURNS trigger AS $$
BEGIN
  IF NEW.expires_at IS NULL THEN
    NEW.expires_at := now() + interval '120 seconds';
  END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_remote_auth_set_expiry ON "public"."remote_auth_requests";
CREATE TRIGGER trg_remote_auth_set_expiry
  BEFORE INSERT ON "public"."remote_auth_requests"
  FOR EACH ROW EXECUTE FUNCTION public.fn_set_remote_auth_expiry();

-- ---------------------------------------------------------------------
-- 7) target_device_id trong remote_auth_requests phải là thiết bị
--    is_trusted = true và thuộc đúng user_id của request
-- ---------------------------------------------------------------------
CREATE OR REPLACE FUNCTION public.fn_check_target_device_trusted()
RETURNS trigger AS $$
DECLARE
  v_owner uuid;
  v_trusted boolean;
BEGIN
  SELECT user_id, is_trusted INTO v_owner, v_trusted
    FROM public.trusted_login_devices
   WHERE id = NEW.target_device_id;

  IF v_owner IS NULL THEN
    RAISE EXCEPTION 'trusted_login_devices % không tồn tại.', NEW.target_device_id;
  ELSIF v_owner <> NEW.user_id THEN
    RAISE EXCEPTION 'Thiết bị % không thuộc user %.', NEW.target_device_id, NEW.user_id;
  ELSIF v_trusted IS DISTINCT FROM TRUE THEN
    RAISE EXCEPTION 'Thiết bị % chưa được đánh dấu is_trusted, không thể nhận push-auth.', NEW.target_device_id;
  END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_remote_auth_check_target ON "public"."remote_auth_requests";
CREATE TRIGGER trg_remote_auth_check_target
  BEFORE INSERT OR UPDATE OF target_device_id ON "public"."remote_auth_requests"
  FOR EACH ROW WHEN (NEW.target_device_id IS NOT NULL)
  EXECUTE FUNCTION public.fn_check_target_device_trusted();

-- =====================================================================
-- ROW LEVEL SECURITY — mặc định KHOÁ TOÀN BỘ với anon/authenticated.
-- Backend dùng service_role key (tự động BYPASS RLS trên Supabase) để
-- thao tác; không policy nào được cấp cho client truy cập trực tiếp.
-- => đúng nguyên tắc "row-level authorization ở BACKEND"
-- =====================================================================
ALTER TABLE "public"."users"                  ENABLE ROW LEVEL SECURITY;
ALTER TABLE "public"."sessions"               ENABLE ROW LEVEL SECURITY;
ALTER TABLE "public"."webauthn_credentials"   ENABLE ROW LEVEL SECURITY;
ALTER TABLE "public"."pending_registrations"  ENABLE ROW LEVEL SECURITY;
ALTER TABLE "public"."email_otp_challenges"   ENABLE ROW LEVEL SECURITY;
ALTER TABLE "public"."totp_credentials"       ENABLE ROW LEVEL SECURITY;
ALTER TABLE "public"."hotp_credentials"       ENABLE ROW LEVEL SECURITY;
ALTER TABLE "public"."account_backup_codes"   ENABLE ROW LEVEL SECURITY;
ALTER TABLE "public"."trusted_login_devices"  ENABLE ROW LEVEL SECURITY;
ALTER TABLE "public"."remote_auth_requests"   ENABLE ROW LEVEL SECURITY;
ALTER TABLE "public"."login_otp_attempts"     ENABLE ROW LEVEL SECURITY;
ALTER TABLE "public"."system_settings"        ENABLE ROW LEVEL SECURITY;
ALTER TABLE "public"."announcements"          ENABLE ROW LEVEL SECURITY;
ALTER TABLE "public"."devices"                ENABLE ROW LEVEL SECURITY;
ALTER TABLE "public"."device_status_logs"     ENABLE ROW LEVEL SECURITY;
ALTER TABLE "public"."device_commands"        ENABLE ROW LEVEL SECURITY;
ALTER TABLE "public"."permissions"            ENABLE ROW LEVEL SECURITY;
ALTER TABLE "public"."device_access"          ENABLE ROW LEVEL SECURITY;
ALTER TABLE "public"."access_cards"           ENABLE ROW LEVEL SECURITY;
ALTER TABLE "public"."card_device_access"     ENABLE ROW LEVEL SECURITY;
ALTER TABLE "public"."nfc_readers"            ENABLE ROW LEVEL SECURITY;
ALTER TABLE "public"."nfc_reader_configs"     ENABLE ROW LEVEL SECURITY;
ALTER TABLE "public"."nfc_sessions"           ENABLE ROW LEVEL SECURITY;
ALTER TABLE "public"."nfc_logs"               ENABLE ROW LEVEL SECURITY;
ALTER TABLE "public"."support_requests"       ENABLE ROW LEVEL SECURITY;
ALTER TABLE "public"."notifications"          ENABLE ROW LEVEL SECURITY;
ALTER TABLE "public"."audit_logs"             ENABLE ROW LEVEL SECURITY;

-- Khởi tạo dòng cấu hình singleton mặc định (nếu chưa có)
INSERT INTO "public"."system_settings" (id) VALUES (1) ON CONFLICT (id) DO NOTHING;

-- =====================================================================
-- NOTE: security best practices WITHIN DB (không phải hướng dẫn triển khai backend)
-- =====================================================================
-- 1. Admin đầu tiên: INSERT vào users với is_admin = TRUE, password_hash
--    là Argon2id hash được tạo ở backend (KHÔNG insert password plaintext
--    qua SQL Editor của Supabase).
-- 2. Mỗi lần claim device mới: backend phải (a) verify device_code tồn
--    tại + status = 'provisioning', (b) verify provisioning_secret_hash
--    khớp secret người dùng nhập/scan, (c) trong 1 transaction: set
--    owner_id, set status phù hợp (online/offline) — trigger sẽ tự cập
--    nhật is_owner cho user.
-- 3. Sinh mã ngẫu nhiên (share_code/authorization_code/recovery_code/
--    otp_code/provisioning_secret/backup_code) và hash đều thực hiện ở
--    backend bằng CSPRNG + Argon2id/SHA-256, DB chỉ lưu hash.
-- 4. RIÊNG totp_credentials.secret_encrypted và hotp_credentials.secret_encrypted:
--    đây là bí mật đối xứng, KHÔNG hash mà MÃ HOÁ (Fernet/AES-256-GCM) bằng
--    khoá lưu ở biến môi trường/KMS (không lưu khoá mã hoá trong DB). Đây là
--    2 ngoại lệ duy nhất so với nguyên tắc "chỉ lưu hash" vì bản chất TOTP/HOTP
--    cần round-trip (backend phải tự tính lại mã để so khớp).
-- 5. account_backup_codes dùng CHUNG cho mọi phương thức 2FA của tài khoản
--    (không tách riêng theo TOTP/HOTP/Email) — mỗi lần (tái) sinh mã, xoá
--    hết mã cũ trước khi tạo 8 mã mới, chỉ hiện plaintext đúng 1 lần.
-- 6. Push-auth (remote_auth_requests) CHỈ gửi tới đúng 1 target_device_id
--    đã is_trusted=true (ép buộc bởi trigger fn_check_target_device_trusted),
--    tuyệt đối không broadcast yêu cầu xác nhận cho mọi thiết bị của user.
-- 7. login_otp_attempts / pending_registrations / remote_auth_requests /
--    email_otp_challenges đã hết hạn nên được dọn định kỳ bằng Supabase
--    Scheduled Function hoặc pg_cron — KHÔNG dọn ngay trong luồng request
--    của user để tránh tăng độ trễ.
-- 8. audit_logs là bảng NHẬT KÝ AN NINH DUY NHẤT của toàn hệ thống (gộp cả
--    hoạt động user lẫn hành động admin) — mọi service chỉ INSERT, không
--    bao giờ UPDATE/DELETE (được ép buộc cứng bằng trigger ở tầng DB).