"""
MIGRATION GỘP BẢNG: 21 bảng -> 13 bảng (DỮ LIỆU CŨ ĐƯỢC CHÉP SANG, không mất dòng nào).

CÁCH DÙNG (làm theo đúng thứ tự):
  1. BACKUP DB trước (pg_dump). Nên chạy thử trên bản sao/staging trước khi chạy thật.
  2. Đổi tên file này thành số kế tiếp trong smartlock/migrations/, vd. 0021_merge_tables.py
     và SỬA hằng LAST_MIGRATION bên dưới = tên migration mới nhất hiện có (không có đuôi .py).
  3. Thay smartlock/models.py bằng models.py mới.
  4. python manage.py migrate smartlock
  5. python manage.py makemigrations --check --dry-run
     -> nếu in ra "No changes detected" là khớp hoàn toàn. Nếu còn vài AlterField chỉ về choices/help_text
        thì chạy makemigrations bình thường để sinh thêm 1 file nhỏ (không đụng dữ liệu).

THỨ TỰ BÊN TRONG (atomic=False để tránh lỗi "pending trigger events" của Postgres khi vừa chép dữ liệu vừa đổi FK):
  A. Tạo 3 bảng mới (ActivityLog, AccessCredential, SecurityRecord)
  B. Chép dữ liệu từ 11 bảng cũ sang (giữ NGUYÊN id nên mọi FK cũ vẫn đúng) - bỏ qua loại đã chép (chạy lại được)
  C. Đổi CardDeviceAccess.access_card sang trỏ AccessCredential
  D. Xoá 11 bảng cũ
  E. Tạo 11 PROXY cùng tên cũ (không có bảng, chỉ là state của Django)
Migration KHÔNG đảo ngược được (khôi phục = restore backup).
"""
import uuid

import django.core.validators
import django.db.models.deletion
from django.db import migrations, models


LAST_MIGRATION = '0012_remove_systemsettings_ip_blacklist'

SET_NULL = django.db.models.deletion.SET_NULL
CASCADE = django.db.models.deletion.CASCADE
RESTRICT = django.db.models.deletion.RESTRICT

TRUE, FALSE = '(1=1)', '(1=0)'          # literal boolean chạy được cả Postgres lẫn SQLite


# ---------------------------------------------------------------------------------------- B. CHÉP DỮ LIỆU
def _specs(vendor):
    json_empty = "'[]'::jsonb" if vendor == 'postgresql' else "'[]'"

    activity_defaults = {'success': TRUE, 'severity': "'info'", 'action': "''", 'event_type': "''",
                         'method': "''", 'lock_state': "''", 'tamper_detected': FALSE}
    cred_defaults = {'max_uses': '1', 'use_count': '0', 'is_revoked': FALSE, 'threshold': '0.6',
                     'consent_confirmed': FALSE, 'is_active': TRUE}
    sec_defaults = {'purpose': "''", 'token_hash': "''", 'attempts': '0', 'is_used': FALSE,
                    'prev_refresh_hash': "''", 'device_name': "''", 'platform': "''", 'app_version': "''",
                    'fcm_token': "''", 'push_enabled': TRUE, 'sign_count': '0', 'transports': json_empty,
                    'name': "''", 'totp_secret_encrypted': "''", 'totp_confirmed': FALSE, 'totp_last_step': '0',
                    'email_otp_enabled': FALSE, 'preferred_method': "''"}

    def same(*cols):
        return {c: c for c in cols}

    # (bảng_nguồn, bảng_đích, kind, {cột_đích: biểu_thức_nguồn}, {cột_đích_NOT_NULL: mặc định})
    return [
        # ---- ActivityLog ----
        ('smartlock_auditlog', 'smartlock_activitylog', 'AUDIT',
         same('id', 'actor_user_id', 'target_user_id', 'device_id', 'action', 'username_attempt', 'severity',
              'success', 'ip_address', 'user_agent', 'metadata', 'created_at'), activity_defaults),
        ('smartlock_nfclog', 'smartlock_activitylog', 'NFC',
         same('id', 'reader_id', 'nfc_tag_id', 'device_id', 'user_id', 'event_type', 'success', 'ip_address',
              'user_agent', 'metadata', 'created_at'), activity_defaults),
        ('smartlock_accessevent', 'smartlock_activitylog', 'ACCESS',
         same('id', 'device_id', 'method', 'success', 'reason', 'user_id', 'access_card_id', 'door_pin_id',
              'face_profile_id', 'confidence', 'snapshot_url', 'ip_address', 'created_at'), activity_defaults),
        ('smartlock_devicestatuslog', 'smartlock_activitylog', 'STATUS',
         {**same('id', 'device_id', 'battery_level', 'signal_strength', 'lock_state', 'tamper_detected',
                 'temperature', 'raw_payload', 'recorded_at'), 'created_at': 'recorded_at'}, activity_defaults),
        # ---- AccessCredential ----
        ('smartlock_accesscard', 'smartlock_accesscredential', 'CARD',
         same('id', 'user_id', 'name', 'card_uid_hash', 'is_active', 'created_at', 'updated_at'), cred_defaults),
        ('smartlock_doorpincode', 'smartlock_accesscredential', 'PIN',
         {**same('id', 'device_id', 'created_by_id', 'label', 'pin_hash', 'valid_from', 'expires_at', 'max_uses',
                 'use_count', 'is_revoked', 'revoked_at', 'created_at'), 'updated_at': 'created_at'},
         {k: v for k, v in cred_defaults.items() if k in ('threshold', 'consent_confirmed', 'is_active')}),
        ('smartlock_faceprofile', 'smartlock_accesscredential', 'FACE',
         same('id', 'user_id', 'device_id', 'name', 'embedding_encrypted', 'threshold', 'consent_confirmed',
              'is_active', 'created_at', 'updated_at'),
         {k: v for k, v in cred_defaults.items() if k in ('max_uses', 'use_count', 'is_revoked')}),
        # ---- SecurityRecord ----
        ('smartlock_onetimecode', 'smartlock_securityrecord', 'OTP',
         {**same('id', 'user_id', 'purpose', 'token_hash', 'attempts', 'is_used', 'used_at', 'expires_at',
                 'created_at'), 'updated_at': 'created_at'}, sec_defaults),
        ('smartlock_mobilesession', 'smartlock_securityrecord', 'SESSION',
         {**same('id', 'user_id', 'refresh_hash', 'prev_refresh_hash', 'device_name', 'platform', 'app_version',
                 'fcm_token', 'push_enabled', 'ip_address', 'created_at', 'last_used_at', 'expires_at',
                 'revoked_at'), 'updated_at': 'created_at'}, sec_defaults),
        ('smartlock_fido2credential', 'smartlock_securityrecord', 'PASSKEY',
         {**same('id', 'user_id', 'credential_id', 'public_key', 'sign_count', 'transports', 'name', 'created_at',
                 'last_used_at'), 'updated_at': 'created_at'}, sec_defaults),
        ('smartlock_twofactorconfig', 'smartlock_securityrecord', 'TFCONFIG',
         same('id', 'user_id', 'totp_secret_encrypted', 'totp_confirmed', 'totp_last_step', 'email_otp_enabled',
              'preferred_method', 'enabled_at', 'created_at', 'updated_at'), sec_defaults),
    ]


def copy_data(apps, schema_editor):
    conn = schema_editor.connection
    q = conn.ops.quote_name
    existing = set(conn.introspection.table_names())
    with conn.cursor() as cur:
        for src, dst, kind, mapping, defaults in _specs(conn.vendor):
            if src not in existing:
                continue
            cur.execute(f'SELECT 1 FROM {q(dst)} WHERE kind = %s LIMIT 1', [kind])
            if cur.fetchone():
                continue                                    # loại này đã chép rồi -> bỏ qua (chạy lại an toàn)
            cols = ['kind'] + list(mapping) + [c for c in defaults if c not in mapping]
            exprs = ["%s"] + [q(v) for v in mapping.values()] + [v for c, v in defaults.items() if c not in mapping]
            cur.execute(f'INSERT INTO {q(dst)} ({", ".join(q(c) for c in cols)}) '
                        f'SELECT {", ".join(exprs)} FROM {q(src)}', [kind])


# ---------------------------------------------------------------------------------------- A/C/D/E. STATE + SCHEMA
SEVERITY = [('info', 'Info'), ('warning', 'Warning'), ('critical', 'Critical')]
LOCK_STATE = [('locked', 'Locked'), ('unlocked', 'Unlocked'), ('jammed', 'Jam'), ('unknown', 'Unknown')]
NFC_EVENT = [('TAP_SUCCESS', 'Tap Success'), ('TAP_FAILED', 'Tap Failed'), ('CARD_REGISTER', 'Card Register'),
             ('READER_CONNECTED', 'Reader Connected'), ('READER_DISCONNECTED', 'Reader Disconnected'),
             ('CONFIG_UPDATED', 'Config Updated'), ('SESSION_TIMEOUT', 'Session Timeout')]
METHODS = [('RFID', 'Thẻ RFID'), ('PIN', 'Mã PIN'), ('FACE', 'Khuôn mặt'), ('BLE', 'Bluetooth'),
           ('NFC_PHONE', 'NFC trên điện thoại')]
OTP_PURPOSE = [('EMAIL_VERIFY', 'Verify email'), ('PASSWORD_RESET', 'Password reset'),
               ('SUPPORT_AUTH', 'Support auth'), ('RECOVERY_CONFIRM', 'Recovery confirm'),
               ('UPDATE_INFO', 'Update info'), ('TF_SETUP', '2FA email - thiết lập'),
               ('TF_VERIFY', '2FA email - xác thực')]
TWO_FA = [('totp', 'Google Authenticator (TOTP)'), ('fido2', 'Passkey / FIDO2'), ('email', 'Email OTP')]

Q = models.Q
F = models.F


def _pk():
    return ('id', models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False))


def _fk(name, to, on_delete, related_name, null=True):
    kw = dict(blank=null, null=null, on_delete=on_delete, related_name=related_name, to=to)
    return (name, models.ForeignKey(**kw))


class Migration(migrations.Migration):
    atomic = False
    dependencies = [('smartlock', LAST_MIGRATION)]

    operations = [
        # ============================ A. 3 BẢNG MỚI ============================
        migrations.CreateModel(
            name='ActivityLog',
            fields=[
                _pk(),
                ('kind', models.CharField(choices=[('AUDIT', 'Audit log'), ('NFC', 'NFC log'),
                                                    ('ACCESS', 'Access event'), ('STATUS', 'Device status log')],
                                          max_length=10)),
                _fk('device', 'smartlock.device', SET_NULL, 'activity_logs'),
                _fk('user', 'smartlock.user', SET_NULL, 'activity_logs'),
                ('success', models.BooleanField(default=True)),
                ('severity', models.CharField(choices=SEVERITY, default='info', max_length=20)),
                ('ip_address', models.GenericIPAddressField(blank=True, null=True)),
                ('user_agent', models.TextField(blank=True, null=True)),
                ('metadata', models.JSONField(blank=True, null=True)),
                _fk('actor_user', 'smartlock.user', SET_NULL, 'audit_logs_actor'),
                _fk('target_user', 'smartlock.user', SET_NULL, 'audit_logs_target'),
                ('action', models.CharField(blank=True, default='', max_length=50)),
                ('username_attempt', models.CharField(blank=True, max_length=150, null=True)),
                _fk('reader', 'smartlock.nfcreader', SET_NULL, 'activity_logs'),
                ('event_type', models.CharField(blank=True, choices=NFC_EVENT, default='', max_length=50)),
                ('method', models.CharField(blank=True, choices=METHODS, default='', max_length=10)),
                ('reason', models.CharField(blank=True, help_text='Lý do thất bại, nếu có.', max_length=100, null=True)),
                ('confidence', models.FloatField(blank=True, help_text='Độ tin cậy nhận diện khuôn mặt (nếu có).', null=True)),
                ('snapshot_url', models.URLField(blank=True, help_text='Ảnh chụp lúc mở cửa, lưu ở object storage (MinIO/S3), khuyến nghị giữ tối đa 30 ngày.', max_length=512, null=True)),
                ('battery_level', models.IntegerField(blank=True, null=True, validators=[django.core.validators.MinValueValidator(0), django.core.validators.MaxValueValidator(100)])),
                ('signal_strength', models.IntegerField(blank=True, null=True)),
                ('lock_state', models.CharField(blank=True, choices=LOCK_STATE, default='', max_length=20)),
                ('tamper_detected', models.BooleanField(default=False)),
                ('temperature', models.DecimalField(blank=True, decimal_places=1, max_digits=4, null=True)),
                ('raw_payload', models.JSONField(blank=True, null=True)),
                ('recorded_at', models.DateTimeField(blank=True, null=True)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
            ],
            options={'abstract': False},
        ),
        migrations.CreateModel(
            name='AccessCredential',
            fields=[
                _pk(),
                ('kind', models.CharField(choices=[('CARD', 'Thẻ RFID'), ('PIN', 'Mã PIN'), ('FACE', 'Khuôn mặt')], max_length=10)),
                _fk('user', 'smartlock.user', CASCADE, '+'),
                _fk('created_by', 'smartlock.user', RESTRICT, '+'),
                _fk('device', 'smartlock.device', CASCADE, '+'),
                ('name', models.CharField(blank=True, max_length=100, null=True)),
                ('label', models.CharField(blank=True, help_text='VD: "Khách Booking #123"', max_length=100, null=True)),
                ('card_uid_hash', models.CharField(blank=True, max_length=255, null=True)),
                ('pin_hash', models.CharField(blank=True, max_length=255, null=True)),
                ('embedding_encrypted', models.BinaryField(blank=True, help_text='Vector đặc trưng khuôn mặt (vd. 128 chiều), đã mã hoá Fernet.', null=True)),
                ('valid_from', models.DateTimeField(blank=True, null=True)),
                ('expires_at', models.DateTimeField(blank=True, null=True)),
                ('max_uses', models.IntegerField(default=1)),
                ('use_count', models.IntegerField(default=0)),
                ('is_revoked', models.BooleanField(default=False)),
                ('revoked_at', models.DateTimeField(blank=True, null=True)),
                ('threshold', models.FloatField(default=0.6)),
                ('consent_confirmed', models.BooleanField(default=False, help_text='Xác nhận người này đã đồng ý được thu thập dữ liệu khuôn mặt (bắt buộc theo NĐ 13/2023).')),
                ('is_active', models.BooleanField(default=True)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
            ],
            options={'abstract': False},
        ),
        migrations.CreateModel(
            name='SecurityRecord',
            fields=[
                _pk(),
                ('kind', models.CharField(choices=[('OTP', 'One-time code'), ('SESSION', 'Mobile session'), ('PASSKEY', 'Passkey / FIDO2'), ('TFCONFIG', '2FA config')], max_length=10)),
                ('user', models.ForeignKey(on_delete=CASCADE, related_name='+', to='smartlock.user')),
                ('purpose', models.CharField(blank=True, choices=OTP_PURPOSE, default='', max_length=50)),
                ('token_hash', models.CharField(blank=True, default='', max_length=255)),
                ('attempts', models.IntegerField(default=0)),
                ('is_used', models.BooleanField(default=False)),
                ('used_at', models.DateTimeField(blank=True, null=True)),
                ('refresh_hash', models.CharField(blank=True, max_length=64, null=True)),
                ('prev_refresh_hash', models.CharField(blank=True, default='', max_length=64)),
                ('device_name', models.CharField(blank=True, default='', max_length=100)),
                ('platform', models.CharField(blank=True, default='', max_length=20)),
                ('app_version', models.CharField(blank=True, default='', max_length=30)),
                ('fcm_token', models.CharField(blank=True, default='', max_length=512)),
                ('push_enabled', models.BooleanField(default=True)),
                ('ip_address', models.GenericIPAddressField(blank=True, null=True)),
                ('revoked_at', models.DateTimeField(blank=True, null=True)),
                ('credential_id', models.CharField(blank=True, max_length=512, null=True)),
                ('public_key', models.BinaryField(blank=True, null=True)),
                ('sign_count', models.BigIntegerField(default=0)),
                ('transports', models.JSONField(blank=True, default=list)),
                ('name', models.CharField(blank=True, default='', max_length=100)),
                ('totp_secret_encrypted', models.CharField(blank=True, default='', max_length=255)),
                ('totp_confirmed', models.BooleanField(default=False)),
                ('totp_last_step', models.BigIntegerField(default=0)),
                ('email_otp_enabled', models.BooleanField(default=False)),
                ('preferred_method', models.CharField(blank=True, choices=TWO_FA, default='', max_length=10)),
                ('enabled_at', models.DateTimeField(blank=True, null=True)),
                ('expires_at', models.DateTimeField(blank=True, null=True)),
                ('last_used_at', models.DateTimeField(blank=True, null=True)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
            ],
            options={'abstract': False},
        ),
        # FK từ ActivityLog sang AccessCredential (tạo sau vì AccessCredential phải tồn tại trước)
        migrations.AddField('activitylog', 'nfc_tag', models.ForeignKey(blank=True, null=True, on_delete=SET_NULL, related_name='nfc_logs', to='smartlock.accesscredential')),
        migrations.AddField('activitylog', 'access_card', models.ForeignKey(blank=True, null=True, on_delete=SET_NULL, related_name='access_events_as_card', to='smartlock.accesscredential')),
        migrations.AddField('activitylog', 'door_pin', models.ForeignKey(blank=True, null=True, on_delete=SET_NULL, related_name='access_events_as_pin', to='smartlock.accesscredential')),
        migrations.AddField('activitylog', 'face_profile', models.ForeignKey(blank=True, null=True, on_delete=SET_NULL, related_name='access_events_as_face', to='smartlock.accesscredential')),

        # ---- Index + Constraint ----
        migrations.AddIndex('activitylog', models.Index(fields=['kind', 'created_at'], name='idx_actlog_kind_time')),
        migrations.AddIndex('activitylog', models.Index(fields=['device', 'kind', 'created_at'], name='idx_actlog_dev_kind_time')),
        migrations.AddIndex('activitylog', models.Index(fields=['actor_user', 'created_at'], name='idx_actlog_actor_time')),
        migrations.AddIndex('activitylog', models.Index(fields=['user', 'created_at'], name='idx_actlog_user_time')),
        migrations.AddIndex('activitylog', models.Index(fields=['device', 'method', 'success', 'created_at'], name='idx_actlog_method_ok')),
        migrations.AddIndex('activitylog', models.Index(fields=['device', 'recorded_at'], name='idx_actlog_dev_rec')),
        migrations.AddConstraint('activitylog', models.CheckConstraint(check=Q(kind__in=['AUDIT', 'NFC', 'ACCESS', 'STATUS']), name='chk_actlog_kind')),
        migrations.AddConstraint('activitylog', models.CheckConstraint(check=Q(battery_level__isnull=True) | Q(battery_level__gte=0, battery_level__lte=100), name='chk_actlog_battery_range')),
        migrations.AddConstraint('activitylog', models.CheckConstraint(check=~Q(kind='STATUS') | (Q(battery_level__isnull=False) & ~Q(lock_state='')), name='chk_actlog_status_required')),
        migrations.AddConstraint('activitylog', models.CheckConstraint(check=~Q(kind='ACCESS') | ~Q(method=''), name='chk_actlog_access_method')),

        migrations.AddIndex('accesscredential', models.Index(fields=['kind', 'user'], name='idx_cred_kind_user')),
        migrations.AddIndex('accesscredential', models.Index(fields=['kind', 'device'], name='idx_cred_kind_device')),
        migrations.AddIndex('accesscredential', models.Index(fields=['device', 'expires_at'], name='idx_cred_dev_exp')),
        migrations.AddConstraint('accesscredential', models.CheckConstraint(check=Q(kind__in=['CARD', 'PIN', 'FACE']), name='chk_cred_kind')),
        migrations.AddConstraint('accesscredential', models.UniqueConstraint(fields=['card_uid_hash'], condition=Q(kind='CARD'), name='uniq_cred_card_uid')),
        migrations.AddConstraint('accesscredential', models.CheckConstraint(check=~Q(kind='CARD') | (Q(card_uid_hash__isnull=False) & Q(user__isnull=False)), name='chk_cred_card_required')),
        migrations.AddConstraint('accesscredential', models.CheckConstraint(check=~Q(kind='PIN') | Q(max_uses__gte=0, use_count__gte=0), name='chk_cred_pin_uses_nonneg')),
        migrations.AddConstraint('accesscredential', models.CheckConstraint(check=~Q(kind='PIN') | (Q(expires_at__isnull=False) & Q(expires_at__gt=F('valid_from'))), name='chk_cred_pin_expiry')),
        migrations.AddConstraint('accesscredential', models.CheckConstraint(check=~Q(kind='PIN') | Q(is_revoked=False) | Q(revoked_at__isnull=False), name='chk_cred_pin_revoked_date')),
        migrations.AddConstraint('accesscredential', models.CheckConstraint(check=~Q(kind='PIN') | (Q(pin_hash__isnull=False) & Q(device__isnull=False) & Q(created_by__isnull=False)), name='chk_cred_pin_required')),
        migrations.AddConstraint('accesscredential', models.UniqueConstraint(fields=['user', 'device'], condition=Q(kind='FACE'), name='uniq_cred_face_user_device')),
        migrations.AddConstraint('accesscredential', models.CheckConstraint(check=~Q(kind='FACE') | Q(threshold__gt=0, threshold__lte=2), name='chk_cred_face_threshold')),
        migrations.AddConstraint('accesscredential', models.CheckConstraint(check=~Q(kind='FACE') | Q(is_active=False) | Q(consent_confirmed=True), name='chk_cred_face_active_consent')),
        migrations.AddConstraint('accesscredential', models.CheckConstraint(check=~Q(kind='FACE') | (Q(user__isnull=False) & Q(device__isnull=False)), name='chk_cred_face_required')),

        migrations.AddIndex('securityrecord', models.Index(fields=['user', 'kind', 'purpose', 'created_at'], name='idx_secrec_user_purpose')),
        migrations.AddIndex('securityrecord', models.Index(fields=['user', 'kind', 'revoked_at'], name='idx_secrec_user_rev')),
        migrations.AddIndex('securityrecord', models.Index(fields=['prev_refresh_hash'], condition=Q(kind='SESSION'), name='idx_secrec_prev_refresh')),
        migrations.AddIndex('securityrecord', models.Index(fields=['fcm_token'], condition=Q(kind='SESSION'), name='idx_secrec_fcm')),
        migrations.AddConstraint('securityrecord', models.CheckConstraint(check=Q(kind__in=['OTP', 'SESSION', 'PASSKEY', 'TFCONFIG']), name='chk_secrec_kind')),
        migrations.AddConstraint('securityrecord', models.CheckConstraint(check=~Q(kind='OTP') | Q(attempts__gte=0), name='chk_secrec_otp_attempts')),
        migrations.AddConstraint('securityrecord', models.CheckConstraint(check=~Q(kind='OTP') | Q(used_at__isnull=True) | Q(is_used=True), name='chk_secrec_otp_usedat')),
        migrations.AddConstraint('securityrecord', models.CheckConstraint(check=~Q(kind='OTP') | (~Q(purpose='') & Q(expires_at__isnull=False)), name='chk_secrec_otp_required')),
        migrations.AddConstraint('securityrecord', models.UniqueConstraint(fields=['refresh_hash'], condition=Q(kind='SESSION'), name='uniq_secrec_refresh_hash')),
        migrations.AddConstraint('securityrecord', models.CheckConstraint(check=~Q(kind='SESSION') | (Q(refresh_hash__isnull=False) & Q(expires_at__gt=F('created_at'))), name='chk_secrec_session')),
        migrations.AddConstraint('securityrecord', models.UniqueConstraint(fields=['credential_id'], condition=Q(kind='PASSKEY'), name='uniq_secrec_credential_id')),
        migrations.AddConstraint('securityrecord', models.CheckConstraint(check=~Q(kind='PASSKEY') | (Q(credential_id__isnull=False) & Q(public_key__isnull=False)), name='chk_secrec_passkey')),
        migrations.AddConstraint('securityrecord', models.UniqueConstraint(fields=['user'], condition=Q(kind='TFCONFIG'), name='uniq_secrec_tfconfig_user')),

        # ============================ B. CHÉP DỮ LIỆU ============================
        migrations.RunPython(copy_data, migrations.RunPython.noop, elidable=False),

        # ============================ C. ĐỔI FK CardDeviceAccess ============================
        migrations.AlterField('carddeviceaccess', 'access_card',
                              models.ForeignKey(on_delete=CASCADE, to='smartlock.accesscredential')),

        # ============================ D. XOÁ 11 BẢNG CŨ (thứ tự theo phụ thuộc FK) ============================
        migrations.DeleteModel('NfcLog'),
        migrations.DeleteModel('AccessEvent'),
        migrations.DeleteModel('AuditLog'),
        migrations.DeleteModel('DeviceStatusLog'),
        migrations.DeleteModel('DoorPinCode'),
        migrations.DeleteModel('FaceProfile'),
        migrations.DeleteModel('AccessCard'),
        migrations.DeleteModel('OneTimeCode'),
        migrations.DeleteModel('MobileSession'),
        migrations.DeleteModel('Fido2Credential'),
        migrations.DeleteModel('TwoFactorConfig'),

        # ============================ E. 11 PROXY (tên cũ, không có bảng) ============================
        migrations.CreateModel('AuditLog', [], options={'proxy': True, 'indexes': [], 'constraints': []}, bases=('smartlock.activitylog',)),
        migrations.CreateModel('NfcLog', [], options={'proxy': True, 'indexes': [], 'constraints': []}, bases=('smartlock.activitylog',)),
        migrations.CreateModel('AccessEvent', [], options={'proxy': True, 'indexes': [], 'constraints': []}, bases=('smartlock.activitylog',)),
        migrations.CreateModel('DeviceStatusLog', [], options={'proxy': True, 'indexes': [], 'constraints': []}, bases=('smartlock.activitylog',)),
        migrations.CreateModel('AccessCard', [], options={'proxy': True, 'indexes': [], 'constraints': []}, bases=('smartlock.accesscredential',)),
        migrations.CreateModel('DoorPinCode', [], options={'proxy': True, 'indexes': [], 'constraints': []}, bases=('smartlock.accesscredential',)),
        migrations.CreateModel('FaceProfile', [], options={'proxy': True, 'indexes': [], 'constraints': []}, bases=('smartlock.accesscredential',)),
        migrations.CreateModel('OneTimeCode', [], options={'proxy': True, 'indexes': [], 'constraints': []}, bases=('smartlock.securityrecord',)),
        migrations.CreateModel('MobileSession', [], options={'proxy': True, 'ordering': ['-created_at'], 'indexes': [], 'constraints': []}, bases=('smartlock.securityrecord',)),
        migrations.CreateModel('Fido2Credential', [], options={'proxy': True, 'indexes': [], 'constraints': []}, bases=('smartlock.securityrecord',)),
        migrations.CreateModel('TwoFactorConfig', [], options={'proxy': True, 'indexes': [], 'constraints': []}, bases=('smartlock.securityrecord',)),
    ]
