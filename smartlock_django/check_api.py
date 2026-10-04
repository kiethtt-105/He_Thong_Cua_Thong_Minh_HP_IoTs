#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
check_api.py  -  Kiểm thử REST API Smart Lock (/api/v1/) KHÔNG CẦN NHẬP GÌ.

Quy trình mỗi lần chạy:
  1. TỰ TẠO dữ liệu mẫu ngẫu nhiên nhưng đầy đủ thông tin (6 user, 3 khoá, thẻ NFC, PIN, khuôn mặt,
     chia sẻ + quyền, lịch sử ra vào, nhật ký NFC, lệnh, thông báo, audit, 2FA, phiên app...).
  2. CHẠY TEST toàn bộ API app (/api/v1/) + API khoá (firmware) ngay trong tiến trình Django
     (django.test.Client) - KHÔNG cần bật `runserver`.
  3. IN RA MÀN HÌNH toàn bộ log: từng request/response, tin MQTT, email, AuditLog, AccessEvent,
     NfcLog, DeviceCommand, Notification...
  4. XOÁ SẠCH mọi dữ liệu mẫu + log sinh ra khỏi database, rồi đếm lại để xác nhận còn 0 dòng.

Chạy (đặt cạnh manage.py, cùng môi trường/venv và .env của dự án):

    python check_api.py                # hỏi xác nhận DB rồi chạy
    python check_api.py --yes          # không hỏi
    python check_api.py --keep         # không xoá (để tự xem DB), xoá sau bằng --cleanup-only
    python check_api.py --cleanup-only # chỉ dọn dữ liệu mẫu còn sót (vd. lần trước bị Ctrl+C)
    python check_api.py --seed 42      # dữ liệu ngẫu nhiên lặp lại được
    python check_api.py --log-file out.txt   # ghi thêm toàn bộ output ra file

An toàn:
  * MQTT, email và push FCM bị CHẶN (mock): lệnh UNLOCK/LOCK chỉ được ghi lại, KHÔNG gửi ra broker thật.
  * Dữ liệu mẫu đều gắn nhãn: email @checkapi.test, mã khoá CHK-xxxx, IP 203.0.113.77 -> dọn chính xác,
    không đụng dữ liệu thật.
  * Script ghi vào database mà .env đang trỏ tới (có thể là Supabase thật) -> luôn kiểm tra tên DB ở bước xác nhận.
"""
import argparse
import json
import os
import random
import re
import secrets
import string
import sys
import time
import unicodedata
import uuid
from collections import OrderedDict
from datetime import timedelta
from pathlib import Path

HERE = Path(__file__).resolve().parent
TEST_IP = '203.0.113.77'            # dải TEST-NET-3 (tài liệu) - không phải IP thật của ai
DOMAIN = 'checkapi.test'
CODE_PREFIX = 'CHK-'
ANN_PREFIX = '[CHK]'

# ---------------------------------------------------------------- hiển thị
if os.name == 'nt':
    os.system('')
USE_COLOR = sys.stdout.isatty()
G, R, Y, B, D, N = (('\033[92m', '\033[91m', '\033[93m', '\033[96m', '\033[90m', '\033[0m')
                    if USE_COLOR else ('', '', '', '', '', ''))
_ANSI = re.compile(r'\x1b\[[0-9;]*m')
OUT_BUF = []


def out(msg=''):
    print(msg)
    OUT_BUF.append(_ANSI.sub('', str(msg)))


stats = {'pass': 0, 'fail': 0, 'skip': 0}
failures = []


def section(title):
    out(f'\n{B}== {title} =={N}')


def record(ok_, name, detail=''):
    if ok_:
        stats['pass'] += 1
        out(f'  {G}[ OK ]{N} {name}' + (f'  {D}{detail}{N}' if detail else ''))
    else:
        stats['fail'] += 1
        failures.append(f'{name} - {detail}')
        out(f'  {R}[FAIL]{N} {name}  {R}{detail}{N}')
    return ok_


def skip(name, why):
    stats['skip'] += 1
    out(f'  {Y}[SKIP]{N} {name}  {D}{why}{N}')


def info(msg):
    out(f'  {D}{msg}{N}')


# ---------------------------------------------------------------- Django (nạp muộn để --help chạy không cần Django)
services = web = M = settings = timezone = Q = Client = pyotp = cache = None
rnd = random.Random()
CLIENT = None
ARGS = None

HTTP_LOG = []      # mọi request/response
MQTT_SENT = []     # tin MQTT bị chặn (đáng lẽ gửi ra broker)
MAILS = []         # email bị chặn (đáng lẽ gửi đi)
PERSONS = {}       # role -> dict(user, password, tokens...)
DEVS = {}          # key -> dict(obj, secret)
SEED = {}          # dữ liệu mẫu phụ (UID thẻ, PIN gốc, vector mặt...)
T_TEST = None


def find_settings_module():
    manage = HERE / 'manage.py'
    if manage.exists():
        m = re.search(r"DJANGO_SETTINGS_MODULE['\"]\s*,\s*['\"]([\w.]+)['\"]",
                      manage.read_text(encoding='utf-8', errors='ignore'))
        if m:
            return m.group(1)
    return 'smartlock_django.settings'


def load_django():
    global services, web, M, settings, timezone, Q, Client, pyotp, cache, CLIENT
    sys.path.insert(0, str(HERE))
    os.environ.setdefault('DJANGO_SETTINGS_MODULE', find_settings_module())
    os.environ['LOCAL_REPLICA'] = 'False'      # đọc/ghi thẳng DB chính, không qua bản sao local
    os.environ['EMAIL_ASYNC'] = '0'            # gửi mail đồng bộ (đằng nào cũng bị mock)
    import django
    django.setup()
    import logging
    logging.disable(logging.WARNING)           # bớt ồn: chỉ giữ ERROR trở lên
    from django.conf import settings as _settings
    from django.core.cache import cache as _cache
    from django.db.models import Q as _Q
    from django.test import Client as _Client
    from django.utils import timezone as _tz
    import pyotp as _pyotp
    from smartlock import models as _M, services as _services, views as _web
    settings, cache, Q, Client, timezone, pyotp = _settings, _cache, _Q, _Client, _tz, _pyotp
    M, services, web = _M, _services, _web

    if 'localhost' not in settings.ALLOWED_HOSTS and '*' not in settings.ALLOWED_HOSTS:
        settings.ALLOWED_HOSTS = [*settings.ALLOWED_HOSTS, 'localhost']

    # ---- chặn thế giới bên ngoài: MQTT / email / push ----
    def fake_publish(device_code, payload):
        MQTT_SENT.append({'at': timezone.now(), 'device_code': device_code, 'payload': dict(payload)})

    def fake_mail(subject, plain, html, to, log_body=True):
        MAILS.append({'at': timezone.now(), 'to': to, 'subject': subject, 'plain': plain})
        return True

    services.publish_command = fake_publish
    services.send_mail = fake_mail
    web._send_mail = fake_mail
    services.send_notification_push = lambda notification_id: 0
    services._push_in_thread = lambda notification_id: None
    CLIENT = Client(raise_request_exception=False)


# ---------------------------------------------------------------- HTTP in-process
SECRET_KEYS = {'password', 'old_password', 'new_password', 'secret', 'refresh_token', 'access_token', 'token',
               'ticket', 'plain_pin', 'pin', 'code', 'challenge_token', 'fcm_token', 'authorization'}


def mask(obj):
    if isinstance(obj, dict):
        return {k: ('***' if k.lower() in SECRET_KEYS and v not in (None, '', False) else mask(v))
                for k, v in obj.items()}
    if isinstance(obj, list):
        return [mask(v) for v in obj[:20]] + (['...'] if len(obj) > 20 else [])
    return obj


def call(method, path, body=None, who=None, token=None, headers=None, retry429=False, label=''):
    """-> (status, json|None, ms). Gọi /api/v1<path> ngay trong tiến trình (không qua mạng)."""
    if who is not None and token is None:
        token = (who.get('tokens') or {}).get('access')
    extra = {'REMOTE_ADDR': TEST_IP, 'HTTP_X_FORWARDED_FOR': TEST_IP, 'HTTP_HOST': 'localhost',
             'HTTP_USER_AGENT': 'check_api/2.0 (in-process)', 'HTTP_ACCEPT': 'application/json'}
    if token:
        extra['HTTP_AUTHORIZATION'] = f'Bearer {token}'
    for k, v in (headers or {}).items():
        extra['HTTP_' + k.upper().replace('-', '_')] = v
    data = json.dumps(body) if body is not None else ''
    for attempt in (1, 2):
        t0 = time.time()
        resp = CLIENT.generic(method, '/api/v1' + path, data=data, content_type='application/json',
                              secure=True, **extra)
        ms = int((time.time() - t0) * 1000)
        try:
            js = json.loads(resp.content.decode('utf-8')) if resp.content else None
        except ValueError:
            js = {'_not_json': resp.content[:200].decode('utf-8', 'replace')}
        HTTP_LOG.append({'n': len(HTTP_LOG) + 1, 'at': timezone.now(), 'method': method, 'path': path,
                         'who': label or (who or {}).get('role', '-' if not token else 'token'),
                         'status': resp.status_code, 'ms': ms, 'req': mask(body), 'res': mask(js)})
        if resp.status_code == 429 and retry429 and attempt == 1:
            info('Bị throttle (429) - chờ 62 giây rồi thử lại...')
            time.sleep(62)
            continue
        return resp.status_code, js, ms


def err_code(js):
    return ((js or {}).get('error') or {}).get('code')


def first_list(js):
    if isinstance(js, dict):
        for v in js.values():
            if isinstance(v, list) and (not v or isinstance(v[0], dict)):
                return v
    return []


def check(name, res, status, ok=None, code=None, expect=None):
    """Đối chiếu (status, json, ms) với kỳ vọng. expect(js) -> True/None = đạt, str = lý do lỗi."""
    st, js, ms = res
    wanted = status if isinstance(status, (tuple, list)) else (status,)
    problems = []
    if st not in wanted:
        problems.append(f'HTTP {st} (cần {"/".join(map(str, wanted))})')
    if ok is not None and not (isinstance(js, dict) and js.get('ok') is ok):
        problems.append(f'ok={js.get("ok") if isinstance(js, dict) else None} (cần {ok})')
    if code and err_code(js) != code:
        problems.append(f'error.code={err_code(js)} (cần {code})')
    if expect and not problems:
        try:
            r = expect(js)
        except Exception as exc:                                  # noqa: BLE001
            r = f'lỗi khi kiểm tra dữ liệu: {type(exc).__name__}: {exc}'
        if r is False:
            r = 'dữ liệu trả về không đúng kỳ vọng'
        if isinstance(r, str):
            problems.append(r)
    if problems and isinstance(js, dict) and js.get('error'):
        problems.append(f'message: {js["error"].get("message")}')
    if problems and isinstance(js, dict) and '_not_json' in js:
        problems.append('không phải JSON: ' + js['_not_json'][:80].replace('\n', ' '))
    return record(not problems, name, '; '.join(problems) if problems else f'{st} · {ms}ms')


def check_db(name, cond, detail=''):
    return record(bool(cond), 'DB: ' + name, detail if not cond else '')


def jget(js, *path, default=None):
    cur = js
    for p in path:
        if isinstance(cur, dict) and p in cur:
            cur = cur[p]
        else:
            return default
    return cur


# ---------------------------------------------------------------- phạm vi dữ liệu mẫu (để in log, đếm, xoá)
def scope():
    U = M.User.objects.filter(email__iendswith='@' + DOMAIN)
    Dv = M.Device.objects.filter(device_code__startswith=CODE_PREFIX)
    t = OrderedDict()   # THỨ TỰ = thứ tự xoá (bảng con trước)
    t['AuditLog'] = M.AuditLog.objects.filter(
        Q(actor_user__in=U) | Q(target_user__in=U) | Q(device__in=Dv)
        | Q(username_attempt__icontains=DOMAIN) | Q(ip_address=TEST_IP))
    t['NfcLog'] = M.NfcLog.objects.filter(Q(device__in=Dv) | Q(user__in=U) | Q(ip_address=TEST_IP))
    t['AccessEvent'] = M.AccessEvent.objects.filter(Q(device__in=Dv) | Q(user__in=U) | Q(ip_address=TEST_IP))
    t['Notification'] = M.Notification.objects.filter(Q(user__in=U) | Q(device__in=Dv))
    t['DeviceCommand'] = M.DeviceCommand.objects.filter(Q(device__in=Dv) | Q(issued_by__in=U))
    t['DoorPinCode'] = M.DoorPinCode.objects.filter(Q(device__in=Dv) | Q(created_by__in=U))
    t['FaceProfile'] = M.FaceProfile.objects.filter(Q(device__in=Dv) | Q(user__in=U))
    t['CardDeviceAccess'] = M.CardDeviceAccess.objects.filter(Q(device__in=Dv) | Q(access_card__user__in=U))
    t['AccessCard'] = M.AccessCard.objects.filter(user__in=U)
    t['NfcReader'] = M.NfcReader.objects.filter(device__in=Dv)
    t['DeviceAccess'] = M.DeviceAccess.objects.filter(Q(device__in=Dv) | Q(user__in=U) | Q(created_by__in=U))
    t['DeviceStatusLog'] = M.DeviceStatusLog.objects.filter(device__in=Dv)
    t['MobileSession'] = M.MobileSession.objects.filter(Q(user__in=U) | Q(ip_address=TEST_IP))
    t['OneTimeCode'] = M.OneTimeCode.objects.filter(user__in=U)
    t['TwoFactorConfig'] = M.TwoFactorConfig.objects.filter(user__in=U)
    t['Announcement'] = M.Announcement.objects.filter(title__startswith=ANN_PREFIX)
    t['Device'] = Dv
    t['User'] = U
    return t


def count_all():
    return OrderedDict((k, qs.count()) for k, qs in scope().items())


# ---------------------------------------------------------------- sinh dữ liệu mẫu ngẫu nhiên
HO = ['Nguyễn', 'Trần', 'Lê', 'Phạm', 'Hoàng', 'Huỳnh', 'Phan', 'Vũ', 'Võ', 'Đặng', 'Bùi', 'Đỗ', 'Hồ', 'Ngô', 'Dương', 'Lý']
DEM = ['Văn', 'Thị', 'Minh', 'Hoàng', 'Quốc', 'Ngọc', 'Thanh', 'Gia', 'Anh', 'Đức', 'Bảo', 'Khánh']
TEN = ['An', 'Bình', 'Châu', 'Dũng', 'Giang', 'Hà', 'Hải', 'Hùng', 'Khoa', 'Lan', 'Linh', 'Long', 'Mai', 'Nam',
       'Phúc', 'Quân', 'Sơn', 'Thảo', 'Trang', 'Tuấn', 'Vy', 'Yến']
LOCATIONS = ['Cửa chính tầng trệt', 'Cổng sau', 'Phòng làm việc tầng 2', 'Kho hàng', 'Căn hộ 12A05', 'Văn phòng Quận 7',
             'Nhà xe', 'Phòng server']
BOOKINGS = ['Khách Booking #', 'Khách thuê nhà #', 'Thợ sửa điện #', 'Người giao hàng #']


def slug(s):
    s = s.replace('Đ', 'D').replace('đ', 'd')
    return ''.join(c for c in unicodedata.normalize('NFKD', s) if not unicodedata.combining(c)).lower().replace(' ', '')


def strong_password():
    return 'Aa1!' + secrets.token_urlsafe(12)


def rand_phone():
    return '09' + ''.join(rnd.choice(string.digits) for _ in range(8))


def rand_mac():
    return ':'.join(f'{rnd.randint(0, 255):02X}' for _ in range(6))


def rand_uid():
    return ''.join(rnd.choice('0123456789ABCDEF') for _ in range(8))


def rand_ip():
    return f'192.168.{rnd.randint(0, 5)}.{rnd.randint(2, 250)}'


def backdate(model, pk, **fields):
    model.objects.filter(pk=pk).update(**fields)


def person_data(role):
    ho, dem, ten = rnd.choice(HO), rnd.choice(DEM), rnd.choice(TEN)
    tag = secrets.token_hex(3)
    return {'role': role, 'tag': tag, 'full_name': f'{ho} {dem} {ten}', 'password': strong_password(),
            'email': f'{slug(ten)}.{slug(ho)}.{tag}@{DOMAIN}', 'username': f'chk_{role}_{tag}',
            'phone': rand_phone(), 'avatar_url': f'https://avatars.{DOMAIN}/u/{tag}.png', 'tokens': None}


def make_person(role, active=True, verified=True):
    d = person_data(role)
    d['user'] = M.User.objects.create_user(
        email=d['email'], username=d['username'], password=d['password'], full_name=d['full_name'],
        phone=d['phone'], avatar_url=d['avatar_url'], is_active=active, email_verified=verified)
    PERSONS[role] = d
    return d


def make_device(key, owner, status, name, now):
    secret = secrets.token_hex(16)
    dev = M.Device(
        device_code=CODE_PREFIX + secrets.token_hex(4).upper(), provisioning_secret_hash=services.hash_token(secret),
        device_mode='simulated', owner=owner, name=name, mac_address=rand_mac(),
        firmware_version=f'1.{rnd.randint(0, 9)}.{rnd.randint(0, 20)}', status=status,
        battery_level=rnd.randint(55, 100), location=rnd.choice(LOCATIONS), last_seen_at=now,
        bluetooth_enabled=True, wifi_enabled=True, nfc_enabled=True)
    if owner:
        dev.is_purchased = True
        dev.purchased_at = now - timedelta(days=rnd.randint(5, 200))
    dev.save()
    DEVS[key] = {'obj': dev, 'secret': secret}
    return dev


def seed_all():
    """Tạo bộ dữ liệu mẫu đầy đủ. Trả về dict thống kê."""
    now = timezone.now()
    services.ensure_default_permissions()

    owner = make_person('owner')['user']
    family = make_person('family')['user']
    viewer = make_person('viewer')['user']
    make_person('stranger')
    tfa = make_person('tfa')['user']
    make_person('pending', active=False, verified=False)
    stranger = PERSONS['stranger']['user']

    dev_a = make_device('A', owner, 'online', 'Cửa chính', now)
    dev_c = make_device('C', owner, 'online', 'Cổng sau (kịch bản khoá tạm)', now)
    make_device('B', None, 'provisioning', 'Khoá mới chưa gán chủ', now)

    # --- lịch sử trạng thái khoá (10 bản ghi, mới nhất = locked)
    states = ['unlocked', 'locked', 'locked', 'unlocked', 'locked', 'locked', 'jammed', 'locked', 'unlocked', 'locked']
    for i in range(9, -1, -1):
        for dev in (dev_a, dev_c):
            log = M.DeviceStatusLog.objects.create(
                device=dev, battery_level=max(5, dev.battery_level - i), signal_strength=rnd.randint(-85, -40),
                lock_state=states[i] if i else 'locked', tamper_detected=(i == 7),
                temperature=round(rnd.uniform(24, 36), 1),
                raw_payload={'fw': dev.firmware_version, 'rssi': rnd.randint(-85, -40), 'uptime': rnd.randint(100, 99999)})
            backdate(M.DeviceStatusLog, log.pk, recorded_at=now - timedelta(minutes=20 * i + 1))

    # --- đầu đọc NFC
    reader = M.NfcReader.objects.create(device=dev_a, reader_mode='simulated', name='Đầu đọc cửa chính', is_active=True,
                                        last_seen_at=now, grant_permission=['UNLOCK'])

    # --- thẻ NFC: owner (A + C), family (A)
    SEED['cards'] = {}
    for key, usr, name, devs in (('owner', owner, 'Thẻ chính', (dev_a, dev_c)),
                                 ('family', family, 'Thẻ của vợ/chồng', (dev_a,))):
        uid = rand_uid()
        card = M.AccessCard.objects.create(card_uid_hash=M.hash_card_uid(services.normalize_uid(uid)),
                                           user=usr, name=name, is_active=True)
        for dv in devs:
            M.CardDeviceAccess.objects.create(access_card=card, device=dv)
        SEED['cards'][key] = {'uid': uid, 'obj': card}

    # --- mã PIN khách: A (hợp lệ / hết hạn / đã thu hồi), C (hợp lệ)
    SEED['pins'] = {}

    def make_pin(dev, tag, label, plain, valid_from, expires, max_uses=1, use_count=0, revoked=False):
        pin = M.DoorPinCode(device=dev, created_by=owner, label=label, valid_from=valid_from, expires_at=expires,
                            max_uses=max_uses, use_count=use_count, is_revoked=revoked,
                            revoked_at=now if revoked else None)
        pin.set_pin(plain)
        pin.save()
        SEED['pins'][tag] = {'plain': plain, 'obj': pin}
        return pin

    used = set()

    def new_pin_plain():
        while True:
            p = ''.join(rnd.choice(string.digits) for _ in range(6))
            if p not in used:
                used.add(p)
                return p

    make_pin(dev_a, 'A_valid', f'{rnd.choice(BOOKINGS)}{rnd.randint(100, 999)}', new_pin_plain(),
             now - timedelta(minutes=5), now + timedelta(hours=24))
    make_pin(dev_a, 'A_expired', f'{rnd.choice(BOOKINGS)}{rnd.randint(100, 999)}', new_pin_plain(),
             now - timedelta(days=2), now - timedelta(days=1), use_count=1)
    make_pin(dev_a, 'A_revoked', f'{rnd.choice(BOOKINGS)}{rnd.randint(100, 999)}', new_pin_plain(),
             now - timedelta(hours=3), now + timedelta(days=2), revoked=True)
    make_pin(dev_c, 'C_valid', f'{rnd.choice(BOOKINGS)}{rnd.randint(100, 999)}', new_pin_plain(),
             now - timedelta(minutes=5), now + timedelta(hours=6))

    # --- khuôn mặt mẫu: owner trên A (vector 128 chiều, mã hoá Fernet)
    base = [rnd.uniform(-0.3, 0.3) for _ in range(128)]
    SEED['face_base'] = base
    face_o = M.FaceProfile(user=owner, device=dev_a, name=PERSONS['owner']['full_name'], threshold=0.5,
                           consent_confirmed=True, is_active=True)
    face_o.set_embedding(base)
    face_o.save()
    SEED['face_owner'] = face_o

    # --- chia sẻ: family (vai trò 'family', không hết hạn), viewer (chỉ xem, hết hạn sau 7 ngày)
    perms = {p.code: p for p in M.Permission.objects.all()}
    services.grant_access(dev_a, owner, family, [perms[c] for c in services.preset_codes('family')], None)
    services.grant_access(dev_a, owner, viewer, [perms['view_history']], now + timedelta(days=7))

    # --- lịch sử ra vào (AccessEvent) trên A: đủ 5 kênh, cả thành công lẫn thất bại; cách đây >= 45 phút
    cards = SEED['cards']
    specs = [
        ('RFID', True, None, owner, cards['owner']['obj'], None, None),
        ('RFID', False, 'UNKNOWN_CARD', None, None, None, None),
        ('PIN', True, None, owner, None, SEED['pins']['A_valid']['obj'], None),
        ('PIN', False, 'INVALID_OR_EXPIRED_PIN', None, None, None, None),
        ('FACE', True, None, owner, None, None, face_o),
        ('FACE', False, 'FACE_NOT_MATCHED', None, None, None, None),
        ('BLE', True, None, family, None, None, None),
        ('BLE', False, 'BLE_TICKET_EXPIRED', family, None, None, None),
        ('NFC_PHONE', True, None, owner, None, None, None),
        ('NFC_PHONE', False, 'NFC_PHONE_NOT_ALLOWED', viewer, None, None, None),
        ('RFID', True, None, family, cards['family']['obj'], None, None),
        ('PIN', True, None, owner, None, SEED['pins']['A_expired']['obj'], None),
        ('FACE', True, None, owner, None, None, face_o),
        ('BLE', True, None, owner, None, None, None),
    ]
    for i, (method, ok_, reason, usr, card, pin, face) in enumerate(specs):
        ev = M.AccessEvent.objects.create(
            device=dev_a, method=method, success=ok_, reason=reason, user=usr, access_card=card, door_pin=pin,
            face_profile=face, confidence=round(rnd.uniform(0.15, 0.55), 3) if method == 'FACE' else None,
            snapshot_url=f'https://storage.{DOMAIN}/snap/{secrets.token_hex(6)}.jpg' if method == 'FACE' else None,
            ip_address=rand_ip())
        backdate(M.AccessEvent, ev.pk, created_at=now - timedelta(minutes=45 + 37 * i + rnd.randint(0, 20)))
    for i in range(2):
        ev = M.AccessEvent.objects.create(device=dev_c, method='RFID', success=bool(i), user=owner if i else None,
                                          reason=None if i else 'UNKNOWN_CARD', ip_address=rand_ip())
        backdate(M.AccessEvent, ev.pk, created_at=now - timedelta(hours=3 + i))

    # --- nhật ký đầu đọc NFC
    for i, (etype, ok_, card) in enumerate([
            ('READER_CONNECTED', True, None), ('CARD_REGISTER', True, cards['owner']['obj']),
            ('TAP_SUCCESS', True, cards['owner']['obj']), ('TAP_FAILED', False, None),
            ('CONFIG_UPDATED', True, None), ('SESSION_TIMEOUT', False, None)]):
        lg = M.NfcLog.objects.create(reader=reader, nfc_tag=card, device=dev_a, user=owner, event_type=etype,
                                     success=ok_, ip_address=rand_ip(), user_agent='ESP32-RC522/1.2',
                                     metadata={'rssi': rnd.randint(-70, -30), 'seq': i})
        backdate(M.NfcLog, lg.pk, created_at=now - timedelta(minutes=50 + 25 * i))

    # --- lệnh điều khiển cũ
    for i, (cmd, st) in enumerate([('LOCK', 'acknowledged'), ('UNLOCK', 'acknowledged'), ('REBOOT', 'expired'),
                                   ('PING', 'failed')]):
        c = M.DeviceCommand.objects.create(
            device=dev_a, issued_by=owner, command_type=cmd, status=st, payload={'source': 'app'},
            command_token_hash=services.hash_token(secrets.token_urlsafe(16)),
            expires_at=now - timedelta(hours=2 * i + 1) + timedelta(seconds=120),
            acknowledged_at=(now - timedelta(hours=2 * i + 1)) if st == 'acknowledged' else None)
        backdate(M.DeviceCommand, c.pk, created_at=now - timedelta(hours=2 * i + 1))

    # --- thông báo cho owner & family (có đọc / chưa đọc, đủ mức độ)
    for i, (usr, typ, title, sev, read) in enumerate([
            (owner, 'DEVICE', 'Khoá đã online', 'info', True), (owner, 'CARD', 'Có thẻ NFC mới', 'info', False),
            (owner, 'SECURITY', 'Đăng nhập từ IP mới', 'warning', False),
            (owner, 'ACCESS_BURST', 'Nhiều lần mở cửa sai', 'critical', False),
            (owner, 'DOOR_EVENT', 'Cửa vừa được mở bằng thẻ', 'info', True),
            (family, 'SHARE', 'Bạn được chia sẻ khoá', 'info', False)]):
        n = M.Notification.objects.create(user=usr, device=dev_a, type=typ, title=title,
                                          message=f'{title} - dữ liệu mẫu check_api.', severity=sev,
                                          is_read=read, read_at=now if read else None)
        backdate(M.Notification, n.pk, created_at=now - timedelta(minutes=30 + 11 * i))

    # --- audit mẫu
    for i, (act, sev, ok_, actor, target) in enumerate([
            ('LOGIN', 'info', True, owner, None), ('DEVICE_UPDATED', 'info', True, owner, None),
            ('ACCESS_GRANTED', 'info', True, owner, family), ('CARD_REGISTERED', 'info', True, owner, None),
            ('LOGIN_FAILED', 'warning', False, None, owner)]):
        a = M.AuditLog.objects.create(actor_user=actor, target_user=target, device=dev_a, action=act, severity=sev,
                                      success=ok_, ip_address=rand_ip(), user_agent='SmartLockApp/1.4 (Android 14)',
                                      metadata={'seed': True, 'channel': 'mobile'})
        backdate(M.AuditLog, a.pk, created_at=now - timedelta(minutes=60 + 9 * i))

    # --- 2FA: user 'tfa' bật TOTP + Email OTP
    totp_secret = pyotp.random_base32()
    cfg = M.TwoFactorConfig(user=tfa, totp_confirmed=True, email_otp_enabled=True, preferred_method='totp',
                            enabled_at=now)
    cfg.set_totp_secret(totp_secret)
    cfg.save()
    M.sync_two_fa_flag(tfa)
    SEED['totp_secret'] = totp_secret

    # --- mã xác thực email còn hiệu lực cho user chưa kích hoạt
    pend = PERSONS['pending']['user']
    M.OneTimeCode.objects.create(user=pend, purpose='EMAIL_VERIFY', token_hash=services.hash_token(uuid.uuid4().hex),
                                 expires_at=now + timedelta(minutes=30))

    # --- phiên đăng nhập app cũ của owner (để test danh sách / thu hồi phiên)
    sess = M.MobileSession.objects.create(
        user=owner, refresh_hash=services.hash_token(secrets.token_urlsafe(32)), device_name='Pixel 8 (mẫu)',
        platform='android', app_version='1.4.2', fcm_token='fcm-' + secrets.token_hex(16), push_enabled=True,
        ip_address=rand_ip(), last_used_at=now - timedelta(hours=1), expires_at=now + timedelta(days=30))
    SEED['old_session'] = sess

    # --- thông báo hệ thống
    M.Announcement.objects.create(title=f'{ANN_PREFIX} Bảo trì định kỳ', body='Thông báo mẫu từ check_api.',
                                  level='info', created_by=owner, is_active=True)


def print_seed_summary():
    section('DỮ LIỆU MẪU ĐÃ TẠO (ngẫu nhiên, đầy đủ thông tin)')
    out(f'  {B}Người dùng{N}')
    for role, p in PERSONS.items():
        u = p['user']
        out(f'    - {role:<8} id={u.id}\n'
            f'      email={u.email}  username={u.username}  họ tên={u.full_name}  sđt={u.phone}\n'
            f'      avatar={u.avatar_url}  active={u.is_active}  email_verified={u.email_verified}  '
            f'2FA={u.two_fa_enabled}  mật khẩu={p["password"]}')
    out(f'  {B}Khoá{N}')
    for key, d in DEVS.items():
        v = d['obj']
        out(f'    - [{key}] {v.name}  code={v.device_code}  secret={d["secret"]}  id={v.id}\n'
            f'      mode={v.device_mode}  status={v.status}  mac={v.mac_address}  fw={v.firmware_version}  '
            f'pin={v.battery_level}%  vị trí={v.location}  chủ={v.owner.username if v.owner_id else "(chưa có)"}')
    out(f'  {B}Thẻ NFC{N}  ' + '  '.join(f'{k}: UID={c["uid"]}' for k, c in SEED['cards'].items()))
    out(f'  {B}Mã PIN{N}    ' + '  '.join(f'{k}={p["plain"]}' for k, p in SEED['pins'].items()))
    out(f'  {B}TOTP secret (user tfa){N}  {SEED["totp_secret"]}')
    out(f'  {B}Số dòng đã có trong DB{N}')
    for k, n in count_all().items():
        out(f'    {k:<17}{n}')


# ---------------------------------------------------------------- đăng nhập helper
def login_raw(person, password=None, device_name='check_api'):
    body = {'identifier': person['user'].email, 'password': password or person['password'],
            'device_name': device_name, 'platform': 'android', 'app_version': 'check_api'}
    return call('POST', '/auth/login/', body, label=person['role'], retry429=True)


def take_tokens(person, js):
    tokens = js.get('tokens') if isinstance(js.get('tokens'), dict) else js
    if tokens.get('access_token') and tokens.get('refresh_token'):
        person['tokens'] = {'access': tokens['access_token'], 'refresh': tokens['refresh_token']}
        return True
    return 'thiếu access_token/refresh_token (khoá: ' + ', '.join(sorted(js)) + ')'


def login_ok(person, name=None):
    r = login_raw(person)
    check(name or f'Đăng nhập: {person["role"]}', r, 200, ok=True, expect=lambda j: take_tokens(person, j))
    return r


def evcount(device, method, success):
    return M.AccessEvent.objects.filter(device=device, method=method, success=success, created_at__gte=T_TEST).count()


def last_mqtt(device_code, command):
    for m in reversed(MQTT_SENT):
        if m['device_code'] == device_code and m['payload'].get('command') == command:
            return m
    return None


def dev_headers(key):
    return {'X-Device-Code': DEVS[key]['obj'].device_code, 'X-Device-Secret': DEVS[key]['secret']}


def touch(*keys):
    """Giả lập khoá vừa gửi tín hiệu (như subscriber MQTT) để không bị coi là mất kết nối khi test chạy lâu."""
    for k in keys:
        services.touch_device(DEVS[k]['obj'])


def set_dev(key, **fields):
    """Đổi cột của khoá bằng UPDATE trực tiếp (không ghi đè các cột khác bằng bản cache cũ)."""
    dev = DEVS[key]['obj']
    M.Device.objects.filter(pk=dev.pk).update(**fields)
    dev.refresh_from_db()


# ================================================================ CÁC NHÓM TEST
def t_public():
    section('1. Route công khai / bảo vệ (không token)')
    check('API khoá: thiếu header → 401', call('GET', '/device/config/'), 401, ok=False, code='DEVICE_AUTH_REQUIRED')
    check('API khoá: sai mã/secret → 401',
          call('GET', '/device/config/', headers={'X-Device-Code': 'NOPE-0000', 'X-Device-Secret': 'x'}),
          401, ok=False, code='DEVICE_AUTH_FAILED')
    check('Login thiếu dữ liệu → 400', call('POST', '/auth/login/', {}, retry429=True), 400, ok=False)
    check('Login sai phương thức (GET) → 405', call('GET', '/auth/login/'), 405, ok=False, code='METHOD_NOT_ALLOWED')
    check('Login user không tồn tại → 400/401', call('POST', '/auth/login/', {
        'identifier': f'khong.ton.tai@{DOMAIN}', 'password': 'sai-mat-khau-123', 'device_name': 'check_api',
        'platform': 'android'}, retry429=True), (400, 401), ok=False)
    check('Không có token → 401', call('GET', '/me/'), 401, ok=False)
    check('Token rác → 401', call('GET', '/me/', token='token.rac.abc'), 401, ok=False)
    check('Route không tồn tại → 404', call('GET', '/khong-co-route/'), 404)


def t_register():
    section('2. Đăng ký / xác thực email / quên mật khẩu')
    owner = PERSONS['owner']
    pend = PERSONS['pending']
    if services.system_settings().registration_enabled:
        reg = person_data('reg')
        body = {'email': reg['email'], 'username': reg['username'], 'full_name': reg['full_name'],
                'password': reg['password']}
        check('Đăng ký: username có @ → 400 BAD_USERNAME',
              call('POST', '/auth/register/', {**body, 'username': 'chk@bad'}, label='reg'), 400, ok=False,
              code='BAD_USERNAME')
        check('Đăng ký hợp lệ → 201 (cần xác thực email)', call('POST', '/auth/register/', body, label='reg'), 201,
              ok=True, expect=lambda j: j.get('verification_required') is True or 'thiếu verification_required')
        u = M.User.objects.filter(email__iexact=reg['email']).first()
        check_db('user mới được tạo ở trạng thái chưa kích hoạt', u and not u.is_active and not u.email_verified)
        check_db('email xác thực đã được gửi (mock)', any(m['to'] == reg['email'] for m in MAILS))
        check('Đăng ký lại email chưa xác thực → 200 (gửi lại)', call('POST', '/auth/register/', body, label='reg'),
              200, ok=True)
        check('Đăng ký trùng username → 409', call('POST', '/auth/register/', {
            **body, 'email': f'khac.{reg["tag"]}@{DOMAIN}', 'username': owner['user'].username}, label='reg'),
            409, ok=False, code='USERNAME_TAKEN')
        check('Đăng ký email đã có tài khoản → 409', call('POST', '/auth/register/', {
            **body, 'username': f'chk_reg2_{reg["tag"]}', 'email': owner['user'].email}, label='reg'),
            409, ok=False, code='EMAIL_EXISTS')
        check('Login tài khoản chưa xác thực email → 403',
              login_raw({'user': u, 'password': reg['password'], 'role': 'reg'}), 403, ok=False,
              code='EMAIL_NOT_VERIFIED')
        n_before = sum(1 for m in MAILS if m['to'] == reg['email'])
        check('Gửi lại email xác thực → 200 trung tính',
              call('POST', '/auth/resend-verification/', {'email': reg['email']}, label='reg', retry429=True), 200, ok=True)
        check_db('trong 60 giây không gửi thêm mail (chống spam)',
                 sum(1 for m in MAILS if m['to'] == reg['email']) == n_before)
    else:
        skip('Đăng ký tài khoản', 'hệ thống đang đóng đăng ký (SystemSettings.registration_enabled=False)')
    check('Gửi lại email xác thực cho user chờ kích hoạt → 200',
          call('POST', '/auth/resend-verification/', {'email': pend['user'].email}, label='pending', retry429=True), 200, ok=True)
    check('Quên mật khẩu: email lạ → 200 trung tính',
          call('POST', '/auth/password-reset/', {'email': f'la.{secrets.token_hex(3)}@{DOMAIN}'}, retry429=True), 200, ok=True)
    n0 = sum(1 for m in MAILS if m['to'] == owner['user'].email)
    check('Quên mật khẩu: email có thật → 200 trung tính',
          call('POST', '/auth/password-reset/', {'email': owner['user'].email}, label='owner', retry429=True), 200, ok=True)
    check_db('email đặt lại mật khẩu đã được gửi (mock)',
             sum(1 for m in MAILS if m['to'] == owner['user'].email) == n0 + 1)
    check('Quên mật khẩu: tài khoản chưa xác thực → 200 trung tính',
          call('POST', '/auth/password-reset/', {'email': pend['user'].email}, retry429=True), 200, ok=True)


def t_auth():
    section('3. Đăng nhập / 2FA / làm mới token / phiên')
    owner, family, viewer, stranger, tfa = (PERSONS[k] for k in ('owner', 'family', 'viewer', 'stranger', 'tfa'))
    check('Login sai mật khẩu → 401', login_raw(owner, password='Sai-mat-khau-1!'), 401, ok=False,
          code='INVALID_CREDENTIALS')
    login_ok(owner, 'Đăng nhập chủ khoá (owner)')
    check('Token owner dùng được (GET /me/)', call('GET', '/me/', who=owner), 200, ok=True,
          expect=lambda j: jget(j, 'user', 'email') == owner['user'].email or 'email trả về không khớp')
    login_ok(family, 'Đăng nhập thành viên gia đình (family)')
    login_ok(viewer, 'Đăng nhập người chỉ xem (viewer)')
    login_ok(stranger, 'Đăng nhập người lạ (stranger)')

    # ---- 2FA TOTP
    r = login_raw(tfa)
    check('Login tài khoản bật 2FA → yêu cầu mã 2FA', r, 200, ok=True, expect=lambda j: (
        j.get('two_factor_required') is True and 'totp' in (j.get('methods') or []) and
        'email' in (j.get('methods') or []) and bool(j.get('challenge_token')))
        or f'phản hồi 2FA không đúng: methods={j.get("methods")}')
    ch = (r[1] or {}).get('challenge_token')
    check('2FA TOTP: mã sai → 401', call('POST', '/auth/2fa/verify/', {
        'challenge_token': ch, 'method': 'totp', 'code': '000000'}, label='tfa', retry429=True),
        401, ok=False, code='TWO_FACTOR_INVALID')
    check('2FA TOTP: mã đúng → 200 + token', call('POST', '/auth/2fa/verify/', {
        'challenge_token': ch, 'method': 'totp', 'code': pyotp.TOTP(SEED['totp_secret']).now()},
        label='tfa', retry429=True), 200, ok=True, expect=lambda j: take_tokens(tfa, j))
    # ---- 2FA Email OTP
    r = login_raw(tfa)
    ch2 = (r[1] or {}).get('challenge_token')
    n_mail = len(MAILS)
    check('2FA Email: gửi mã → 200', call('POST', '/auth/2fa/email/send/', {'challenge_token': ch2}, label='tfa',
                                          retry429=True), 200, ok=True)
    check('2FA Email: gửi lại ngay → 429 (cooldown)', call('POST', '/auth/2fa/email/send/', {
        'challenge_token': ch2}, label='tfa', retry429=True), 429, ok=False, code='COOLDOWN')
    mail = next((m for m in MAILS[n_mail:] if m['to'] == tfa['user'].email), None)
    code = (re.search(r'\b(\d{6})\b', mail['plain']) or [None, None])[1] if mail else None
    check_db('email chứa mã OTP 6 số (mock)', code)
    if code:
        check('2FA Email: nhập đúng mã → 200 + token', call('POST', '/auth/2fa/verify/', {
            'challenge_token': ch2, 'method': 'email', 'code': code}, label='tfa', retry429=True),
            200, ok=True, expect=lambda j: take_tokens(tfa, j))

    # ---- refresh token xoay vòng + phát hiện dùng lại
    old_refresh = owner['tokens']['refresh']
    r = call('POST', '/auth/refresh/', {'refresh_token': old_refresh}, label='owner')
    check('Làm mới token (refresh xoay vòng)', r, 200, ok=True, expect=lambda j: (
        bool(j.get('access_token')) and j.get('refresh_token') != old_refresh) or 'refresh_token không được xoay')
    if jget(r[1], 'access_token'):
        owner['tokens'] = {'access': r[1]['access_token'], 'refresh': r[1].get('refresh_token', old_refresh)}
    throw = {'role': 'owner(phiên phụ)', 'user': owner['user'], 'password': owner['password'], 'tokens': None}
    r = login_raw(throw, device_name='check_api-phiên phụ')
    if r[0] == 200 and take_tokens(throw, r[1]) is True:
        r1 = throw['tokens']['refresh']
        call('POST', '/auth/refresh/', {'refresh_token': r1}, label='owner-phụ')
        check('Dùng lại refresh token cũ → bị từ chối', call('POST', '/auth/refresh/', {'refresh_token': r1},
                                                              label='owner-phụ'), (400, 401), ok=False)


def t_account():
    section('4. Tài khoản (owner): hồ sơ / phiên / push / 2FA / bootstrap')
    owner = PERSONS['owner']
    u = owner['user']
    check('GET /me/', call('GET', '/me/', who=owner), 200, ok=True, expect=lambda j: (
        j.get('device_count') == 2 and j.get('card_count') == 1) or
        f'device_count={j.get("device_count")} card_count={j.get("card_count")} (mong đợi 2 và 1)')
    new_name, new_phone = 'Nguyễn Văn Kiểm Thử', rand_phone()
    check('PATCH /me/ đổi họ tên + sđt', call('PATCH', '/me/', {'full_name': new_name, 'phone': new_phone}, who=owner),
          200, ok=True)
    u.refresh_from_db()
    check_db('hồ sơ đã được lưu', u.full_name == new_name and u.phone == new_phone)
    check('GET /bootstrap/', call('GET', '/bootstrap/', who=owner), 200, ok=True, expect=lambda j: (
        any(d.get('id') == str(DEVS['A']['obj'].id) for d in j.get('devices', [])) and
        any(str(a.get('title', '')).startswith(ANN_PREFIX) for a in j.get('announcements', [])) and
        isinstance(j.get('notifications'), list)) or 'thiếu khoá/thông báo hệ thống trong bootstrap')
    old = SEED['old_session']
    r = call('GET', '/me/sessions/', who=owner)
    check('GET /me/sessions/ (có phiên hiện tại + phiên mẫu)', r, 200, ok=True, expect=lambda j: (
        any(s.get('is_current') for s in j.get('sessions', [])) and
        any(s.get('id') == str(old.id) for s in j.get('sessions', []))) or 'thiếu phiên hiện tại hoặc phiên mẫu')
    check('Thu hồi phiên mẫu → 200', call('DELETE', f'/me/sessions/{old.id}/', who=owner), 200, ok=True)
    old.refresh_from_db()
    check_db('phiên mẫu đã bị thu hồi', old.revoked_at is not None)
    check('Thu hồi phiên không tồn tại → 404', call('DELETE', f'/me/sessions/{uuid.uuid4()}/', who=owner), 404,
          ok=False)
    check('PUT /me/push-token/', call('PUT', '/me/push-token/', {'fcm_token': 'fcm-' + secrets.token_hex(20),
                                                                 'push_enabled': True}, who=owner),
          200, ok=True, expect=lambda j: j.get('has_push_token') is True or 'has_push_token != true')
    check('DELETE /me/push-token/', call('DELETE', '/me/push-token/', who=owner), 200, ok=True)
    check('GET /me/two-factor/', call('GET', '/me/two-factor/', who=owner), 200, ok=True,
          expect=lambda j: j.get('enabled') is False or 'owner không bật 2FA nhưng enabled != false')
    check('GET /me/two-factor/ (tfa) liệt kê totp + email', call('GET', '/me/two-factor/', who=PERSONS['tfa']), 200,
          ok=True, expect=lambda j: set(j.get('usable_in_app', [])) >= {'totp', 'email'} or 'thiếu totp/email')
    check('Đổi mật khẩu: sai mật khẩu cũ → 400', call('POST', '/me/password/', {
        'old_password': 'Sai-mat-khau-1!', 'new_password': strong_password()}, who=owner), 400, ok=False,
        code='WRONG_PASSWORD')
    check('Đổi mật khẩu: mật khẩu mới yếu → 400', call('POST', '/me/password/', {
        'old_password': owner['password'], 'new_password': '123'}, who=owner), 400, ok=False, code='WEAK_PASSWORD')
    new_pw = strong_password()
    check('Đổi mật khẩu thành công → 200', call('POST', '/me/password/', {
        'old_password': owner['password'], 'new_password': new_pw}, who=owner), 200, ok=True)
    owner['password'] = new_pw
    u.refresh_from_db()
    check_db('mật khẩu mới có hiệu lực', u.check_password(new_pw))
    check_db('có thông báo bảo mật "Mật khẩu đã thay đổi"',
             M.Notification.objects.filter(user=u, type='SECURITY', created_at__gte=T_TEST).exists())


def t_devices():
    section('5. Khoá: danh sách / chi tiết / sửa / trạng thái / lệnh / vé BLE-NFC')
    owner, family, viewer, stranger = (PERSONS[k] for k in ('owner', 'family', 'viewer', 'stranger'))
    A, C = DEVS['A']['obj'], DEVS['C']['obj']
    aid = str(A.id)
    touch('A', 'C')
    check('GET /devices/ (owner thấy A + C)', call('GET', '/devices/', who=owner), 200, ok=True, expect=lambda j: (
        {str(A.id), str(C.id)} <= {d['id'] for d in j.get('devices', [])} and
        'UNLOCK' in next(d for d in j['devices'] if d['id'] == aid)['permissions'])
        or 'thiếu khoá A/C hoặc thiếu quyền UNLOCK của chủ')
    check('GET /devices/ (family thấy A, quyền hạn chế)', call('GET', '/devices/', who=family), 200, ok=True,
          expect=lambda j: (len(j['devices']) == 1 and 'view_history' in j['devices'][0]['permissions'] and
                            'manage_pins' not in j['devices'][0]['permissions']) or 'quyền family không đúng')
    check('GET /devices/ (stranger thấy 0 khoá)', call('GET', '/devices/', who=stranger), 200, ok=True,
          expect=lambda j: len(j.get('devices', [])) == 0 or 'người lạ lại thấy khoá')
    check('GET /devices/{id}/ (owner)', call('GET', f'/devices/{aid}/', who=owner), 200, ok=True, expect=lambda j: (
        jget(j, 'last_status', 'lock_state') == 'locked' and len(j.get('recent_commands', [])) >= 1)
        or f'last_status/recent_commands không đúng: {jget(j, "last_status")}')
    check('GET /devices/{id}/ (stranger) → 404', call('GET', f'/devices/{aid}/', who=stranger), 404, ok=False,
          code='DEVICE_NOT_FOUND')
    check('Khoá không tồn tại → 404', call('GET', f'/devices/{uuid.uuid4()}/', who=owner), 404, ok=False)
    r = call('PATCH', f'/devices/{aid}/', {'name': 'Cửa chính (đã đổi tên)', 'location': 'Tầng 1 - Sảnh'}, who=owner)
    check('PATCH khoá (owner) đổi tên + vị trí', r, 200, ok=True)
    A.refresh_from_db()
    check_db('tên + vị trí đã lưu', A.name == 'Cửa chính (đã đổi tên)' and A.location == 'Tầng 1 - Sảnh')
    check('PATCH khoá: cờ không phải boolean → 400', call('PATCH', f'/devices/{aid}/', {'wifi_enabled': 'yes'},
                                                           who=owner), 400, ok=False, code='BAD_FIELD')
    check('PATCH khoá: tên rỗng → 400', call('PATCH', f'/devices/{aid}/', {'name': ' '}, who=owner), 400, ok=False,
          code='MISSING_FIELD')
    check('PATCH khoá bởi family → 403', call('PATCH', f'/devices/{aid}/', {'name': 'hack'}, who=family), 403,
          ok=False, code='OWNER_ONLY')

    check('GET /devices/{id}/live/', call('GET', f'/devices/{aid}/live/', who=owner), 200, ok=True, expect=lambda j: (
        j.get('connected') is True and j.get('lock_state') == 'locked' and j.get('locked_out') is False and
        len(j.get('events', [])) >= 1) or f'live: connected={j.get("connected")} lock={j.get("lock_state")}')
    check('GET /devices/{id}/live/ (viewer có view_history → có events)', call('GET', f'/devices/{aid}/live/',
                                                                              who=viewer), 200, ok=True,
          expect=lambda j: 'events' in j or 'viewer phải thấy events')
    check('GET /devices/{id}/live/ (family có view_history)', call('GET', f'/devices/{aid}/live/',
                                                                                  who=family), 200, ok=True)
    check('GET /devices/{id}/commands/history/', call('GET', f'/devices/{aid}/commands/history/', who=owner), 200,
          ok=True, expect=lambda j: len(first_list(j)) >= 4 or 'thiếu lệnh mẫu')

    # ---- lệnh
    check('Lệnh không hợp lệ → 400', call('POST', f'/devices/{aid}/commands/', {'command': 'KHONG_CO'}, who=owner), 400,
          ok=False, code='BAD_COMMAND')
    check('REBOOT bởi family (chỉ chủ) → 403', call('POST', f'/devices/{aid}/commands/', {'command': 'REBOOT'},
                                                      who=family), 403, ok=False, code='FORBIDDEN')
    check('LOCK bởi viewer (không có quyền) → 403', call('POST', f'/devices/{aid}/commands/', {'command': 'LOCK'},
                                                          who=viewer), 403, ok=False, code='FORBIDDEN')
    check('LOCK bởi stranger → 404', call('POST', f'/devices/{aid}/commands/', {'command': 'LOCK'}, who=stranger),
          404, ok=False)
    r = call('POST', f'/devices/{aid}/commands/', {'command': 'LOCK'}, who=owner)
    check('LOCK bởi owner → 202', r, 202, ok=True, expect=lambda j: jget(j, 'command', 'status') == 'sent' or
          f'status={jget(j, "command", "status")} (cần sent)')
    lock_id = jget(r[1], 'command', 'id')
    mq = last_mqtt(A.device_code, 'LOCK')
    check_db('lệnh LOCK đã được "publish" MQTT (mock) tới đúng khoá', mq and mq['payload'].get('command_id') == lock_id)
    check('LOCK lặp lại ngay → 429', call('POST', f'/devices/{aid}/commands/', {'command': 'LOCK'}, who=owner), 429,
          ok=False, code='DUPLICATE')
    check('UNLOCK bởi family (có quyền) → 202', call('POST', f'/devices/{aid}/commands/', {'command': 'UNLOCK'},
                                                       who=family), 202, ok=True)
    check_db('lệnh UNLOCK chỉ được ghi lại (không gửi ra broker thật)', last_mqtt(A.device_code, 'UNLOCK') is not None)
    set_dev('A', wifi_enabled=False)
    check('Wi-Fi khoá tắt → lệnh bị từ chối 409', call('POST', f'/devices/{aid}/commands/', {'command': 'REBOOT'},
                                                        who=owner), 409, ok=False, code='WIFI_DISABLED')
    set_dev('A', wifi_enabled=True)

    # ---- poll trạng thái lệnh + khoá ack (vòng hai chiều)
    check('GET /commands/{id}/ (owner) trạng thái = sent', call('GET', f'/commands/{lock_id}/', who=owner), 200,
          ok=True, expect=lambda j: jget(j, 'command', 'status') == 'sent' or 'status != sent')
    check('GET /commands/{id}/ (viewer) → 404', call('GET', f'/commands/{lock_id}/', who=viewer), 404, ok=False)
    ack = call('POST', '/device/ack/', {'command_id': lock_id, 'token': mq['payload'].get('token') if mq else 'x',
                                         'success': True}, headers=dev_headers('A'), label='firmware-A')
    check('Khoá gửi ACK cho lệnh LOCK → 200', ack, 200, ok=True)
    cmd = M.DeviceCommand.objects.filter(pk=lock_id).first()
    check_db('lệnh LOCK chuyển sang acknowledged', cmd and cmd.status == 'acknowledged',
             f'status={cmd.status if cmd else None}')
    check('GET /commands/{id}/ sau ACK = acknowledged', call('GET', f'/commands/{lock_id}/', who=owner), 200, ok=True,
          expect=lambda j: jget(j, 'command', 'status') == 'acknowledged' or 'chưa acknowledged')

    # ---- vé BLE / NFC
    SEED['tickets'] = {}
    for kind in ('ble', 'nfc'):
        r = call('POST', f'/devices/{aid}/{kind}-ticket/', who=owner)
        check(f'Vé {kind.upper()} (owner) → 200', r, 200, ok=True,
              expect=lambda j: (bool(j.get('ticket')) and j.get('ttl_seconds', 0) > 0) or 'thiếu ticket/ttl')
        SEED['tickets'][kind] = jget(r[1], 'ticket')
    check('Vé BLE bởi viewer (không có quyền) → 403', call('POST', f'/devices/{aid}/ble-ticket/', who=viewer), 403,
          ok=False, code='FORBIDDEN')
    check('Vé NFC bởi stranger → 404', call('POST', f'/devices/{aid}/nfc-ticket/', who=stranger), 404, ok=False)
    set_dev('A', bluetooth_enabled=False)
    check('Bluetooth khoá tắt → vé BLE 409', call('POST', f'/devices/{aid}/ble-ticket/', who=owner), 409, ok=False,
          code='CHANNEL_UNAVAILABLE')
    set_dev('A', bluetooth_enabled=True)


def t_pins():
    section('6. Mã PIN khách')
    owner, family, viewer, stranger = (PERSONS[k] for k in ('owner', 'family', 'viewer', 'stranger'))
    aid = str(DEVS['A']['obj'].id)
    r = call('POST', f'/devices/{aid}/pins/', {'label': 'Khách test API', 'ttl_minutes': 60, 'max_uses': 1}, who=owner)
    check('Tạo PIN (owner) → 201 + plain_pin 6 số', r, 201, ok=True, expect=lambda j: (
        re.fullmatch(r'\d{6}', str(j.get('plain_pin', ''))) is not None) or 'plain_pin không phải 6 số')
    new_pin_id = jget(r[1], 'pin', 'id')
    check('Tạo PIN: ttl không hợp lệ → 400', call('POST', f'/devices/{aid}/pins/', {'ttl_minutes': 'abc'}, who=owner),
          400, ok=False, code='BAD_FIELD')
    check('GET PIN (owner thấy cả mẫu + mới)', call('GET', f'/devices/{aid}/pins/', who=owner), 200, ok=True,
          expect=lambda j: len(j.get('pins', [])) >= 4 or f'chỉ có {len(j.get("pins", []))} PIN')
    fam_access = M.DeviceAccess.objects.filter(device=DEVS['A']['obj'], user=family['user'], is_active=True).first()
    check('Tạo PIN (family KHÔNG có manage_pins) → 403', call('POST', f'/devices/{aid}/pins/', {}, who=family), 403,
          ok=False, code='FORBIDDEN')
    check('Owner nâng quyền family lên "người trông nhà" (manager)', call('PATCH', f'/shares/{fam_access.id}/', {
        'preset': 'manager'}, who=owner), 200, ok=True,
        expect=lambda j: 'manage_pins' in jget(j, 'share', 'permissions', default=[]) or 'thiếu manage_pins')
    r = call('POST', f'/devices/{aid}/pins/', {'label': 'PIN của người trông nhà', 'ttl_minutes': 30}, who=family)
    check('Tạo PIN (manager có manage_pins) → 201', r, 201, ok=True)
    fam_pin = jget(r[1], 'pin', 'id')
    check('GET PIN (manager chỉ thấy PIN của mình)', call('GET', f'/devices/{aid}/pins/', who=family), 200, ok=True,
          expect=lambda j: len(j.get('pins', [])) == 1 or f'thấy {len(j.get("pins", []))} PIN (cần 1)')
    check('Tạo PIN (viewer không có manage_pins) → 403', call('POST', f'/devices/{aid}/pins/', {}, who=viewer), 403,
          ok=False, code='FORBIDDEN')
    check('GET PIN (stranger) → 404', call('GET', f'/devices/{aid}/pins/', who=stranger), 404, ok=False)
    check('Manager thu hồi PIN của owner → 404', call('DELETE', f'/pins/{new_pin_id}/', who=family), 404, ok=False)
    check('Owner thu hồi PIN của manager → 200', call('DELETE', f'/pins/{fam_pin}/', who=owner), 200, ok=True)
    check('Hạ quyền family về lại preset "family"', call('PATCH', f'/shares/{fam_access.id}/', {'preset': 'family'},
                                                         who=owner), 200, ok=True,
          expect=lambda j: 'manage_pins' not in jget(j, 'share', 'permissions', default=[]) or 'vẫn còn manage_pins')
    check('Owner thu hồi PIN vừa tạo → 200', call('DELETE', f'/pins/{new_pin_id}/', who=owner), 200, ok=True)
    pin = M.DoorPinCode.objects.filter(pk=new_pin_id).first()
    check_db('PIN đã bị thu hồi (is_revoked + revoked_at)', pin and pin.is_revoked and pin.revoked_at)


def t_cards_readers():
    section('7. Thẻ NFC + đầu đọc NFC')
    owner, family, viewer, stranger = (PERSONS[k] for k in ('owner', 'family', 'viewer', 'stranger'))
    A = DEVS['A']['obj']
    aid = str(A.id)
    uid = rand_uid()
    r = call('POST', f'/devices/{aid}/cards/', {'uid': uid, 'name': 'Thẻ test API'}, who=owner)
    check('Đăng ký thẻ bằng UID → 201', r, 201, ok=True)
    card_id = jget(r[1], 'card', 'id')
    check('Đăng ký thẻ trùng UID → 409', call('POST', f'/devices/{aid}/cards/', {'uid': uid}, who=owner), 409,
          ok=False, code='CARD_EXISTS')
    check('Đăng ký thẻ: UID quá ngắn → 400', call('POST', f'/devices/{aid}/cards/', {'uid': 'AB'}, who=owner), 400,
          ok=False, code='BAD_UID')
    check_db('NfcLog CARD_REGISTER được ghi', M.NfcLog.objects.filter(
        device=A, event_type='CARD_REGISTER', created_at__gte=T_TEST).exists())
    check('GET /cards/ (owner thấy thẻ mới)', call('GET', '/cards/', who=owner), 200, ok=True,
          expect=lambda j: any(c['id'] == card_id for c in j.get('cards', [])) or 'thiếu thẻ vừa đăng ký')
    check('PATCH thẻ: đổi tên + tắt', call('PATCH', f'/cards/{card_id}/', {'name': 'Thẻ đã đổi tên', 'is_active': False},
                                            who=owner), 200, ok=True)
    c = M.AccessCard.objects.get(pk=card_id)
    check_db('thẻ đã đổi tên và bị tắt', c.name == 'Thẻ đã đổi tên' and c.is_active is False)
    check('PATCH thẻ: is_active sai kiểu → 400', call('PATCH', f'/cards/{card_id}/', {'is_active': 'x'}, who=owner),
          400, ok=False, code='BAD_FIELD')
    check('Tắt/bật thẻ trên 1 khoá (link)', call('PATCH', f'/cards/{card_id}/devices/{aid}/', {'is_active': False},
                                                 who=owner), 200, ok=True)
    check('Link: thiếu is_active → 400', call('PATCH', f'/cards/{card_id}/devices/{aid}/', {}, who=owner), 400, ok=False,
          code='BAD_FIELD')
    owner_card = SEED['cards']['owner']['obj']
    check('Family sửa thẻ của owner → 404', call('PATCH', f'/cards/{owner_card.id}/', {'name': 'x'}, who=family), 404,
          ok=False)
    check('Family đăng ký thẻ riêng (manage_nfc) → 201', call('POST', f'/devices/{aid}/cards/', {
        'uid': rand_uid(), 'name': 'Thẻ family 2'}, who=family), 201, ok=True)
    check_db('owner được thông báo có thẻ mới từ family', M.Notification.objects.filter(
        user=PERSONS['owner']['user'], type='CARD', created_at__gte=T_TEST).exists())
    check('Viewer đăng ký thẻ → 403', call('POST', f'/devices/{aid}/cards/', {'uid': rand_uid()}, who=viewer), 403,
          ok=False, code='FORBIDDEN')
    set_dev('A', nfc_enabled=False)
    check('NFC khoá tắt → đăng ký thẻ 409', call('POST', f'/devices/{aid}/cards/', {'uid': rand_uid()}, who=owner),
          409, ok=False, code='NFC_DISABLED')
    set_dev('A', nfc_enabled=True)
    check('Xoá thẻ (owner) → 200', call('DELETE', f'/cards/{card_id}/', who=owner), 200, ok=True)
    check_db('thẻ đã bị xoá', not M.AccessCard.objects.filter(pk=card_id).exists())

    # ---- đầu đọc
    r = call('POST', f'/devices/{aid}/nfc-readers/', {'name': 'Đầu đọc test API'}, who=owner)
    check('Thêm đầu đọc mô phỏng → 201', r, 201, ok=True)
    rid = jget(r[1], 'reader', 'id')
    check('GET đầu đọc', call('GET', f'/devices/{aid}/nfc-readers/', who=owner), 200, ok=True,
          expect=lambda j: len(j.get('readers', [])) >= 2 or 'thiếu đầu đọc')
    check('Family thêm đầu đọc (chỉ chủ) → 403', call('POST', f'/devices/{aid}/nfc-readers/', {}, who=family), 403,
          ok=False, code='OWNER_ONLY')
    check('Bật đăng ký-bằng-quẹt (60s)', call('PATCH', f'/nfc-readers/{rid}/', {'auto_register': True}, who=owner), 200,
          ok=True, expect=lambda j: jget(j, 'reader', 'auto_register') is True or 'auto_register chưa bật')
    check('Tắt đăng ký-bằng-quẹt', call('PATCH', f'/nfc-readers/{rid}/', {'auto_register': False}, who=owner), 200,
          ok=True, expect=lambda j: jget(j, 'reader', 'auto_register') is False or 'auto_register vẫn bật')
    check('Tắt đầu đọc', call('PATCH', f'/nfc-readers/{rid}/', {'is_active': False}, who=owner), 200, ok=True)
    check('PATCH đầu đọc: body rỗng → 400', call('PATCH', f'/nfc-readers/{rid}/', {}, who=owner), 400, ok=False,
          code='MISSING_FIELD')


def t_faces():
    section('8. Khuôn mặt')
    owner, family, viewer, stranger = (PERSONS[k] for k in ('owner', 'family', 'viewer', 'stranger'))
    aid = str(DEVS['A']['obj'].id)
    base = [rnd.uniform(-0.3, 0.3) for _ in range(128)]

    def frames(n, noise=0.01):
        return [[x + rnd.gauss(0, noise) for x in base] for _ in range(n)]

    check('Đăng ký mặt thiếu đồng ý → 400', call('POST', f'/devices/{aid}/faces/', {
        'consent_confirmed': False, 'embeddings': frames(4)}, who=family), 400, ok=False, code='CONSENT_REQUIRED')
    check('Đăng ký mặt: 2 khung hình → 422', call('POST', f'/devices/{aid}/faces/', {
        'consent_confirmed': True, 'embeddings': frames(2)}, who=family), 422, ok=False, code='FRAME_COUNT')
    check('Đăng ký mặt: khung hình lệch nhau → 422', call('POST', f'/devices/{aid}/faces/', {
        'consent_confirmed': True, 'embeddings': [[rnd.uniform(-0.5, 0.5) for _ in range(128)] for _ in range(4)]},
        who=family), 422, ok=False, code='INCONSISTENT')
    check('Đăng ký mặt: vector phẳng → 422', call('POST', f'/devices/{aid}/faces/', {
        'consent_confirmed': True, 'embeddings': [[0.1] * 128] * 4}, who=family), 422, ok=False, code='BAD_VECTOR')
    r = call('POST', f'/devices/{aid}/faces/', {'consent_confirmed': True, 'embeddings': frames(4),
                                                 'name': PERSONS['family']['full_name']}, who=family)
    check('Đăng ký mặt hợp lệ (family) → 201', r, 201, ok=True)
    pid = jget(r[1], 'profile', 'id')
    fp = M.FaceProfile.objects.filter(pk=pid).first()
    check_db('embedding được mã hoá và giải mã lại đủ 128 chiều', fp and len(fp.get_embedding()) == 128)
    check_db('owner được thông báo có khuôn mặt mới', M.Notification.objects.filter(
        user=PERSONS['owner']['user'], type='FACE', created_at__gte=T_TEST).exists())
    check('GET khuôn mặt (family chỉ thấy của mình)', call('GET', f'/devices/{aid}/faces/', who=family), 200, ok=True,
          expect=lambda j: len(j.get('profiles', [])) == 1 or 'family phải thấy đúng 1 hồ sơ')
    check('GET khuôn mặt (owner thấy tất cả)', call('GET', f'/devices/{aid}/faces/', who=owner), 200, ok=True,
          expect=lambda j: len(j.get('profiles', [])) >= 2 or 'owner phải thấy ≥ 2 hồ sơ')
    check('GET khuôn mặt (viewer) → 403', call('GET', f'/devices/{aid}/faces/', who=viewer), 403, ok=False)
    check('Stranger xoá hồ sơ của family → 404', call('DELETE', f'/faces/{pid}/', who=PERSONS['stranger']), 404,
          ok=False)
    check('Owner xoá hồ sơ của family → 200', call('DELETE', f'/faces/{pid}/', who=owner), 200, ok=True)
    check_db('hồ sơ khuôn mặt đã xoá', not M.FaceProfile.objects.filter(pk=pid).exists())


def t_firmware():
    section('9. API khoá (firmware): config / heartbeat / mở cửa bằng thẻ-PIN-điện thoại / khoá tạm')
    A, C = DEVS['A']['obj'], DEVS['C']['obj']
    ha, hc = dev_headers('A'), dev_headers('C')
    owner = PERSONS['owner']
    r = call('GET', '/device/config/', headers=ha, label='firmware-A')
    if check('GET /device/config/', r, 200, ok=True):
        for k in ('unix_time', 'intervals'):
            record(k in r[1] or k in (r[1].get('config') or {}), f'config có trường "{k}"')
    n_logs = M.DeviceStatusLog.objects.filter(device=A).count()
    r = call('POST', '/device/heartbeat/', {'battery': 87, 'signal': -60, 'tamper': False, 'firmware': 'chk-2.0',
                                            'lock_state': 'locked'}, headers=ha, label='firmware-A')
    if check('POST /device/heartbeat/', r, 200, ok=True):
        record(isinstance(r[1].get('commands'), list), 'heartbeat trả về mảng "commands"')
    check_db('heartbeat ghi thêm DeviceStatusLog', M.DeviceStatusLog.objects.filter(device=A).count() == n_logs + 1)
    A.refresh_from_db()
    check_db('heartbeat cập nhật pin + firmware của khoá', A.battery_level == 87 and A.firmware_version == 'chk-2.0',
             f'pin={A.battery_level} fw={A.firmware_version}')
    check('GET /device/commands/', call('GET', '/device/commands/', headers=ha, label='firmware-A'), 200, ok=True)
    check('POST /device/ack/ lệnh giả → bị từ chối', call('POST', '/device/ack/', {
        'command_id': str(uuid.uuid4()), 'token': 'x', 'success': True}, headers=ha, label='firmware-A'),
        (400, 404), ok=False)
    check('POST /device/events/ loại sai → 400', call('POST', '/device/events/', {'type': 'KHONG_CO'}, headers=ha,
                                                       label='firmware-A'), 400, ok=False)

    def granted(name, res, want):
        check(name, res, 200, ok=True,
              expect=lambda j: j.get('granted') is want or f'granted={j.get("granted")} (cần {want})')

    # ---- khoá A: thành công trước, tối đa 2 lần sai (ngưỡng khoá tạm là 3 lần / 60 giây)
    pin_ok = SEED['pins']['A_valid']['plain']
    granted('PIN hợp lệ → granted=true', call('POST', '/device/access/pin/', {'pin': pin_ok}, headers=ha,
                                              label='firmware-A'), True)
    check_db('AccessEvent PIN thành công + lệnh UNLOCK (mock) nguồn pin', evcount(A, 'PIN', True) == 1 and
             (last_mqtt(A.device_code, 'UNLOCK') or {}).get('payload', {}).get('source') == 'pin')
    granted('RFID thẻ hợp lệ (owner) → granted=true', call('POST', '/device/access/rfid/', {
        'uid': SEED['cards']['owner']['uid']}, headers=ha, label='firmware-A'), True)
    check_db('AccessEvent RFID thành công gắn đúng chủ thẻ', M.AccessEvent.objects.filter(
        device=A, method='RFID', success=True, user=owner['user'], created_at__gte=T_TEST).exists())
    for kind, ch in (('ble', 'ble'), ('nfc', 'nfc')):
        ticket = SEED.get('tickets', {}).get(kind)
        if ticket:
            granted(f'Vé {kind.upper()} hợp lệ → granted=true', call('POST', '/device/access/phone/', {
                'channel': ch, 'ticket': ticket, 'ok': True, 'at': int(time.time())}, headers=ha,
                label='firmware-A'), True)
    granted('PIN sai → granted=false', call('POST', '/device/access/pin/', {'pin': '000000'}, headers=ha,
                                           label='firmware-A'), False)
    granted('RFID thẻ lạ → granted=false', call('POST', '/device/access/rfid/', {'uid': 'DEADBEEF'}, headers=ha,
                                               label='firmware-A'), False)
    check_db('2 lần sai trên khoá A chưa gây khoá tạm', not services.in_lockout(A))

    # ---- khoá C: kịch bản "quẹt thẻ lạ 3 lần -> khoá tạm + còi + báo chủ"
    pin_c = SEED['pins']['C_valid']['plain']
    granted('[C] PIN hợp lệ lần 1 → granted=true', call('POST', '/device/access/pin/', {'pin': pin_c}, headers=hc,
                                                        label='firmware-C'), True)
    granted('[C] PIN dùng-một-lần dùng lại → granted=false (sai #1)', call('POST', '/device/access/pin/', {
        'pin': pin_c}, headers=hc, label='firmware-C'), False)
    granted('[C] Vé BLE rác → granted=false (sai #2)', call('POST', '/device/access/phone/', {
        'channel': 'ble', 'ticket': 'sai.0.sai', 'ok': True}, headers=hc, label='firmware-C'), False)
    granted('[C] Thẻ lạ → granted=false (sai #3 → khoá tạm)', call('POST', '/device/access/rfid/', {
        'uid': 'BADC0DE1'}, headers=hc, label='firmware-C'), False)
    check_db('khoá C bị khoá tạm (AuditLog ACCESS_BURST_LOCKOUT)', M.AuditLog.objects.filter(
        device=C, action=services.LOCKOUT_ACTION).exists())
    check_db('còi BUZZER_ALERT được gửi (mock)', last_mqtt(C.device_code, 'BUZZER_ALERT') is not None)
    check_db('chủ nhà nhận thông báo ACCESS_BURST (critical)', M.Notification.objects.filter(
        user=owner['user'], device=C, type='ACCESS_BURST', severity='critical').exists())
    granted('[C] Đang khoá tạm: thẻ HỢP LỆ vẫn bị từ chối', call('POST', '/device/access/rfid/', {
        'uid': SEED['cards']['owner']['uid']}, headers=hc, label='firmware-C'), False)
    check_db('lý do từ chối = DEVICE_LOCKED_OUT', M.AccessEvent.objects.filter(
        device=C, reason='DEVICE_LOCKED_OUT', created_at__gte=T_TEST).exists())
    check('App thấy khoá C đang bị khoá tạm (locked_out)', call('GET', f'/devices/{C.id}/live/', who=owner), 200,
          ok=True, expect=lambda j: j.get('locked_out') is True or 'locked_out != true')
    granted('[A] Khoá A không bị ảnh hưởng: thẻ hợp lệ vẫn mở được', call('POST', '/device/access/rfid/', {
        'uid': SEED['cards']['family']['uid']}, headers=ha, label='firmware-A'), True)


def t_history_notifications():
    section('10. Lịch sử ra vào / audit / thông báo / poll sự kiện')
    owner, family, viewer, stranger = (PERSONS[k] for k in ('owner', 'family', 'viewer', 'stranger'))
    aid = str(DEVS['A']['obj'].id)
    check('GET /history/ (owner)', call('GET', '/history/?page=1&page_size=50', who=owner), 200, ok=True,
          expect=lambda j: len(first_list(j)) >= 10 or f'chỉ có {len(first_list(j))} dòng lịch sử')
    check('GET /history/?method=PIN&success=1', call('GET', '/history/?method=PIN&success=1&page_size=50', who=owner),
          200, ok=True, expect=lambda j: (len(first_list(j)) >= 1 and all(
              e.get('method') == 'PIN' and e.get('success') is True for e in first_list(j)))
          or 'bộ lọc method/success trả sai dữ liệu')
    check('GET /history/?device=A', call('GET', f'/history/?device={aid}&page_size=50', who=owner), 200, ok=True,
          expect=lambda j: all(e.get('device_id') == aid for e in first_list(j)) or 'lẫn khoá khác')
    check('GET /history/ (viewer có view_history)', call('GET', '/history/', who=viewer), 200, ok=True,
          expect=lambda j: len(first_list(j)) >= 1 or 'viewer không thấy lịch sử')
    check('GET /history/ (stranger: rỗng)', call('GET', '/history/', who=stranger), 200, ok=True,
          expect=lambda j: len(first_list(j)) == 0 or 'stranger thấy lịch sử của khoá khác')
    check('Phân trang sai → 400', call('GET', '/history/?page=abc', who=owner), 400, ok=False)
    check('GET /audit/ (owner)', call('GET', '/audit/?page=1&page_size=50', who=owner), 200, ok=True,
          expect=lambda j: len(first_list(j)) >= 5 or f'chỉ có {len(first_list(j))} dòng audit')

    r = call('GET', '/notifications/', who=owner)
    check('GET /notifications/ (có chưa đọc)', r, 200, ok=True,
          expect=lambda j: j.get('unread_count', 0) >= 1 or 'unread_count = 0')
    items = first_list(r[1])
    check('GET /notifications/?unread=1', call('GET', '/notifications/?unread=1', who=owner), 200, ok=True,
          expect=lambda j: all(n.get('is_read') is False for n in first_list(j)) or 'lẫn thông báo đã đọc')
    some = [n['id'] for n in items[:2]]
    check('Đánh dấu đã đọc theo ids', call('POST', '/notifications/read/', {'ids': some}, who=owner), 200, ok=True)
    check('Đánh dấu đã đọc: thiếu tham số → 400', call('POST', '/notifications/read/', {}, who=owner), 400, ok=False,
          code='MISSING_FIELD')
    check('Đánh dấu đã đọc tất cả', call('POST', '/notifications/read/', {'all': True}, who=owner), 200, ok=True,
          expect=lambda j: j.get('unread_count') == 0 or f'unread_count={j.get("unread_count")}')
    if items:
        check('Xoá 1 thông báo → 200', call('DELETE', f'/notifications/{items[0]["id"]}/', who=owner), 200, ok=True)
        check('Xoá lại thông báo đó → 404', call('DELETE', f'/notifications/{items[0]["id"]}/', who=owner), 404,
              ok=False)
    check('Xoá tất cả thông báo đã đọc', call('DELETE', '/notifications/', who=owner), 200, ok=True,
          expect=lambda j: j.get('deleted', 0) >= 1 or 'không xoá được dòng nào')
    r = call('GET', '/events/', who=owner)
    check('GET /events/ lần đầu (cursor)', r, 200, ok=True, expect=lambda j: bool(j.get('cursor')) or 'thiếu cursor')
    cursor = jget(r[1], 'cursor')
    services.notify(owner['user'], 'Sự kiện poll mẫu', 'Tạo từ check_api để thử /events/.', type_='SYSTEM')
    check('GET /events/?cursor=... nhận thông báo mới', call('GET', f'/events/?cursor={cursor}', who=owner), 200,
          ok=True, expect=lambda j: any('poll mẫu' in e.get('title', '') for e in j.get('events', []))
          or 'không nhận được thông báo mới')


def t_shares_claim():
    section('11. Chia sẻ khoá / rời khỏi khoá / claim khoá')
    owner, family, viewer, stranger = (PERSONS[k] for k in ('owner', 'family', 'viewer', 'stranger'))
    A, B = DEVS['A']['obj'], DEVS['B']['obj']
    aid = str(A.id)
    check('GET /permissions/ (danh mục quyền)', call('GET', '/permissions/', who=owner), 200, ok=True, expect=lambda j: (
        len(j.get('groups', [])) >= 4 and 'family' in (j.get('role_presets') or {})
        or any(p.get('key') == 'family' for p in (j.get('role_presets') or []) if isinstance(p, dict)))
        or 'thiếu groups/role_presets')
    check('GET shares của khoá (owner)', call('GET', f'/devices/{aid}/shares/', who=owner), 200, ok=True,
          expect=lambda j: len(j.get('shares', [])) == 2 or f'{len(j.get("shares", []))} chia sẻ (cần 2)')
    check('GET shares bởi family → 403', call('GET', f'/devices/{aid}/shares/', who=family), 403, ok=False,
          code='OWNER_ONLY')
    exp = (timezone.now() + timedelta(days=1)).isoformat()
    n0 = len(MAILS)
    r = call('POST', f'/devices/{aid}/shares/', {'identifier': stranger['user'].email, 'preset': 'guest',
                                                  'expires_at': exp}, who=owner)
    check('Chia sẻ cho stranger (preset guest, hết hạn 1 ngày) → 201', r, 201, ok=True,
          expect=lambda j: j.get('created') is True or 'created != true')
    share_id = jget(r[1], 'share', 'id')
    check_db('email báo chia sẻ được gửi (mock)', any(m['to'] == stranger['user'].email for m in MAILS[n0:]))
    check_db('stranger nhận thông báo trong app', M.Notification.objects.filter(
        user=stranger['user'], created_at__gte=T_TEST).exists())
    check('Chia sẻ lại cùng người → cập nhật (200)', call('POST', f'/devices/{aid}/shares/', {
        'identifier': stranger['user'].username, 'preset': 'viewer'}, who=owner), 200, ok=True,
        expect=lambda j: j.get('created') is False or 'created != false')
    check('Chia sẻ cho chính mình → 400', call('POST', f'/devices/{aid}/shares/', {
        'identifier': owner['user'].email, 'preset': 'guest'}, who=owner), 400, ok=False, code='SELF_SHARE')
    check('Chia sẻ user không tồn tại → 404', call('POST', f'/devices/{aid}/shares/', {
        'identifier': f'khong.co@{DOMAIN}', 'preset': 'guest'}, who=owner), 404, ok=False, code='USER_NOT_FOUND')
    check('Chia sẻ preset sai → 400', call('POST', f'/devices/{aid}/shares/', {
        'identifier': stranger['user'].email, 'preset': 'khong_co'}, who=owner), 400, ok=False, code='BAD_PRESET')
    check('Chia sẻ hết hạn trong quá khứ → 400', call('POST', f'/devices/{aid}/shares/', {
        'identifier': stranger['user'].email, 'preset': 'guest',
        'expires_at': (timezone.now() - timedelta(days=1)).isoformat()}, who=owner), 400, ok=False, code='BAD_DATETIME')
    check('Chia sẻ không chọn quyền → 400', call('POST', f'/devices/{aid}/shares/', {
        'identifier': stranger['user'].email}, who=owner), 400, ok=False, code='MISSING_FIELD')
    check('Family chia sẻ lại → 403', call('POST', f'/devices/{aid}/shares/', {
        'identifier': stranger['user'].email, 'preset': 'guest'}, who=family), 403, ok=False, code='OWNER_ONLY')
    check('stranger thấy khoá được chia sẻ (incoming)', call('GET', '/shares/incoming/', who=stranger), 200, ok=True,
          expect=lambda j: any(s['device_id'] == aid for s in j.get('shares', [])) or 'thiếu khoá được chia sẻ')
    check('GET /devices/ của stranger giờ có khoá A', call('GET', '/devices/', who=stranger), 200, ok=True,
          expect=lambda j: any(d['id'] == aid for d in j.get('devices', [])) or 'chưa thấy khoá A')
    check('PATCH quyền chia sẻ (owner) → family-preset', call('PATCH', f'/shares/{share_id}/', {'preset': 'family'},
                                                              who=owner), 200, ok=True,
          expect=lambda j: 'UNLOCK' in jget(j, 'share', 'permissions', default=[]) or 'chưa cập nhật quyền')
    check('Stranger rời khỏi khoá → 200', call('POST', f'/shares/{share_id}/leave/', who=stranger), 200, ok=True)
    check_db('owner được thông báo người dùng đã rời khoá', M.Notification.objects.filter(
        user=owner['user'], type='SHARE', created_at__gte=T_TEST).exists())
    check('Stranger không còn thấy khoá A', call('GET', f'/devices/{aid}/', who=stranger), 404, ok=False)

    # ---- claim khoá bằng code + secret
    b_code, b_secret = B.device_code, DEVS['B']['secret']
    touch('B')      # khoá mới vừa gửi tín hiệu -> đủ điều kiện claim (cần 'đang kết nối')
    check('Claim: secret sai → 400', call('POST', '/devices/claim/', {'device_code': b_code, 'secret': 'sai-secret'},
                                          who=stranger), 400, ok=False, code='BAD_CREDENTIALS')
    check('Claim khoá đã có chủ (đúng secret) → 409', call('POST', '/devices/claim/', {
        'device_code': A.device_code, 'secret': DEVS['A']['secret']}, who=stranger), 409, ok=False,
        code='ALREADY_OWNED')
    check('Claim khoá mới đúng code + secret → 201', call('POST', '/devices/claim/', {
        'device_code': b_code, 'secret': b_secret}, who=stranger), 201, ok=True,
        expect=lambda j: jget(j, 'device', 'is_owner') is True or 'stranger chưa là chủ')
    B.refresh_from_db()
    check_db('khoá B có chủ + online + đã đánh dấu mua', B.owner_id == stranger['user'].id and B.status == 'online'
             and B.is_purchased and B.purchased_at)
    check_db('thông báo "Đã thêm khoá vào tài khoản"', M.Notification.objects.filter(
        user=stranger['user'], device=B, type='DEVICE').exists())

    # ---- thu hồi quyền viewer (cuối cùng, sau khi viewer đã dùng xong)
    vs = M.DeviceAccess.objects.filter(device=A, user=viewer['user'], is_active=True).first()
    check('Owner thu hồi quyền của viewer → 200', call('DELETE', f'/shares/{vs.id}/', who=owner), 200, ok=True)
    check('Viewer sau thu hồi: không thấy khoá → 404', call('GET', f'/devices/{aid}/', who=viewer), 404, ok=False)
    check('Thu hồi quyền không tồn tại → 404', call('DELETE', f'/shares/{uuid.uuid4()}/', who=owner), 404, ok=False)


def t_logout():
    section('12. Đăng xuất')
    owner, tfa = PERSONS['owner'], PERSONS['tfa']
    check('Logout owner → 200', call('POST', '/auth/logout/', {}, who=owner), 200, ok=True)
    check('Sau logout token bị từ chối → 401', call('GET', '/me/', who=owner), 401, ok=False)
    check('Logout tất cả phiên (tfa) → 200', call('POST', '/auth/logout/', {'all': True}, who=tfa), 200, ok=True,
          expect=lambda j: j.get('revoked', 0) >= 2 or f'revoked={j.get("revoked")} (cần ≥ 2)')
    check('Token tfa cũ bị từ chối → 401', call('GET', '/me/', who=tfa), 401, ok=False)


# ================================================================ IN TOÀN BỘ LOG
def fmt_t(dt):
    return timezone.localtime(dt).strftime('%H:%M:%S') if dt else '--:--:--'


def short(obj, n=150):
    s = json.dumps(obj, ensure_ascii=False, default=str) if not isinstance(obj, str) else obj
    return s if len(s) <= n else s[:n - 1] + '…'


def dump_logs():
    out(f'\n{B}{"=" * 78}\n  NHẬT KÝ ĐẦY ĐỦ (in trước khi xoá khỏi database)\n{"=" * 78}{N}')

    section(f'A. HTTP request/response ({len(HTTP_LOG)})')
    for h in HTTP_LOG:
        col = G if h['status'] < 300 else (Y if h['status'] < 500 else R)
        out(f'  #{h["n"]:<3} {fmt_t(h["at"])} {h["who"]:<17} {h["method"]:<6} {h["path"][:58]:<58} '
            f'{col}{h["status"]}{N} {h["ms"]}ms')
        if h['req'] not in (None, {}, ''):
            out(f'        {D}→ {short(h["req"])}{N}')
        out(f'        {D}← {short(h["res"], 200)}{N}')

    section(f'B. Tin MQTT bị chặn - đáng lẽ publish ra broker ({len(MQTT_SENT)})')
    for m in MQTT_SENT:
        out(f'  {fmt_t(m["at"])}  topic≈{services.cmd_topic(m["device_code"])}  {short(mask(m["payload"]), 170)}')

    section(f'C. Email bị chặn - đáng lẽ gửi đi ({len(MAILS)})')
    for m in MAILS:
        out(f'  {fmt_t(m["at"])}  → {m["to"]}  | {m["subject"]}')

    sc = scope()
    ts = sc['AuditLog'].select_related('actor_user', 'target_user', 'device').order_by('created_at')
    section(f'D. AuditLog ({ts.count()})')
    for a in ts:
        who = (a.actor_user.username if a.actor_user_id else '-') + ('→' + a.target_user.username
                                                                    if a.target_user_id else '')
        out(f'  {fmt_t(a.created_at)} {a.severity:<8} {"ok " if a.success else "ERR"} {a.action:<26} {who:<34} '
            f'{(a.device.device_code if a.device_id else "-"):<13} {a.ip_address or "-"}  {D}{short(a.metadata, 90)}{N}')

    qs = sc['AccessEvent'].select_related('device', 'user').order_by('created_at')
    section(f'E. AccessEvent - lịch sử ra vào ({qs.count()})')
    for e in qs:
        out(f'  {fmt_t(e.created_at)} {e.device.device_code:<13} {e.method:<10} {"OK  " if e.success else "FAIL"} '
            f'{(e.reason or "-"):<24} {(e.user.username if e.user_id else "-"):<20} '
            f'{"conf=" + str(e.confidence) if e.confidence is not None else ""}')

    qs = sc['NfcLog'].select_related('device', 'user').order_by('created_at')
    section(f'F. NfcLog ({qs.count()})')
    for n in qs:
        out(f'  {fmt_t(n.created_at)} {(n.device.device_code if n.device_id else "-"):<13} {n.event_type:<20} '
            f'{"ok " if n.success else "ERR"} {(n.user.username if n.user_id else "-"):<20} {n.ip_address or "-"}')

    qs = sc['DeviceCommand'].select_related('device', 'issued_by').order_by('created_at')
    section(f'G. DeviceCommand ({qs.count()})')
    for c in qs:
        out(f'  {fmt_t(c.created_at)} {c.device.device_code:<13} {c.command_type:<8} {c.status:<13} '
            f'bởi {c.issued_by.username:<20} ack={fmt_t(c.acknowledged_at) if c.acknowledged_at else "-"}')

    qs = sc['Notification'].select_related('user').order_by('created_at')
    section(f'H. Notification ({qs.count()})')
    for n in qs:
        out(f'  {fmt_t(n.created_at)} {n.severity:<8} {"đã đọc " if n.is_read else "CHƯA ĐỌC"} {n.type:<13} '
            f'→ {n.user.username:<20} {n.title}')

    section(f'I. Các bảng khác: số dòng trước khi xoá')
    for k, v in count_all().items():
        out(f'  {k:<17}{v}')


# ================================================================ DỌN DẸP
def cleanup(perm_before):
    section('XOÁ DỮ LIỆU MẪU + LOG KHỎI DATABASE')
    errors = 0
    for name, qs in scope().items():
        try:
            n = qs.count()
            if n:
                qs.delete()
            out(f'  {G}xoá{N} {name:<17}{n} dòng')
        except Exception as exc:                                       # noqa: BLE001
            errors += 1
            out(f'  {R}LỖI{N} {name:<17}{type(exc).__name__}: {exc}')
    try:
        created = M.Permission.objects.filter(code__in=services.PERMISSION_CODES).exclude(code__in=perm_before)
        n = created.count()
        if n:
            created.delete()
        out(f'  {G}xoá{N} {"Permission":<17}{n} dòng (danh mục quyền do lần chạy này tạo)')
    except Exception as exc:                                           # noqa: BLE001
        errors += 1
        out(f'  {R}LỖI{N} Permission       {exc}')
    left = {k: v for k, v in count_all().items() if v}
    if left or errors:
        out(f'  {R}CÒN SÓT: {left}{N}  → chạy lại: python check_api.py --cleanup-only')
        return False
    out(f'  {G}Đã xác nhận: toàn bộ dữ liệu mẫu và log liên quan đều còn 0 dòng trong DB.{N}')
    return True


def confirm_db():
    db = settings.DATABASES['default']
    out(f'  Database : {db.get("ENGINE", "?").split(".")[-1]}  host={db.get("HOST") or "(local)"}  '
        f'name={db.get("NAME")}')
    out(f'  {D}Script sẽ GHI dữ liệu mẫu vào DB trên rồi xoá. MQTT/email/push bị chặn (mock).{N}')
    if ARGS.yes:
        return True
    try:
        return input('  Tiếp tục? (y/N): ').strip().lower() in ('y', 'yes', 'c', 'co', 'có')
    except EOFError:
        return False


# ================================================================ MAIN
def main():
    global ARGS, T_TEST, rnd
    ap = argparse.ArgumentParser(description='Kiểm thử API Smart Lock: tự tạo dữ liệu mẫu → test → in log → xoá.')
    ap.add_argument('--yes', '-y', action='store_true', help='không hỏi xác nhận')
    ap.add_argument('--keep', action='store_true', help='không xoá dữ liệu mẫu sau khi test')
    ap.add_argument('--cleanup-only', action='store_true', help='chỉ dọn dữ liệu mẫu còn sót lại')
    ap.add_argument('--seed', type=int, default=None, help='hạt giống cho dữ liệu ngẫu nhiên')
    ap.add_argument('--log-file', default=None, help='ghi thêm toàn bộ output ra file')
    ARGS = ap.parse_args()
    rnd = random.Random(ARGS.seed)

    out(f'{B}==============  SMART LOCK API CHECK (tự tạo dữ liệu → test → log → xoá)  =============={N}')
    try:
        load_django()
    except Exception as exc:                                           # noqa: BLE001
        out(f'{R}Không nạp được Django: {type(exc).__name__}: {exc}{N}')
        out('Hãy chạy script ở thư mục chứa manage.py, đúng venv, và có file .env đầy đủ.')
        return 2
    if not confirm_db():
        out('Đã huỷ.')
        return 0
    perm_before = set(M.Permission.objects.values_list('code', flat=True))

    if ARGS.cleanup_only:
        ok_ = cleanup(perm_before)
        return 0 if ok_ else 2

    leftovers = {k: v for k, v in count_all().items() if v}
    if leftovers:
        out(f'{Y}Phát hiện dữ liệu mẫu còn sót từ lần trước {leftovers} → dọn trước khi chạy.{N}')
        cleanup(perm_before)

    t_start = time.time()
    try:
        section('TẠO DỮ LIỆU MẪU')
        seed_all()
        T_TEST = timezone.now()
        print_seed_summary()
        for fn in (t_public, t_register, t_auth, t_account, t_devices, t_pins, t_cards_readers, t_faces,
                   t_firmware, t_history_notifications, t_shares_claim, t_logout):
            try:
                fn()
            except KeyboardInterrupt:
                raise
            except Exception as exc:                                   # noqa: BLE001
                import traceback
                record(False, f'{fn.__name__} bị lỗi script', f'{type(exc).__name__}: {exc}')
                out(D + traceback.format_exc() + N)
    except KeyboardInterrupt:
        out(f'\n{Y}Bị ngắt (Ctrl+C) - vẫn in log và dọn dữ liệu...{N}')
    except Exception as exc:                                           # noqa: BLE001
        import traceback
        record(False, 'Lỗi khi tạo dữ liệu mẫu', f'{type(exc).__name__}: {exc}')
        out(D + traceback.format_exc() + N)
    finally:
        try:
            dump_logs()
        except Exception as exc:                                       # noqa: BLE001
            out(f'{R}Không in được log: {type(exc).__name__}: {exc}{N}')
        cleaned = True
        if ARGS.keep:
            out(f'\n{Y}--keep: giữ nguyên dữ liệu mẫu. Xoá sau bằng: python check_api.py --cleanup-only{N}')
        else:
            cleaned = cleanup(perm_before)

    total = stats['pass'] + stats['fail']
    out(f'\n{B}== KẾT QUẢ =={N}  {G}đạt {stats["pass"]}/{total}{N}  '
        f'{R if stats["fail"] else D}lỗi {stats["fail"]}{N}  {Y}bỏ qua {stats["skip"]}{N}  '
        f'{D}({time.time() - t_start:.1f}s, {len(HTTP_LOG)} request){N}')
    for f in failures:
        out(f'  {R}- {f}{N}')
    if ARGS.log_file:
        try:
            Path(ARGS.log_file).write_text('\n'.join(OUT_BUF), encoding='utf-8')
            print(f'Đã ghi log ra {ARGS.log_file}')
        except OSError as exc:
            print(f'Không ghi được file log: {exc}')
    if not cleaned:
        return 2
    return 1 if stats['fail'] else 0


if __name__ == '__main__':
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print('\nTạm biệt!')
        sys.exit(130)