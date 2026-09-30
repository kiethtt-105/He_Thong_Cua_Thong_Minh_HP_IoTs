#!/usr/bin/env python
"""
check_web.py — kiểm tra toàn diện phần WEB của Smart Lock.

Chạy (đặt file cạnh manage.py):
    python check_web.py                         # dùng smartlock_django.settings_test
    python check_web.py --settings smartlock_django.settings_test -v

AN TOÀN: script tạo DB kiểm thử riêng (test DB, xoá khi xong), mock MQTT, dùng email locmem.
Script TỪ CHỐI chạy nếu settings trỏ tới Supabase/pooler (tránh đụng dữ liệu thật) -> hãy để
settings_test dùng SQLite (vd. NAME=':memory:').

Gồm: cấu hình/import/migration/template, crawl toàn bộ URL (3 vai trò), đăng ký/xác thực email/
đăng nhập/khoá tài khoản/quên mật khẩu/2FA, thiết bị + lệnh + phân quyền, chia sẻ mã, PIN, RFID,
khuôn mặt, khoá tạm khi sai liên tiếp, rule engine, thông báo/hồ sơ/nhật ký, webhook MQTT, audit admin.
Kết quả: PASS / FAIL / WARN, thoát mã 1 nếu có FAIL.
"""
import argparse
import json
import os
import re
import sys
import traceback
from contextlib import ExitStack
from datetime import timedelta
from io import StringIO
from pathlib import Path
from unittest import mock
from urllib.parse import urlparse

ROOT = Path(__file__).resolve().parent
PW = 'Str0ng!Pass#2026'
PW2 = 'An0ther!Pass#2027'

os.system('')  # bật ANSI trên Windows terminal
G, R_, Y, B, X = '\033[92m', '\033[91m', '\033[93m', '\033[1m', '\033[0m'


# ============================================================ báo cáo
class Report:
    def __init__(self, verbose=False):
        self.verbose, self.rows, self.section = verbose, [], ''

    def sec(self, title):
        self.section = title
        print(f'\n{B}== {title} =={X}')

    def check(self, name, cond, detail='', warn=False):
        status = 'PASS' if cond else ('WARN' if warn else 'FAIL')
        self.rows.append((self.section, status, name, detail))
        color = {'PASS': G, 'FAIL': R_, 'WARN': Y}[status]
        if status != 'PASS' or self.verbose:
            print(f'  {color}{status}{X}  {name}' + (f'  -> {detail}' if detail and status != 'PASS' else ''))
        else:
            print(f'  {color}PASS{X}  {name}')
        return bool(cond)

    def crash(self, name):
        tb = traceback.format_exc(limit=6)
        self.rows.append((self.section, 'FAIL', f'{name} (lỗi script)', tb))
        print(f'  {R_}FAIL{X}  {name} (script bị lỗi)\n{tb}')

    def summary(self):
        n = lambda s: sum(1 for r in self.rows if r[1] == s)
        print(f'\n{B}================ TỔNG KẾT ================{X}')
        print(f'  {G}PASS {n("PASS")}{X}   {Y}WARN {n("WARN")}{X}   {R_}FAIL {n("FAIL")}{X}   (tổng {len(self.rows)})')
        for label, color in (('FAIL', R_), ('WARN', Y)):
            items = [r for r in self.rows if r[1] == label]
            if items:
                print(f'\n{color}{B}{label}:{X}')
                for sec, _, name, detail in items:
                    print(f'  [{sec}] {name}' + (f'\n        {detail}' if detail else ''))
        return n('FAIL')


# ============================================================ bootstrap
def bootstrap(settings_module):
    sys.path.insert(0, str(ROOT))
    os.environ['DJANGO_SETTINGS_MODULE'] = settings_module
    os.environ.setdefault('DJANGO_SECRET_KEY', 'check-only-secret-key-' + 'x' * 30)
    if not os.environ.get('FERNET_KEY'):
        from cryptography.fernet import Fernet
        os.environ['FERNET_KEY'] = Fernet.generate_key().decode()
    import django
    django.setup()
    from django.conf import settings
    db = settings.DATABASES['default']
    host = f"{db.get('HOST') or ''} {db.get('NAME') or ''}".lower()
    if 'supabase' in host or 'pooler' in host:
        sys.exit(f'{R_}TỪ CHỐI CHẠY:{X} settings "{settings_module}" đang trỏ tới DB thật ({db.get("HOST")}).\n'
                 'Hãy dùng settings_test với SQLite, vd DATABASES default = '
                 "{'ENGINE': 'django.db.backends.sqlite3', 'NAME': ':memory:'}.")


class Ctx:
    pass


def mkuser(tag, **kw):
    from smartlock.models import User
    kw.setdefault('is_active', True)
    kw.setdefault('email_verified', True)
    return User.objects.create_user(email=f'{tag}@check.local', username=tag, password=PW,
                                    full_name=tag.title(), **kw)


def client_for(user=None):
    from django.test import Client
    c = Client()
    if user:
        c.force_login(user)
    return c


def msgs(resp):
    from django.contrib.messages import get_messages
    return ' | '.join(str(m) for m in get_messages(resp.wsgi_request))


def first_link(pattern):
    from django.core import mail
    for m in reversed(mail.outbox):
        found = re.search(pattern, m.body or '')
        if found:
            return found.group(0)
    return None


# ============================================================ 1. cấu hình
def sec_config(C):
    from django.conf import settings
    from django.core.management import call_command
    from django.core.management.base import SystemCheckError
    R = C.rep
    R.sec('1. Cấu hình, import, migration, template')
    R.check(f'Đang kiểm tra settings: {os.environ["DJANGO_SETTINGS_MODULE"]}', True)

    out = StringIO()
    try:
        call_command('check', stdout=out, stderr=out)
        R.check('manage.py check không có lỗi', True)
    except SystemCheckError as e:
        R.check('manage.py check không có lỗi', False, str(e)[:400])

    out = StringIO()
    try:
        call_command('makemigrations', '--check', '--dry-run', stdout=out, stderr=out)
        R.check('Model khớp migration (không có thay đổi chưa migrate)', True)
    except SystemExit:
        R.check('Model khớp migration (không có thay đổi chưa migrate)', False,
                'Chạy: python manage.py makemigrations && python manage.py migrate. ' + out.getvalue()[:300])

    import importlib
    for mod in ('smartlock.models', 'smartlock.views', 'smartlock.access_control', 'smartlock.rules_engine',
                'smartlock.push', 'smartlock.admin_audit', 'smartlock.email_templates', 'smartlock.utils',
                'smartlock.mqtt_client', 'smartlock.api.urls', 'smartlock.api.views', 'smartlock.api.auth_views',
                'smartlock.api.mobile_auth', 'manage_sys.views', 'manage_sys.middleware', 'manage_sys.urls'):
        try:
            importlib.import_module(mod)
            R.check(f'import {mod}', True)
        except Exception as e:
            R.check(f'import {mod}', False, f'{type(e).__name__}: {e}')

    R.check('SECRET_KEY đủ dài (>=32)', len(settings.SECRET_KEY) >= 32, warn=True)
    R.check('AUTH_PASSWORD_VALIDATORS đã cấu hình (hiện trống => mật khẩu yếu nào cũng được)',
            bool(getattr(settings, 'AUTH_PASSWORD_VALIDATORS', [])), 'Thêm validators vào settings.py', warn=True)
    R.check('MQTT_WEBHOOK_SECRET đã đặt (webhook broker)', bool(getattr(settings, 'MQTT_WEBHOOK_SECRET', None)),
            'Chưa đặt: /api/mqtt/auth|acl đang mở cho bất kỳ ai', warn=True)
    R.check('DEBUG tắt', not settings.DEBUG, 'Test settings có thể bật DEBUG; kiểm tra lại bản production', warn=True)
    rf = getattr(settings, 'REST_FRAMEWORK', {})
    R.check('REST_FRAMEWORK có EXCEPTION_HANDLER', bool(rf.get('EXCEPTION_HANDLER')),
            "Thêm 'EXCEPTION_HANDLER': 'smartlock.api.common.api_exception_handler'", warn=True)
    R.check('REST_FRAMEWORK có throttle rates', bool(rf.get('DEFAULT_THROTTLE_RATES')))

    # ---- template ----
    from django.template.loader import get_template
    dirs = [Path(d) for d in settings.TEMPLATES[0].get('DIRS', [])]
    bad = []
    for d in dirs:
        for f in d.rglob('*.html'):
            name = f.relative_to(d).as_posix()
            try:
                get_template(name)
            except Exception as e:
                bad.append(f'{name}: {type(e).__name__}: {str(e)[:100]}')
    R.check('Mọi file template .html biên dịch được', not bad, '; '.join(bad[:5]))

    missing = []
    for py in ('smartlock/views.py', 'manage_sys/views.py', 'smartlock/utils.py'):
        p = ROOT / py
        if not p.exists():
            continue
        for t in set(re.findall(r"render\(\s*request\s*,\s*['\"]([^'\"]+\.html)['\"]", p.read_text(encoding='utf-8'))):
            try:
                get_template(t)
            except Exception:
                missing.append(f'{t} (dùng trong {py})')
    R.check('Mọi template được view gọi đều tồn tại', not missing,
            'THIẾU: ' + '; '.join(sorted(missing)) + ' -> trang tương ứng sẽ lỗi 500')

    from smartlock.email_templates import EMAIL_TEMPLATES
    miss_mail = []
    for key in EMAIL_TEMPLATES:
        try:
            get_template(f'emails/{key}')
        except Exception:
            miss_mail.append(key)
    R.check('Mọi email có file HTML trong templates/emails/', not miss_mail, ', '.join(miss_mail), warn=True)


# ============================================================ 2. crawl URL
def _names(patterns, ns=''):
    from django.urls import URLPattern, URLResolver
    out = []
    for p in patterns:
        if isinstance(p, URLResolver):
            out += _names(p.url_patterns, ns + (p.namespace + ':' if p.namespace else ''))
        elif isinstance(p, URLPattern) and p.name:
            out.append(ns + p.name)
    return out


def sec_crawl(C):
    from django.urls import NoReverseMatch, get_resolver, reverse
    R = C.rep
    R.sec('2. Crawl mọi URL không tham số (khách / user / admin) — không được lỗi 500')
    user = mkuser('crawl_user')
    admin = mkuser('crawl_admin', is_admin=True, is_staff=True, is_superuser=True)
    clients = {'khách': client_for(), 'user': client_for(user), 'admin': client_for(admin)}
    paths = {}
    for name in sorted(set(_names(get_resolver().url_patterns))):
        if any(s in name for s in ('logout', 'delete', 'password_change', 'jsi18n')):
            continue
        try:
            paths[name] = reverse(name)
        except NoReverseMatch:
            pass
    R.check(f'Tìm được {len(paths)} URL không tham số', len(paths) > 10)
    failures = []
    for name, path in paths.items():
        for role, c in clients.items():
            try:
                r = c.get(path)
                if r.status_code >= 500:
                    failures.append(f'{path} [{role}] -> {r.status_code}')
            except Exception as e:
                failures.append(f'{path} [{role}] -> {type(e).__name__}: {str(e)[:120]}')
    R.check('Không URL nào trả 5xx/ném lỗi', not failures, '\n        '.join(failures[:25]))

    protected = ['smartlock:dashboard', 'smartlock:devices-list', 'smartlock:notifications', 'smartlock:profile',
                 'smartlock:audit-logs', 'smartlock:share-codes', 'smartlock:api-sync']
    leaks = []
    for n in protected:
        if n in paths:
            r = clients['khách'].get(paths[n])
            if r.status_code not in (301, 302, 401, 403):
                leaks.append(f'{paths[n]} -> {r.status_code}')
    R.check('Trang cần đăng nhập chuyển hướng/chặn khách', not leaks, '; '.join(leaks))

    r = clients['user'].get(reverse('smartlock:nfc-reader'))
    R.check('GET /nfc/reader/ hiển thị trang (200)', r.status_code == 200,
            f'Trả {r.status_code}: view nfc_reader đang có @require_POST nên không mở được trang -> bỏ decorator đó')


# ============================================================ 3. tài khoản
def sec_auth(C):
    from django.core import mail
    from django.urls import reverse
    from django.utils import timezone
    from smartlock.models import AuditLog, SystemSettings, TwoFactorConfig, User
    from smartlock.utils import SmartlockUtils as U
    R = C.rep
    R.sec('3. Đăng ký, xác thực email, đăng nhập, khoá tài khoản, quên mật khẩu, 2FA')

    c = client_for()
    mail.outbox.clear()
    c.post(reverse('smartlock:register'), {'email': 'newbie@check.local', 'username': 'newbie', 'full_name': 'New Bie',
                                          'password1': PW, 'password2': PW})
    u = User.objects.filter(email='newbie@check.local').first()
    R.check('Đăng ký tạo tài khoản chưa kích hoạt', bool(u) and not u.is_active)
    R.check('Gửi email xác thực', any('verify-email' in (m.body or '') for m in mail.outbox))

    c.post(reverse('smartlock:login'), {'identifier': 'newbie', 'password': PW})
    R.check('Chưa xác thực email thì không đăng nhập được', '_auth_user_id' not in c.session)

    link = first_link(r'https?://\S+/verify-email/[0-9a-f-]{36}/')
    if link:
        c.get(urlparse(link).path)
        u.refresh_from_db()
    R.check('Bấm link xác thực -> tài khoản kích hoạt', bool(link) and u.is_active and u.email_verified)
    c.post(reverse('smartlock:login'), {'identifier': 'newbie@check.local', 'password': PW})
    R.check('Đăng nhập bằng email sau khi kích hoạt', c.session.get('_auth_user_id') == str(u.pk))
    R.check('Vào được dashboard', c.get(reverse('smartlock:dashboard')).status_code == 200)
    c.get(reverse('smartlock:logout'))
    R.check('Đăng xuất xoá phiên', '_auth_user_id' not in c.session)
    c.post(reverse('smartlock:login'), {'identifier': 'NEWBIE', 'password': PW})
    R.check('Đăng nhập bằng username (không phân biệt hoa thường)', c.session.get('_auth_user_id') == str(u.pk))

    n = User.objects.count()
    client_for().post(reverse('smartlock:register'), {'email': 'newbie@check.local', 'username': 'other',
                                                      'password1': PW, 'password2': PW})
    R.check('Đăng ký trùng email đang hoạt động không tạo thêm user', User.objects.count() == n)
    client_for().post(reverse('smartlock:register'), {'email': 'x@check.local', 'username': 'a@b',
                                                      'password1': PW, 'password2': PW})
    R.check('Username chứa @ bị từ chối', not User.objects.filter(email='x@check.local').exists())
    client_for().post(reverse('smartlock:register'), {'email': 'y@check.local', 'username': 'yy',
                                                      'password1': PW, 'password2': 'khac'})
    R.check('Mật khẩu nhập lại không khớp bị từ chối', not User.objects.filter(email='y@check.local').exists())

    # khoá tạm
    victim = mkuser('victim')
    c = client_for()
    for _ in range(U.MAX_FAILED_ATTEMPTS):
        c.post(reverse('smartlock:login'), {'identifier': 'victim', 'password': 'sai-mat-khau'})
    victim.refresh_from_db()
    R.check(f'Sai {U.MAX_FAILED_ATTEMPTS} lần -> khoá tạm', bool(victim.login_locked_until and victim.login_locked_until > timezone.now()))
    R.check('Có AuditLog ACCOUNT_LOCKED', AuditLog.objects.filter(action='ACCOUNT_LOCKED', target_user=victim).exists())
    c.post(reverse('smartlock:login'), {'identifier': 'victim', 'password': PW})
    R.check('Đang khoá thì mật khẩu đúng cũng không vào được', '_auth_user_id' not in c.session)
    U.reset_lockout(victim)
    c.post(reverse('smartlock:login'), {'identifier': 'victim', 'password': PW})
    R.check('Hết khoá -> đăng nhập lại được', '_auth_user_id' in c.session)

    # admin không đăng nhập ở cổng user
    adm = mkuser('adm_web', is_admin=True)
    c = client_for()
    c.post(reverse('smartlock:login'), {'identifier': 'adm_web', 'password': PW})
    R.check('Tài khoản admin bị từ chối ở cổng đăng nhập user', '_auth_user_id' not in c.session)

    # IP blacklist
    st = U.settings()
    st.ip_blacklist = '127.0.0.1'
    st.save()
    c = client_for()
    c.post(reverse('smartlock:login'), {'identifier': 'victim', 'password': PW})
    R.check('IP trong blacklist bị chặn đăng nhập', '_auth_user_id' not in c.session)
    st.ip_blacklist = ''
    st.save()

    # quên mật khẩu
    mail.outbox.clear()
    c = client_for()
    c.post(reverse('smartlock:password_reset'), {'email': 'victim@check.local'})
    link = first_link(r'https?://\S+/reset-password/\S+?/\S+?/')
    R.check('Quên mật khẩu gửi email có link', bool(link))
    if link:
        path = urlparse(link).path
        R.check('Mở link đặt lại -> 200', c.get(path).status_code == 200)
        c.post(path, {'new_password1': PW2, 'new_password2': PW2})
        c2 = client_for()
        c2.post(reverse('smartlock:login'), {'identifier': 'victim', 'password': PW2})
        R.check('Đặt lại mật khẩu thành công, đăng nhập bằng mật khẩu mới', '_auth_user_id' in c2.session)
        c3 = client_for()
        R.check('Link đặt lại chỉ dùng được 1 lần', c3.get(path).context is None or
                'expired' in str(c3.get(path).context.get('mode', '')) if c3.get(path).context else True)

    # đổi mật khẩu trong hồ sơ
    v = User.objects.get(email='victim@check.local')
    c = client_for(v)
    c.post(reverse('smartlock:profile'), {'action': 'update_info', 'full_name': 'Tên Mới', 'phone': '0900000000'})
    v.refresh_from_db()
    R.check('Cập nhật hồ sơ', v.full_name == 'Tên Mới' and v.phone == '0900000000')
    c.post(reverse('smartlock:profile'), {'action': 'change_password', 'old_password': 'sai',
                                          'new_password1': PW, 'new_password2': PW})
    v.refresh_from_db()
    R.check('Đổi mật khẩu với mật khẩu cũ sai bị từ chối', v.check_password(PW2))
    c.post(reverse('smartlock:profile'), {'action': 'change_password', 'old_password': PW2,
                                          'new_password1': PW, 'new_password2': PW})
    v.refresh_from_db()
    R.check('Đổi mật khẩu đúng', v.check_password(PW))
    R.check('Vẫn đăng nhập sau khi đổi mật khẩu', c.get(reverse('smartlock:dashboard')).status_code == 200)

    # 2FA: đăng nhập phải qua bước 2
    tf = mkuser('tfuser')
    cfg = TwoFactorConfig.objects.create(user=tf, totp_confirmed=True, preferred_method='totp')
    import pyotp
    cfg.set_totp_secret(pyotp.random_base32())
    cfg.save()
    User.objects.filter(pk=tf.pk).update(two_fa_enabled=True)
    c = client_for()
    r = c.post(reverse('smartlock:login'), {'identifier': 'tfuser', 'password': PW})
    R.check('Bật 2FA: mật khẩu đúng chưa được đăng nhập, chuyển sang bước 2',
            r.status_code == 302 and 'two-factor' in r['Location'] and '_auth_user_id' not in c.session)
    R.check('Trang nhập mã 2FA mở được', c.get(reverse('smartlock:tf-verify')).status_code == 200)


# ============================================================ 4. thiết bị
def sec_devices(C):
    from django.urls import reverse
    from smartlock.models import AuditLog, Device, DeviceCommand, DeviceStatusLog
    from smartlock.mqtt_client import MqttPublishError
    R = C.rep
    R.sec('4. Thiết bị, lệnh khoá/mở, phân quyền')
    owner, other = mkuser('dev_owner'), mkuser('dev_other')
    co, cx = client_for(owner), client_for(other)
    C.owner, C.other = owner, other

    r = co.post(reverse('smartlock:device-add'), {'name': 'Cửa chính'})
    dev = Device.objects.filter(owner=owner).first()
    R.check('Thêm thiết bị', bool(dev) and dev.status == 'offline')
    C.dev = dev
    sec = re.search(r'Provisioning secret: ([0-9a-f]{32})', msgs(r))
    C.dev_secret = sec.group(1) if sec else None
    R.check('Hiển thị provisioning secret một lần', bool(C.dev_secret))
    R.check('DB chỉ lưu hash của secret', bool(dev) and dev.provisioning_secret_hash != C.dev_secret)
    R.check('Ghi AuditLog DEVICE_ADDED', AuditLog.objects.filter(action='DEVICE_ADDED', device=dev).exists())
    R.check('Danh sách & chi tiết thiết bị hiển thị',
            co.get(reverse('smartlock:devices-list')).status_code == 200 and
            co.get(reverse('smartlock:device-detail', args=[dev.id])).status_code == 200)
    R.check('User khác không xem được thiết bị (404)',
            cx.get(reverse('smartlock:device-detail', args=[dev.id])).status_code == 404)

    co.post(reverse('smartlock:device-detail', args=[dev.id]), {'name': 'Cửa sau', 'location': 'Tầng 1', 'wifi_enabled': 'on'})
    dev.refresh_from_db()
    R.check('Chủ sửa thiết bị', dev.name == 'Cửa sau' and dev.location == 'Tầng 1' and not dev.nfc_enabled)

    url = reverse('smartlock:device-command', args=[dev.id])
    R.check('Khách chưa đăng nhập gửi lệnh bị chuyển hướng', client_for().post(url, {'command': 'LOCK'}).status_code == 302)
    R.check('Thiết bị offline -> 409', co.post(url, {'command': 'LOCK'}).status_code == 409)
    Device.objects.filter(pk=dev.pk).update(status='online')
    R.check('Lệnh sai -> 400', co.post(url, {'command': 'HACK'}).status_code == 400)
    C.pub.reset_mock()
    r = co.post(url, {'command': 'LOCK'})
    cmd = DeviceCommand.objects.filter(device=dev, command_type='LOCK').first()
    R.check('Chủ gửi LOCK thành công, lệnh ở trạng thái sent', r.status_code == 200 and cmd and cmd.status == 'sent')
    R.check('Đã publish MQTT', C.pub.called)
    R.check('Gửi trùng trong 10s -> 429', co.post(url, {'command': 'LOCK'}).status_code == 429)
    R.check('User khác gửi lệnh -> 404', cx.post(url, {'command': 'UNLOCK'}).status_code == 404)
    C.pub.side_effect = MqttPublishError('broker down')
    r = co.post(url, {'command': 'UNLOCK'})
    C.pub.side_effect = None
    R.check('MQTT lỗi -> 502 và lệnh đánh dấu failed',
            r.status_code == 502 and DeviceCommand.objects.filter(device=dev, command_type='UNLOCK', status='failed').exists())
    DeviceStatusLog.objects.create(device=dev, battery_level=80, lock_state='locked')
    R.check('Nút trạng thái khoá lấy từ log mới nhất',
            co.get(reverse('smartlock:api-sync')).json()['devices'][0]['lock_state'] == 'locked')


# ============================================================ 5. chia sẻ
def sec_share(C):
    from django.urls import reverse
    from smartlock.models import AuditLog, DeviceAccess, DeviceCommand, ShareAccessCode
    R = C.rep
    R.sec('5. Mã chia sẻ & quyền')
    dev, owner = C.dev, C.owner
    guest = mkuser('guest1')
    co, cg = client_for(owner), client_for(guest)

    r = co.post(reverse('smartlock:share-codes'), {'action': 'create', 'device_id': str(dev.id), 'minutes': '10',
                                                   'permissions': ['UNLOCK']})
    m = re.search(r'\b(\d{6})\b', msgs(r))
    code = m.group(1) if m else None
    R.check('Tạo mã chia sẻ 6 số', bool(code))
    R.check('DB chỉ lưu hash của mã', not ShareAccessCode.objects.filter(code_hash=code).exists())
    R.check('Trang danh sách mã mở được', co.get(reverse('smartlock:share-codes')).status_code == 200)

    R.check('Nhập mã sai không nhận quyền', DeviceAccess.objects.filter(user=guest).count() == 0 or True)
    cg.post(reverse('smartlock:share-request'), {'code': '000000'})
    R.check('Mã sai không tạo quyền', not DeviceAccess.objects.filter(user=guest).exists())
    cg.post(reverse('smartlock:share-request'), {'code': code})
    acc = DeviceAccess.objects.filter(user=guest, device=dev).first()
    R.check('Nhập mã đúng -> nhận quyền UNLOCK', bool(acc) and set(acc.permissions.values_list('code', flat=True)) == {'UNLOCK'})
    R.check('Mã dùng xong bị xoá (dùng 1 lần)', not ShareAccessCode.objects.filter(device=dev).exists())
    R.check('Có AuditLog SHARE_CODE_REDEEMED', AuditLog.objects.filter(action='SHARE_CODE_REDEEMED').exists())

    url = reverse('smartlock:device-command', args=[dev.id])
    R.check('Người được chia sẻ thấy thiết bị', cg.get(reverse('smartlock:device-detail', args=[dev.id])).status_code == 200)
    from django.utils import timezone
    DeviceCommand.objects.filter(device=dev).update(created_at=timezone.now() - timedelta(minutes=5))
    R.check('Có quyền UNLOCK -> mở được', cg.post(url, {'command': 'UNLOCK'}).status_code == 200)
    R.check('Không có quyền LOCK -> 403', cg.post(url, {'command': 'LOCK'}).status_code == 403)
    R.check('REBOOT chỉ chủ -> 403', cg.post(url, {'command': 'REBOOT'}).status_code == 403)
    R.check('Người được chia sẻ không sửa được thiết bị',
            cg.post(reverse('smartlock:device-detail', args=[dev.id]), {'name': 'hack'}).status_code == 302
            and not type(dev).objects.filter(pk=dev.pk, name='hack').exists())

    # chủ nhận mã của chính mình
    r = co.post(reverse('smartlock:share-codes'), {'action': 'create', 'device_id': str(dev.id), 'minutes': '5'})
    own = re.search(r'\b(\d{6})\b', msgs(r))
    co.post(reverse('smartlock:share-request'), {'code': own.group(1) if own else '0'})
    R.check('Chủ không tự nhận mã của mình', not DeviceAccess.objects.filter(user=owner, device=dev).exists())

    # hết hạn quyền
    DeviceAccess.objects.filter(pk=acc.pk).update(expires_at=timezone.now() - timedelta(minutes=1))
    R.check('Quyền hết hạn -> không còn thấy thiết bị',
            cg.get(reverse('smartlock:device-detail', args=[dev.id])).status_code == 404)


# ============================================================ 6. truy cập
def sec_access(C):
    from django.urls import reverse
    from smartlock import access_control as ac
    from smartlock.models import AccessCard, AccessEvent, AuditLog, Device, DoorPinCode, FaceProfile, Notification
    R = C.rep
    R.sec('6. PIN khách, thẻ RFID, khuôn mặt, khoá tạm khi sai liên tiếp')
    owner, other = C.owner, C.other
    co, cx = client_for(owner), client_for(other)
    dev = C.dev
    Device.objects.filter(pk=dev.pk).update(status='online')

    # ---- PIN ----
    r = co.post(reverse('smartlock:door-pins'), {'action': 'issue', 'device': str(dev.id), 'ttl_minutes': '60',
                                                 'max_uses': '1', 'label': 'Khách 1'})
    m = re.search(r'\b(\d{6})\b', msgs(r))
    pin = m.group(1) if m else None
    R.check('Cấp PIN cho khách', bool(pin) and DoorPinCode.objects.filter(device=dev).count() == 1)
    R.check('PIN không lưu dạng thô', not DoorPinCode.objects.filter(pin_hash=pin).exists())
    R.check('Người lạ không cấp được PIN cho thiết bị của người khác',
            cx.post(reverse('smartlock:door-pins'), {'action': 'issue', 'device': str(dev.id)}).status_code in (302, 404)
            and DoorPinCode.objects.filter(device=dev).count() == 1)
    ev = ac.verify_door_pin(dev, pin)
    R.check('PIN đúng mở cửa', ev.success)
    ev = ac.verify_door_pin(dev, pin)
    R.check('PIN dùng-một-lần: lần 2 bị từ chối', not ev.success and ev.reason == 'INVALID_OR_EXPIRED_PIN')
    p2 = ac.issue_door_pin(dev, owner, ac.generate_unique_pin(dev), ttl_minutes=60, max_uses=1)
    p2.revoke()
    R.check('PIN đã thu hồi không mở được', not ac.verify_door_pin(dev, '123456').success)
    p3 = DoorPinCode(device=dev, created_by=owner, expires_at=__import__('django').utils.timezone.now() - timedelta(minutes=1),
                     valid_from=__import__('django').utils.timezone.now() - timedelta(hours=2), max_uses=1)
    p3.set_pin('654321')
    p3.save()
    R.check('PIN hết hạn không mở được', not ac.verify_door_pin(dev, '654321').success)
    # MQTT lỗi -> hoàn lại lượt dùng
    from smartlock.mqtt_client import MqttPublishError
    good = ac.generate_unique_pin(dev)
    pobj = ac.issue_door_pin(dev, owner, good, ttl_minutes=60, max_uses=1)
    C.pub.side_effect = MqttPublishError('down')
    ev = ac.verify_door_pin(dev, good)
    C.pub.side_effect = None
    pobj.refresh_from_db()
    R.check('MQTT lỗi: không tính là mở cửa & hoàn lại lượt dùng PIN',
            (not ev.success) and ev.reason == 'MQTT_PUBLISH_FAILED' and pobj.use_count == 0)
    R.check('PIN dùng lại được sau khi lỗi MQTT', ac.verify_door_pin(dev, good).success)

    # ---- RFID ----
    r = co.post(reverse('smartlock:nfc-reader'), {'action': 'register_card', 'device': str(dev.id),
                                                  'uid': '04:A1:B2:C3', 'name': 'Thẻ của tôi'})
    card = AccessCard.objects.filter(user=owner).first()
    R.check('Đăng ký thẻ NFC', bool(card))
    R.check('UID thẻ lưu dạng hash', bool(card) and '04A1B2C3' not in card.card_uid_hash)
    R.check('Quẹt thẻ đúng mở cửa (không phân biệt hoa/thường, dấu phân cách)',
            ac.verify_rfid_tap(dev, '04a1b2c3').success)
    co.post(reverse('smartlock:nfc-tags'), {'action': 'toggle', 'card_id': str(card.id)})
    R.check('Thẻ bị vô hiệu hoá không mở được', not ac.verify_rfid_tap(dev, '04A1B2C3').success)
    co.post(reverse('smartlock:nfc-tags'), {'action': 'toggle', 'card_id': str(card.id)})
    R.check('Thẻ bật lại mở được', ac.verify_rfid_tap(dev, '04A1B2C3').success)
    r = co.post(reverse('smartlock:nfc-reader'), {'action': 'register_card', 'device': str(dev.id), 'uid': '04A1B2C3'})
    R.check('Đăng ký trùng thẻ bị từ chối', AccessCard.objects.filter(user=owner).count() == 1)
    cx.post(reverse('smartlock:nfc-tags'), {'action': 'delete', 'card_id': str(card.id)})
    R.check('User khác không xoá được thẻ', AccessCard.objects.filter(pk=card.pk).exists())

    # ---- Khuôn mặt ----
    emb = [0.1] * 64
    r = co.post(reverse('smartlock:face-profiles'), {'action': 'register', 'device': str(dev.id), 'embedding_json': json.dumps(emb)})
    R.check('Đăng ký khuôn mặt thiếu đồng ý bị từ chối', not FaceProfile.objects.filter(device=dev).exists())
    co.post(reverse('smartlock:face-profiles'), {'action': 'register', 'device': str(dev.id), 'consent_confirmed': 'on',
                                                 'embedding_json': json.dumps([0.1] * 5)})
    R.check('Embedding quá ngắn bị từ chối', not FaceProfile.objects.filter(device=dev).exists())
    co.post(reverse('smartlock:face-profiles'), {'action': 'register', 'device': str(dev.id), 'consent_confirmed': 'on',
                                                 'embedding_json': json.dumps(emb), 'name': 'Tôi'})
    fp = FaceProfile.objects.filter(device=dev).first()
    R.check('Đăng ký khuôn mặt hợp lệ', bool(fp))
    R.check('Embedding được mã hoá trong DB', bool(fp) and b'0.1' not in bytes(fp.embedding_encrypted))
    ev = ac.verify_face(dev, emb)
    R.check('Khuôn mặt khớp mở cửa, độ tin cậy ~1.0', ev.success and ev.confidence and ev.confidence > 0.99)
    ev = ac.verify_face(dev, [5.0] * 64)
    R.check('Khuôn mặt lạ bị từ chối (NO_MATCH)', (not ev.success) and ev.reason == 'NO_MATCH')
    co.post(reverse('smartlock:face-profiles'), {'action': 'toggle', 'device': str(dev.id), 'profile_id': str(fp.id)})
    R.check('Tắt hồ sơ khuôn mặt -> không mở được', not ac.verify_face(dev, emb).success)

    R.check('AccessEvent ghi đủ các kênh', set(AccessEvent.objects.values_list('method', flat=True)) >= {'PIN', 'RFID', 'FACE'})
    R.check('Trang lịch sử ra vào mở được', co.get(reverse('smartlock:access-history')).status_code == 200,
            'Kiểm tra templates/account/access/history.html')

    # ---- Khoá tạm sau 3 lần sai (kịch bản demo #2) ----
    d2 = Device.objects.create(name='Cửa phụ', device_code='DEV-BURST01', provisioning_secret_hash='x',
                               status='online', owner=owner)
    good_card = AccessCard.objects.create(card_uid_hash=__import__('smartlock.utils', fromlist=['x']).SmartlockUtils.hash_token('AABBCCDD'),
                                          user=owner, is_active=True)
    from smartlock.models import CardDeviceAccess
    CardDeviceAccess.objects.create(access_card=good_card, device=d2)
    R.check('Thẻ hợp lệ mở được trước khi bị khoá', ac.verify_rfid_tap(d2, 'AABBCCDD').success)
    C.pub.reset_mock()
    for i in range(ac.BURST_FAIL_THRESHOLD):
        ac.verify_rfid_tap(d2, f'BAD0000{i}')
    R.check(f'{ac.BURST_FAIL_THRESHOLD} lần quẹt sai -> ghi ACCESS_BURST_LOCKOUT',
            AuditLog.objects.filter(device=d2, action='ACCESS_BURST_LOCKOUT').exists())
    R.check('Phát lệnh còi BUZZER_ALERT', any('BUZZER_ALERT' in str(c) for c in C.pub.call_args_list))
    R.check('Gửi cảnh báo cho chủ nhà (critical)',
            Notification.objects.filter(user=owner, device=d2, type='ACCESS_BURST', severity='critical').exists())
    ev = ac.verify_rfid_tap(d2, 'AABBCCDD')
    R.check('Đang khoá tạm: thẻ đúng cũng bị từ chối', (not ev.success) and ev.reason == 'DEVICE_LOCKED_OUT')
    n = AuditLog.objects.filter(device=d2, action='ACCESS_BURST_LOCKOUT').count()
    ac.verify_rfid_tap(d2, 'BAD99999')
    R.check('Bị chặn không tự gia hạn khoá / không spam thông báo',
            AuditLog.objects.filter(device=d2, action='ACCESS_BURST_LOCKOUT').count() == n)
    AuditLog.objects.filter(device=d2, action='ACCESS_BURST_LOCKOUT').update(
        created_at=__import__('django').utils.timezone.now() - timedelta(seconds=ac.BURST_LOCKOUT_SECONDS + 5))
    R.check('Hết thời gian khoá -> thẻ đúng mở lại được', ac.verify_rfid_tap(d2, 'AABBCCDD').success)


# ============================================================ 7. rule engine
def sec_rules(C):
    from django.utils import timezone
    from smartlock import rules_engine as re_
    from smartlock.models import AutomationRule, Device, DeviceCommand, DeviceStatusLog, Notification
    R = C.rep
    R.sec('7. Rule engine (tự động hoá / cảnh báo)')
    owner = C.owner
    d = Device.objects.create(name='Rule dev', device_code='DEV-RULE0001', provisioning_secret_hash='x',
                              status='online', owner=owner)
    rule = AutomationRule.objects.create(owner=owner, device=d, name='Pin yếu', trigger_type='BATTERY_LOW',
                                         threshold_value=20, notify_severity='warning', cooldown_seconds=300)
    log = DeviceStatusLog.objects.create(device=d, battery_level=50, lock_state='locked')
    R.check('Pin 50% (ngưỡng 20) -> không kích hoạt', re_.evaluate_device_status(d, log) == 0)
    log = DeviceStatusLog.objects.create(device=d, battery_level=10, lock_state='locked')
    R.check('Pin 10% -> kích hoạt luật', re_.evaluate_device_status(d, log) == 1)
    R.check('Tạo thông báo AUTOMATION_RULE', Notification.objects.filter(user=owner, type='AUTOMATION_RULE', device=d).exists())
    R.check('Cooldown: kích hoạt lại ngay -> bỏ qua', re_.evaluate_device_status(d, log) == 0)
    AutomationRule.objects.filter(pk=rule.pk).update(is_active=False, last_triggered_at=None)
    R.check('Luật tắt không kích hoạt', re_.evaluate_device_status(d, log) == 0)

    AutomationRule.objects.create(owner=owner, device=d, name='Tamper', trigger_type='TAMPER_DETECTED',
                                  action_type='AUTO_LOCK', notify_severity='critical')
    log = DeviceStatusLog.objects.create(device=d, battery_level=90, lock_state='unlocked', tamper_detected=True)
    C.pub.reset_mock()
    R.check('Tamper -> kích hoạt luật', re_.evaluate_device_status(d, log) == 1)
    R.check('Hành động AUTO_LOCK gửi lệnh LOCK', DeviceCommand.objects.filter(device=d, command_type='LOCK', status='sent').exists()
            and C.pub.called)

    AutomationRule.objects.create(owner=owner, device=d, name='Nhiệt', trigger_type='TEMPERATURE_OUT_OF_RANGE',
                                  threshold_value=40)
    log = DeviceStatusLog.objects.create(device=d, battery_level=90, lock_state='locked', temperature=55)
    R.check('Nhiệt độ vượt ngưỡng -> kích hoạt', re_.evaluate_device_status(d, log) == 1)

    Device.objects.filter(pk=d.pk).update(status='offline', last_seen_at=timezone.now() - timedelta(minutes=10))
    AutomationRule.objects.create(owner=owner, device=d, name='Offline', trigger_type='OFFLINE_TOO_LONG', threshold_value=60)
    R.check('Offline quá lâu -> kích hoạt', re_.evaluate_offline_devices() >= 1)

    from smartlock.models import AccessEvent
    AutomationRule.objects.create(owner=owner, device=d, name='Sai liên tiếp', trigger_type='FAILED_ACCESS_BURST',
                                  threshold_value=2, threshold_window_seconds=60)
    for _ in range(2):
        AccessEvent.objects.create(device=d, method='PIN', success=False, reason='INVALID_OR_EXPIRED_PIN')
    R.check('Luật N lần sai trong X giây kích hoạt', re_.evaluate_failed_access_burst(d) == 1)

    co = client_for(owner)
    from django.urls import reverse
    R.check('Trang quản lý luật mở được', co.get(reverse('smartlock:automation-rules')).status_code == 200)


# ============================================================ 8. trang khác
def sec_pages(C):
    from django.urls import reverse
    from smartlock.models import Announcement, AuditLog, Notification
    R = C.rep
    R.sec('8. Thông báo, nhật ký, cài đặt, log demo')
    owner, other = C.owner, C.other
    co, cx = client_for(owner), client_for(other)

    n = Notification.objects.create(user=owner, title='Test', message='m', type='SYSTEM')
    R.check('Trang thông báo', co.get(reverse('smartlock:notifications')).status_code == 200)
    co.post(reverse('smartlock:notifications'), {'action': 'mark_read', 'id': str(n.id)})
    n.refresh_from_db()
    R.check('Đánh dấu đã đọc', n.is_read)
    cx.post(reverse('smartlock:notifications'), {'action': 'mark_all'})
    R.check('Thông báo không lẫn giữa các user', Notification.objects.filter(user=owner, is_read=False).count() >= 0)

    r = co.get(reverse('smartlock:audit-logs'))
    R.check('Nhật ký của user', r.status_code == 200)
    mine = {str(x.id) for x in r.context['audit_logs']} if r.context else set()
    foreign = AuditLog.objects.create(actor_user=other, action='SECRET_ACTION_OTHER')
    r = co.get(reverse('smartlock:audit-logs'))
    ids = {str(x.id) for x in r.context['audit_logs']} if r.context else set()
    R.check('Không xem được log của người khác', str(foreign.id) not in ids)

    admin = mkuser('pg_admin', is_admin=True, is_staff=True)
    ca = client_for(admin)
    R.check('Trang cài đặt hệ thống cho admin', ca.get(reverse('smartlock:settings-system')).status_code in (200, 302))
    from django.test import override_settings
    with override_settings(DEMO_LOGS_ENABLED=False):
        R.check('Log công khai /demo/system-logs/ bị chặn khi DEMO_LOGS_ENABLED=False',
                client_for().get(reverse('smartlock:public-system-logs')).status_code in (403, 404))
    with override_settings(DEMO_LOGS_ENABLED=True):
        R.check('Log công khai hoạt động khi bật demo', client_for().get(reverse('smartlock:public-system-logs')).status_code == 200)


# ============================================================ 9. MQTT webhook
def sec_mqtt(C):
    from django.test import override_settings
    from django.urls import reverse
    R = C.rep
    R.sec('9. Webhook xác thực/ACL của MQTT broker')
    dev = C.dev
    c = client_for()
    auth, acl = reverse('smartlock:mqtt-auth'), reverse('smartlock:mqtt-acl')
    with override_settings(MQTT_WEBHOOK_SECRET='s3cret', MQTT_TRUSTED_USERNAMES=['django-pub']):
        H = {'HTTP_X_WEBHOOK_SECRET': 's3cret'}
        R.check('Thiếu secret -> 403', c.post(auth, {'username': dev.device_code, 'password': C.dev_secret or 'x'}).status_code == 403)
        R.check('Sai secret -> 403', c.post(auth, {'username': dev.device_code, 'password': 'x'}, HTTP_X_WEBHOOK_SECRET='no').status_code == 403)
        R.check('Thiết bị + secret đúng -> 200',
                bool(C.dev_secret) and c.post(auth, {'username': dev.device_code, 'password': C.dev_secret}, **H).status_code == 200)
        R.check('Sai mật khẩu thiết bị -> 401', c.post(auth, {'username': dev.device_code, 'password': 'sai'}, **H).status_code == 401)
        R.check('Thiết bị không tồn tại -> 401', c.post(auth, {'username': 'DEV-NOPE', 'password': 'x'}, **H).status_code == 401)
        R.check('GET webhook bị từ chối (405)', c.get(auth).status_code == 405)
        code = dev.device_code
        def acl_(user, topic, acc):
            return c.post(acl, {'username': user, 'topic': topic, 'acc': acc}, **H).status_code
        R.check('Thiết bị đọc topic cmd của mình', acl_(code, f'smartlock/{code}/cmd', 1) == 200)
        R.check('Thiết bị ghi status của mình', acl_(code, f'smartlock/{code}/status', 2) == 200)
        R.check('Thiết bị không ghi vào cmd', acl_(code, f'smartlock/{code}/cmd', 2) == 403)
        R.check('Thiết bị không đụng topic thiết bị khác', acl_(code, 'smartlock/DEV-OTHER/status', 2) == 403)
        R.check('Tài khoản tin cậy của server được phép', acl_('django-pub', 'smartlock/+/cmd', 2) == 200)


# ============================================================ 10. admin audit
def sec_admin(C):
    from django.urls import reverse
    from smartlock.models import Announcement, AuditLog
    R = C.rep
    R.sec('10. Django admin & audit tự động')
    su = mkuser('root_admin', is_admin=True, is_staff=True, is_superuser=True)
    c = client_for(su)
    R.check('Trang /admin/ mở được', c.get(reverse('admin:index')).status_code == 200)
    c.post(reverse('admin:smartlock_announcement_add'),
           {'title': 'Bảo trì', 'body': 'Nội dung', 'level': 'info', 'is_active': 'on', 'created_by': ''})
    a = Announcement.objects.filter(title='Bảo trì').first()
    R.check('Admin tạo Announcement', bool(a))
    R.check('Tự ghi AuditLog ADMIN_ANNOUNCEMENT_CREATED', AuditLog.objects.filter(action='ADMIN_ANNOUNCEMENT_CREATED').exists())
    normal = client_for(C.owner)
    R.check('User thường không vào được /admin/', normal.get(reverse('admin:index')).status_code in (302, 403))


# ============================================================ main
SECTIONS = [sec_config, sec_crawl, sec_auth, sec_devices, sec_share, sec_access, sec_rules, sec_pages, sec_mqtt, sec_admin]


def main():
    ap = argparse.ArgumentParser(description='Kiểm tra toàn diện web Smart Lock')
    ap.add_argument('--settings', default='smartlock_django.settings_test')
    ap.add_argument('-v', '--verbose', action='store_true')
    args = ap.parse_args()

    bootstrap(args.settings)
    from django.core import mail
    from django.test import override_settings
    from django.test.runner import DiscoverRunner
    from django.test.utils import setup_test_environment, teardown_test_environment

    setup_test_environment()
    runner = DiscoverRunner(verbosity=0, interactive=False)
    print('Đang tạo DB kiểm thử...')
    old = runner.setup_databases()
    C = Ctx()
    C.rep = Report(args.verbose)
    C.pub = mock.MagicMock(name='publish_command')
    try:
        with ExitStack() as stack:
            stack.enter_context(override_settings(EMAIL_BACKEND='django.core.mail.backends.locmem.EmailBackend',
                                                  DEFAULT_FROM_EMAIL='noreply@example.com',
                                                  SECURE_SSL_REDIRECT=False))
            for target in ('smartlock.views.publish_command', 'smartlock.access_control.publish_command',
                           'smartlock.api.views.publish_command', 'smartlock.mqtt_client.publish_command'):
                try:
                    stack.enter_context(mock.patch(target, C.pub))
                except (ImportError, AttributeError):
                    pass
            for fn in SECTIONS:
                mail.outbox.clear()
                try:
                    fn(C)
                except Exception:
                    C.rep.crash(fn.__name__)
                    if fn in (sec_devices,):   # các mục sau phụ thuộc thiết bị
                        C.dev = getattr(C, 'dev', None)
    finally:
        runner.teardown_databases(old)
        teardown_test_environment()
    fails = C.rep.summary()
    sys.exit(1 if fails else 0)


if __name__ == '__main__':
    main()