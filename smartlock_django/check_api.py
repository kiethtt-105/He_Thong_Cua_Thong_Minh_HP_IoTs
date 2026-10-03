#!/usr/bin/env python3
"""
check_api.py - MENU kiểm tra REST API Smart Lock (/api/v1/).
Chỉ dùng thư viện chuẩn của Python, không cần pip install. Mọi thông tin được hỏi ngay trong menu,
không phải gõ tham số trên dòng lệnh.

Chạy (server đang bật `python manage.py runserver`):

    python check_api.py

Lưu ý an toàn:
  * Script KHÔNG BAO GIỜ gửi lệnh UNLOCK.
  * Heartbeat ghi trạng thái vào khoá -> nên test API khoá bằng khoá ảo (VDEV_CODE / VDEV_SECRET trong .env).
  * Mật khẩu / secret chỉ giữ trong bộ nhớ, không ghi ra file. File .check_api.json chỉ nhớ địa chỉ server,
    tên đăng nhập và mã khoá cho lần chạy sau.
"""
import getpass
import json
import os
import sys
import time
import urllib.error
import urllib.request

# ---------------------------------------------------------------- hiển thị
if os.name == 'nt':
    os.system('')                      # bật mã màu ANSI trong cmd/PowerShell
USE_COLOR = sys.stdout.isatty()
G, R, Y, B, D, N = (('\033[92m', '\033[91m', '\033[93m', '\033[96m', '\033[90m', '\033[0m')
                    if USE_COLOR else ('', '', '', '', '', ''))
CONFIG_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), '.check_api.json')

stats = {'pass': 0, 'fail': 0, 'skip': 0}
failures = []

# trạng thái dùng chung giữa các mục menu
S = {'base': 'http://127.0.0.1:8000', 'user': '', 'tokens': None,
     'dev_code': '', 'dev_secret': '', 'lock_state': ''}


def load_config():
    try:
        with open(CONFIG_FILE, encoding='utf-8') as f:
            data = json.load(f)
        for k in ('base', 'user', 'dev_code'):
            if data.get(k):
                S[k] = data[k]
    except (OSError, ValueError):
        pass


def save_config():
    try:
        with open(CONFIG_FILE, 'w', encoding='utf-8') as f:
            json.dump({k: S[k] for k in ('base', 'user', 'dev_code')}, f, ensure_ascii=False)
    except OSError:
        pass


def section(title):
    print(f'\n{B}== {title} =={N}')


def record(ok_, name, detail=''):
    if ok_:
        stats['pass'] += 1
        print(f'  {G}[ OK ]{N} {name}' + (f'  {D}{detail}{N}' if detail else ''))
    else:
        stats['fail'] += 1
        failures.append(f'{name} - {detail}')
        print(f'  {R}[FAIL]{N} {name}  {R}{detail}{N}')
    return ok_


def skip(name, why):
    stats['skip'] += 1
    print(f'  {Y}[SKIP]{N} {name}  {D}{why}{N}')


def info(msg):
    print(f'  {D}{msg}{N}')


# ---------------------------------------------------------------- nhập liệu
def ask(prompt, default='', secret=False, required=False):
    """Hỏi người dùng. Enter = giữ giá trị mặc định."""
    while True:
        shown = f' [{default}]' if default and not secret else ''
        try:
            val = (getpass.getpass if secret else input)(f'  {prompt}{shown}: ').strip()
        except EOFError:
            raise KeyboardInterrupt
        if not val:
            val = default
        if val or not required:
            return val
        print(f'  {Y}Không được để trống.{N}')


def confirm(prompt, default=False):
    hint = 'Y/n' if default else 'y/N'
    val = ask(f'{prompt} ({hint})').lower()
    return default if not val else val in ('y', 'yes', 'c', 'co', 'có')


def pause():
    try:
        input(f'\n{D}Nhấn Enter để quay lại menu...{N}')
    except EOFError:
        pass


def choose(title, options):
    """Chọn 1 trong nhiều mục bằng số. options: list[str] -> index hoặc None."""
    print(f'  {title}')
    for i, o in enumerate(options, 1):
        print(f'    {i}. {o}')
    while True:
        val = ask('Chọn số (Enter = huỷ)')
        if not val:
            return None
        if val.isdigit() and 1 <= int(val) <= len(options):
            return int(val) - 1
        print(f'  {Y}Số không hợp lệ.{N}')


# ---------------------------------------------------------------- HTTP
class Client:
    def __init__(self, base, timeout=15):
        self.base, self.timeout = base.rstrip('/'), timeout

    def call(self, method, path, body=None, token=None, headers=None):
        """-> (status, json|None, ms). status 0 = không kết nối được."""
        url = self.base + '/api/v1' + path
        data = json.dumps(body).encode('utf-8') if body is not None else None
        req = urllib.request.Request(url, data=data, method=method)
        req.add_header('Accept', 'application/json')
        if data is not None:
            req.add_header('Content-Type', 'application/json')
        if token:
            req.add_header('Authorization', f'Bearer {token}')
        for k, v in (headers or {}).items():
            req.add_header(k, v)
        t0 = time.time()
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as r:
                status, raw = r.status, r.read()
        except urllib.error.HTTPError as e:
            status, raw = e.code, e.read()
        except (urllib.error.URLError, OSError) as e:
            return 0, {'_net_error': str(getattr(e, 'reason', e))}, int((time.time() - t0) * 1000)
        ms = int((time.time() - t0) * 1000)
        try:
            js = json.loads(raw.decode('utf-8')) if raw else None
        except ValueError:
            js = {'_not_json': raw[:200].decode('utf-8', 'replace')}
        return status, js, ms


def client():
    return Client(S['base'])


def err_code(js):
    return ((js or {}).get('error') or {}).get('code')


def check(name, res, status, ok=None, code=None):
    """Đối chiếu (status, json, ms) với kỳ vọng. status có thể là số hoặc tuple các số chấp nhận."""
    st, js, ms = res
    wanted = status if isinstance(status, (tuple, list)) else (status,)
    problems = []
    if st not in wanted:
        problems.append(f'HTTP {st} (cần {"/".join(map(str, wanted))})')
    if ok is not None and not (isinstance(js, dict) and js.get('ok') is ok):
        problems.append(f'ok={js.get("ok") if isinstance(js, dict) else None} (cần {ok})')
    if code and err_code(js) != code:
        problems.append(f'error.code={err_code(js)} (cần {code})')
    if problems and isinstance(js, dict) and js.get('error'):
        problems.append(f'message: {js["error"].get("message")}')
    if st == 0:
        problems = [f'không kết nối được: {js.get("_net_error")}']
    elif problems and isinstance(js, dict) and '_not_json' in js:
        problems.append('phản hồi không phải JSON: ' + js['_not_json'][:80].replace('\n', ' '))
    return record(not problems, name, '; '.join(problems) if problems else f'{st} · {ms}ms')


def first_list(js):
    """Lấy danh sách object đầu tiên trong phản hồi (items / devices / ...)."""
    if isinstance(js, dict):
        for v in js.values():
            if isinstance(v, list) and (not v or isinstance(v[0], dict)):
                return v
    return []


def access_token():
    return (S['tokens'] or {}).get('access')


# ---------------------------------------------------------------- 1. công khai
def act_public():
    c = client()
    section(f'Route công khai / bảo vệ  ->  {S["base"]}')
    r = c.call('GET', '/device/config/')
    if r[0] == 0:
        record(False, 'Kết nối máy chủ', f'không kết nối được: {r[1].get("_net_error")}')
        print(f'\n  {R}Server chưa chạy hoặc sai địa chỉ. Chạy `python manage.py runserver` hoặc dùng mục 1 để đổi địa chỉ.{N}')
        return
    check('API khoá: thiếu header -> 401', r, 401, ok=False, code='DEVICE_AUTH_REQUIRED')
    check('API khoá: sai mã/secret -> 401',
          c.call('GET', '/device/config/', headers={'X-Device-Code': 'NOPE-0000', 'X-Device-Secret': 'x'}),
          401, ok=False, code='DEVICE_AUTH_FAILED')
    check('Login thiếu dữ liệu -> 400', c.call('POST', '/auth/login/', {}), 400, ok=False)
    check('Login sai phương thức (GET) -> 405', c.call('GET', '/auth/login/'), 405, ok=False,
          code='METHOD_NOT_ALLOWED')
    check('Login sai mật khẩu -> bị từ chối (400/401)', c.call('POST', '/auth/login/', {
        'identifier': 'khong.ton.tai@example.invalid', 'password': 'sai-mat-khau-123', 'device_name': 'check_api',
        'platform': 'android'}), (400, 401), ok=False)
    check('Không có token -> 401', c.call('GET', '/me/'), 401, ok=False)
    check('Token rác -> 401', c.call('GET', '/me/', token='token.rac.abc'), 401, ok=False)
    check('Đường dẫn không tồn tại -> 404', c.call('GET', '/khong-co-route/'), 404)


# ---------------------------------------------------------------- 2. đăng nhập / app
def act_login(silent_if_ok=False):
    """Đăng nhập (hỏi thông tin). -> True nếu có token."""
    if S['tokens'] and silent_if_ok:
        return True
    section('Đăng nhập tài khoản (app)')
    c = client()
    S['user'] = ask('Email hoặc username', S['user'], required=True)
    password = ask('Mật khẩu (gõ không hiện)', secret=True, required=True)
    save_config()
    r = c.call('POST', '/auth/login/', {'identifier': S['user'], 'password': password, 'device_name': 'check_api',
                                        'platform': 'android', 'app_version': 'check_api'})
    js = r[1] if isinstance(r[1], dict) else {}
    if not js.get('two_factor_required'):
        if not check('Đăng nhập', r, 200, ok=True):
            return False
    else:
        record(True, 'Mật khẩu đúng, tài khoản yêu cầu 2FA', f'phương thức: {js.get("methods")}')
        methods = js.get('methods') or ['totp']
        method = methods[0]
        if len(methods) > 1:
            idx = choose('Chọn phương thức 2FA:', methods)
            if idx is None:
                return False
            method = methods[idx]
        challenge = js['challenge_token']
        if method == 'email':
            check('Gửi mã 2FA qua email', c.call('POST', '/auth/2fa/email/send/', {'challenge_token': challenge}),
                  200, ok=True)
        code = ask(f'Nhập mã 2FA ({method})', required=True)
        r = c.call('POST', '/auth/2fa/verify/', {'challenge_token': challenge, 'method': method, 'code': code})
        if not check('Xác minh 2FA', r, 200, ok=True):
            return False
        js = r[1]
    tokens = js.get('tokens') if isinstance(js.get('tokens'), dict) else js
    if not (tokens.get('access_token') and tokens.get('refresh_token')):
        record(False, 'Phản hồi có access_token + refresh_token', f'các khoá trong JSON: {sorted(js)}')
        return False
    S['tokens'] = {'access': tokens['access_token'], 'refresh': tokens['refresh_token']}
    info('Đã đăng nhập. Token được giữ trong bộ nhớ cho tới khi thoát hoặc đăng xuất.')
    return True


def act_logout(quiet=False):
    if not S['tokens']:
        if not quiet:
            skip('Đăng xuất', 'chưa đăng nhập')
        return
    c = client()
    res = c.call('POST', '/auth/logout/', {}, token=access_token())
    if not quiet:
        section('Đăng xuất')
        check('POST /auth/logout/', res, 200, ok=True)
        check('Sau logout token bị từ chối', c.call('GET', '/me/', token=access_token()), 401, ok=False)
    S['tokens'] = None


def pick_device(c):
    r = c.call('GET', '/devices/', token=access_token())
    if not check('GET /devices/', r, 200, ok=True):
        return None
    devices = first_list(r[1])
    if not devices:
        skip('Các API theo từng khoá', 'tài khoản chưa có khoá nào (dùng POST /devices/claim/ để thêm)')
        return None
    if len(devices) == 1:
        d = devices[0]
    else:
        names = [f'{d.get("name") or d.get("id")}  ({d.get("device_code", "?")})' for d in devices]
        idx = choose('Tài khoản có nhiều khoá, chọn khoá để kiểm tra:', names)
        if idx is None:
            return None
        d = devices[idx]
    info(f'Dùng khoá: {d.get("name") or d.get("id")} ({d.get("device_code", "?")})')
    return d


def act_app():
    if not act_login(silent_if_ok=True):
        return
    c = client()
    section('API cho APP (chỉ đọc dữ liệu)')

    r = c.call('POST', '/auth/refresh/', {'refresh_token': S['tokens']['refresh']})
    if check('Làm mới token (refresh xoay vòng)', r, 200, ok=True) and r[1].get('access_token'):
        S['tokens'] = {'access': r[1]['access_token'], 'refresh': r[1].get('refresh_token', S['tokens']['refresh'])}
    t = access_token()

    for name, path in (('GET /me/', '/me/'), ('GET /bootstrap/', '/bootstrap/'),
                       ('GET /me/sessions/', '/me/sessions/'), ('GET /me/two-factor/', '/me/two-factor/'),
                       ('GET /permissions/', '/permissions/'), ('GET /notifications/', '/notifications/'),
                       ('GET /events/', '/events/'), ('GET /history/', '/history/?page=1&page_size=5'),
                       ('GET /audit/', '/audit/?page=1&page_size=5'), ('GET /cards/', '/cards/'),
                       ('GET /shares/incoming/', '/shares/incoming/')):
        check(name, c.call('GET', path, token=t), 200, ok=True)
    check('Phân trang sai -> 400', c.call('GET', '/history/?page=abc', token=t), 400, ok=False)

    d = pick_device(c)
    if not d:
        return
    did = d.get('id')
    check('GET /devices/{id}/', c.call('GET', f'/devices/{did}/', token=t), 200, ok=True)
    check('GET /devices/{id}/live/', c.call('GET', f'/devices/{did}/live/', token=t), 200, ok=True)
    check('GET /devices/{id}/commands/history/', c.call('GET', f'/devices/{did}/commands/history/', token=t),
          200, ok=True)
    for name in ('pins', 'faces', 'nfc-readers', 'shares'):
        r = c.call('GET', f'/devices/{did}/{name}/', token=t)
        if r[0] == 403:
            record(True, f'GET /devices/{{id}}/{name}/', '403 (không phải chủ / không đủ quyền - hợp lệ)')
        else:
            check(f'GET /devices/{{id}}/{name}/', r, 200, ok=True)
    check('Khoá không tồn tại -> 404', c.call('GET', '/devices/00000000-0000-0000-0000-000000000000/', token=t),
          404, ok=False)
    check('Lệnh không hợp lệ -> 400', c.call('POST', f'/devices/{did}/commands/', {'command': 'KHONG_CO'}, token=t),
          400, ok=False)


def act_send_lock():
    if not act_login(silent_if_ok=True):
        return
    c = client()
    section('Gửi lệnh LOCK tới khoá')
    d = pick_device(c)
    if not d:
        return
    if not confirm(f'Gửi lệnh LOCK tới "{d.get("name") or d.get("id")}" (khoá thật sẽ khoá lại). Tiếp tục', False):
        skip('Gửi lệnh LOCK', 'đã huỷ')
        return
    r = c.call('POST', f'/devices/{d["id"]}/commands/', {'command': 'LOCK'}, token=access_token())
    if not check('POST lệnh LOCK', r, 202, ok=True):
        return
    cid = (r[1].get('command') or {}).get('id')
    final = None
    for _ in range(10):
        time.sleep(1.5)
        rs = c.call('GET', f'/commands/{cid}/', token=access_token())
        final = ((rs[1] or {}).get('command') or {}).get('status')
        info(f'trạng thái lệnh: {final}')
        if final in ('acknowledged', 'failed', 'expired'):
            break
    record(final == 'acknowledged', 'Khoá phản hồi lệnh LOCK',
           f'trạng thái cuối: {final} (khoá offline / chưa ack sẽ không đạt)')


# ---------------------------------------------------------------- 3. khoá
def act_device_creds():
    section('Thông tin khoá (firmware)')
    info('Nên dùng khoá ảo: VDEV_CODE / VDEV_SECRET trong file .env')
    S['dev_code'] = ask('Mã khoá (X-Device-Code)', S['dev_code'], required=True)
    S['dev_secret'] = ask('Secret (X-Device-Secret, gõ không hiện)', secret=True, required=True)
    S['lock_state'] = ask('Trạng thái gửi trong heartbeat: locked/unlocked/jammed/unknown (Enter = không gửi)',
                          S['lock_state'])
    if S['lock_state'] not in ('', 'locked', 'unlocked', 'jammed', 'unknown'):
        print(f'  {Y}Giá trị không hợp lệ, bỏ qua.{N}')
        S['lock_state'] = ''
    save_config()
    return True


def device_headers():
    if not (S['dev_code'] and S['dev_secret']):
        if not act_device_creds():
            return None
    return {'X-Device-Code': S['dev_code'], 'X-Device-Secret': S['dev_secret']}


def act_lock():
    h = device_headers()
    if not h:
        return
    c = client()
    section('API cho KHOÁ (firmware)')
    r = c.call('GET', '/device/config/', headers=h)
    if not check('GET /device/config/', r, 200, ok=True):
        info('Sai mã/secret? Dùng mục 6 để nhập lại. Lưu ý: sai quá 10 lần/10 phút sẽ bị chặn tạm (429).')
        S['dev_secret'] = ''
        return
    for k in ('unix_time', 'intervals'):
        record(k in r[1] or k in (r[1].get('config') or {}), f'config có trường "{k}"')
    hb = {'battery': 87, 'signal': -60, 'tamper': False, 'firmware': 'check_api'}
    if S['lock_state']:
        hb['lock_state'] = S['lock_state']
    r = c.call('POST', '/device/heartbeat/', hb, headers=h)
    if check('POST /device/heartbeat/', r, 200, ok=True):
        record(isinstance(r[1].get('commands'), list), 'heartbeat trả về mảng "commands"')
    check('GET /device/commands/', c.call('GET', '/device/commands/', headers=h), 200, ok=True)
    check('POST /device/ack/ lệnh giả -> bị từ chối có kiểm soát',
          c.call('POST', '/device/ack/', {'command_id': '00000000-0000-0000-0000-000000000000', 'token': 'x',
                                          'success': True}, headers=h), (400, 404), ok=False)
    check('POST /device/events/ loại sai -> 400',
          c.call('POST', '/device/events/', {'type': 'KHONG_CO'}, headers=h), 400, ok=False)
    check('POST /device/access/phone/ vé sai -> granted=false', _granted_false(
        c.call('POST', '/device/access/phone/', {'channel': 'ble', 'ticket': 'sai.0.sai', 'ok': False,
                                                 'reason': 'check_api'}, headers=h)), 200, ok=True)


def act_lock_access():
    section('Thử quẹt thẻ / PIN SAI qua API khoá')
    print(f'  {Y}Cảnh báo: thử sai nhiều lần có thể làm khoá bị KHOÁ TẠM (còi + từ chối cục bộ).{N}')
    if not confirm('Vẫn tiếp tục', False):
        skip('Quẹt thẻ / PIN sai', 'đã huỷ')
        return
    h = device_headers()
    if not h:
        return
    c = client()
    check('POST /device/access/rfid/ thẻ lạ -> granted=false',
          _granted_false(c.call('POST', '/device/access/rfid/', {'uid': 'DEADBEEF'}, headers=h)), 200, ok=True)
    check('POST /device/access/pin/ PIN sai -> granted=false',
          _granted_false(c.call('POST', '/device/access/pin/', {'pin': '000000'}, headers=h)), 200, ok=True)


def _granted_false(res):
    """Nếu khoá cho phép mở cửa với dữ liệu sai -> biến thành lỗi."""
    st, js, ms = res
    if st == 200 and isinstance(js, dict) and js.get('granted') is True:
        return (500, {'ok': False, 'error': {'code': 'UNEXPECTED_GRANTED',
                                             'message': 'khoá cho phép mở cửa với dữ liệu sai!'}}, ms)
    return res


# ---------------------------------------------------------------- khác
def act_server():
    section('Địa chỉ server')
    val = ask('Địa chỉ gốc (vd http://127.0.0.1:8000)', S['base'], required=True).rstrip('/')
    if not val.startswith(('http://', 'https://')):
        val = 'http://' + val
    if val != S['base']:
        S['base'], S['tokens'] = val, None           # đổi server -> token cũ vô nghĩa
        info('Đã đổi địa chỉ, phiên đăng nhập cũ được bỏ.')
    save_config()
    info(f'Server hiện tại: {S["base"]}')


def act_all():
    act_public()
    if stats['fail'] and stats['pass'] == 0:
        return
    if confirm('Kiểm tra tiếp API cho APP (cần đăng nhập)', True):
        act_app()
    if confirm('Kiểm tra tiếp API cho KHOÁ (cần mã + secret khoá)', True):
        act_lock()


# ---------------------------------------------------------------- menu
MENU = [
    ('1', 'Đổi địa chỉ server', act_server, False),
    ('2', 'Kiểm tra route công khai / bảo vệ', act_public, True),
    ('3', 'Đăng nhập tài khoản (app)', act_login, True),
    ('4', 'Kiểm tra API cho APP', act_app, True),
    ('5', 'Gửi lệnh LOCK tới khoá (qua app)', act_send_lock, True),
    ('6', 'Nhập thông tin khoá (mã + secret)', act_device_creds, False),
    ('7', 'Kiểm tra API cho KHOÁ (firmware)', act_lock, True),
    ('8', 'Thử quẹt thẻ / PIN sai (có thể gây khoá tạm)', act_lock_access, True),
    ('9', 'Chạy tất cả', act_all, True),
    ('10', 'Đăng xuất', act_logout, True),
    ('0', 'Thoát', None, False),
]


def header():
    os.system('cls' if os.name == 'nt' else 'clear')
    print(f'{B}==============  SMART LOCK API CHECK  =============={N}')
    print(f'  Server : {S["base"]}')
    print(f'  App    : {G + "đã đăng nhập (" + S["user"] + ")" + N if S["tokens"] else D + "chưa đăng nhập" + N}')
    print(f'  Khoá   : {G + S["dev_code"] + N if S["dev_code"] and S["dev_secret"] else D + "chưa nhập" + N}')
    print()
    for key, label, _, _ in MENU:
        print(f'  {key:>2}. {label}')
    print()


def run_action(fn, report):
    stats['pass'] = stats['fail'] = stats['skip'] = 0
    failures.clear()
    try:
        fn()
    except KeyboardInterrupt:
        raise
    except Exception as exc:                          # lỗi trong script, không làm thoát menu
        print(f'\n  {R}Lỗi script: {type(exc).__name__}: {exc}{N}')
    total = stats['pass'] + stats['fail']
    if report and (total or stats['skip']):
        print(f'\n{B}== Kết quả =={N}  {G}đạt {stats["pass"]}/{total}{N}  '
              f'{R if stats["fail"] else D}lỗi {stats["fail"]}{N}  {Y}bỏ qua {stats["skip"]}{N}')
        for f in failures:
            print(f'  {R}- {f}{N}')


def startup():
    """Mở script -> yêu cầu user + mật khẩu -> tự kiểm tra route công khai + API app ngay."""
    os.system('cls' if os.name == 'nt' else 'clear')
    print(f'{B}==============  SMART LOCK API CHECK  =============={N}')
    print(f'  Server : {S["base"]}  {D}(đổi ở mục 1 của menu){N}\n')
    r = client().call('GET', '/device/config/')
    if r[0] == 0:
        print(f'  {R}Không kết nối được server: {r[1].get("_net_error")}{N}')
        print(f'  {Y}Hãy chạy `python manage.py runserver` hoặc đổi địa chỉ ở mục 1.{N}')
        pause()
        return
    if not confirm('Đăng nhập rồi kiểm tra API ngay', True):
        return
    for attempt in range(3):
        stats['pass'] = stats['fail'] = stats['skip'] = 0
        if act_login():
            break
        print(f'  {Y}Đăng nhập chưa được ({attempt + 1}/3). Thử lại...{N}')
    else:
        print(f'\n  {R}Đăng nhập thất bại 3 lần, chuyển sang menu.{N}')
        pause()
        return
    run_action(lambda: (act_public(), act_app()), True)
    pause()


def main():
    load_config()
    startup()
    actions = {k: (fn, rep) for k, _, fn, rep in MENU}
    while True:
        header()
        try:
            choice = input('Chọn chức năng: ').strip()
            if choice == '0':
                break
            if choice not in actions:
                continue
            fn, report = actions[choice]
            run_action(fn, report)
            pause()
        except (KeyboardInterrupt, EOFError):
            print()
            break
    if S['tokens']:
        try:
            act_logout(quiet=True)
            print('Đã đăng xuất phiên kiểm tra.')
        except Exception:
            pass
    print('Tạm biệt!')


if __name__ == '__main__':
    main()