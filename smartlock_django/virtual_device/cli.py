# virtual_device/cli.py
"""
python -m virtual_device <lệnh> [--profile tên]

  provision      Tạo bản ghi khoá trong DB (status=provisioning, chưa có chủ) + sinh identity.json
  info           In mã/secret/broker/topic + trạng thái kết nối & chủ sở hữu trên server
  run            Chạy khoá ảo (nối MQTT, gửi status, nhận lệnh, REPL để mô phỏng thao tác)
  ui             Như run nhưng có GIAO DIỆN WEB mô phỏng khoá (mở trong VS Code Simple Browser)
  claim          Gán khoá cho tài khoản ADMIN (đợi khoá online trước) hoặc user (--as-user)
  ping           Gửi PING hai chiều từ server tới khoá, chờ ack
  release        Gỡ chủ (factory_reset -> revoked) để thử luồng user tự claim
  rotate-secret  Xoay provisioning secret, cập nhật identity.json
"""
import argparse
import logging
import random
import secrets
import sys
import time

from . import config
from .store import Store


# ---------------------------------------------------------------------------- tiện ích
def _store(a) -> Store:
    return Store(a.profile)


def _need_identity(a) -> dict:
    ident = _store(a).load_identity()
    if not ident:
        raise SystemExit(f'Chưa có identity cho profile "{a.profile}". Chạy: '
                         f'python -m virtual_device provision --profile {a.profile}')
    return ident


def _random_mac() -> str:
    # 02:xx = locally administered unicast; models.Device yêu cầu CHỮ HOA
    return ':'.join(['02'] + [f'{random.randint(0, 255):02X}' for _ in range(5)])


def _device(ident):
    from smartlock.models import Device
    d = Device.objects.filter(device_code=ident['device_code']).first()
    if not d:
        raise SystemExit(f'Không thấy {ident["device_code"]} trong DB (đã bị xoá?). Hãy provision lại với --force.')
    return d


def _admin_user(identifier):
    from smartlock import services
    u = services.find_user(identifier)
    if not u:
        raise SystemExit(f'Không tìm thấy tài khoản "{identifier}".')
    if not services.is_admin(u):
        raise SystemExit(f'"{identifier}" không phải admin (cần is_admin / is_staff / is_superuser).')
    return u


def _audit(action, device, actor=None, target=None, success=True, severity='info', **meta):
    from smartlock.models import AuditLog
    meta.setdefault('via', 'virtual_device_cli')
    AuditLog.objects.create(actor_user=actor, target_user=target, device=device, action=action[:50],
                            success=success, severity=severity, metadata=meta)


# ---------------------------------------------------------------------------- provision
def cmd_provision(a):
    store = _store(a)
    if store.has_identity() and not a.force:
        raise SystemExit(f'Profile "{a.profile}" đã có identity ({store.identity_path}). Dùng --force để tạo mới.')
    from .django_bridge import boot
    boot()
    from django.core.exceptions import ValidationError
    from smartlock.models import Device
    from smartlock.services import hash_token

    code = (a.code or f'DEV-{secrets.token_hex(4).upper()}').strip().upper()
    while not a.code and Device.objects.filter(device_code=code).exists():
        code = f'DEV-{secrets.token_hex(4).upper()}'
    if Device.objects.filter(device_code=code).exists():
        raise SystemExit(f'device_code {code} đã tồn tại.')

    secret = secrets.token_hex(16)            # secret gốc: chỉ khoá ảo giữ, DB chỉ lưu hash
    mac = (a.mac or _random_mac()).upper()
    device = Device(
        device_code=code, provisioning_secret_hash=hash_token(secret), device_mode='simulated',
        owner=None, status='provisioning', name=a.name, mac_address=mac,
        firmware_version=a.firmware, battery_level=100, location=a.location or None,
    )
    try:
        device.full_clean()
    except ValidationError as e:
        raise SystemExit(f'Dữ liệu thiết bị không hợp lệ: {e}')
    device.save()
    _audit('VDEVICE_PROVISIONED', device, device_code=code, mac=mac)

    store.save_identity({
        'device_code': code, 'secret': secret, 'device_id': str(device.id), 'name': a.name,
        'mac_address': mac, 'firmware_version': a.firmware, 'location': a.location,
        'mqtt_host': config.MQTT_HOST, 'mqtt_port': config.MQTT_PORT,
    })
    store.save_state({})
    print(f'''
✔ Đã tạo khoá ảo (status=provisioning, CHƯA có chủ)
  Tên           : {a.name}
  Device code   : {code}
  Secret        : {secret}      <- chỉ hiện lúc này, đã lưu vào {store.identity_path}
  MAC           : {mac}
  Firmware      : {a.firmware}

Bước tiếp theo:
  1) Terminal A:  python manage.py mqtt_subscriber
  2) Terminal B:  python -m virtual_device run --profile {a.profile}
  3) Terminal C:  python -m virtual_device claim --profile {a.profile} --admin <email_admin>
''')


# ---------------------------------------------------------------------------- info
def cmd_info(a):
    ident = _need_identity(a)
    code = ident['device_code']
    print(f'''== Thông tin trên khoá ảo (profile "{a.profile}") ==
  Device code : {code}
  Secret      : {ident["secret"]}
  MAC         : {ident.get("mac_address")}
  Firmware    : {ident.get("firmware_version")}
== Kết nối MQTT ==
  Broker      : {config.MQTT_HOST}:{config.MQTT_PORT}  (TLS={config.MQTT_TLS})
  Username    : {code}
  Password    : <secret ở trên>
  Nghe lệnh   : {config.topic_cmd(code)}
  Gửi         : {config.topic_status(code)}  |  {config.topic_ack(code)}  |  {config.topic_event(code)}''')
    try:
        from .django_bridge import boot
        boot()
        from smartlock import services
        d = _device(ident)
        ls = services.link_status(d)
        owner = d.owner.email if d.owner_id else '(chưa có chủ)'
        print(f'''== Trạng thái trên server ==
  Tên / mode  : {d.name} / {d.device_mode}
  Status      : {d.status}
  Chủ sở hữu  : {owner}
  Kết nối     : {"CÓ" if ls["connected"] else "KHÔNG"}  (thấy lần cuối {ls["seconds_ago"]}s trước)
  Pin / FW    : {d.battery_level}% / {d.firmware_version}
  PING gần nhất: {ls["ping_status"]}''')
    except SystemExit as e:
        print(f'(bỏ qua phần server: {e})')
    except Exception as e:
        print(f'(không đọc được DB: {e})')


# ---------------------------------------------------------------------------- claim
def cmd_claim(a):
    ident = _need_identity(a)
    from .django_bridge import boot
    boot()
    from smartlock import services
    from smartlock.models import AuditLog
    device = _device(ident)

    if device.owner_id:
        raise SystemExit(f'Khoá đã có chủ: {device.owner.email}. Dùng "release" nếu muốn gỡ.')

    # Điều kiện của services.claim_device: khoá phải ĐANG kết nối thật -> chờ status đầu tiên.
    deadline = time.time() + a.wait
    while not services.link_status(device)['connected']:
        if time.time() >= deadline:
            raise SystemExit(
                'Khoá chưa kết nối với hệ thống. Kiểm tra: (1) "python -m virtual_device run" đang chạy và hiện '
                'ONLINE, (2) "python manage.py mqtt_subscriber" đang chạy, (3) broker/webhook auth.')
        print('… đợi khoá gửi status đầu tiên', end='\r', flush=True)
        time.sleep(2)

    try:
        if a.as_user:
            user = services.find_user(a.as_user)
            if not user:
                raise SystemExit(f'Không tìm thấy user "{a.as_user}".')
            device = services.user_claim_device(user, ident['device_code'], ident['secret'])
            who, by = user, 'user'
        else:
            who = _admin_user(a.admin)
            device = services.claim_device(device.pk, who, by_admin=True)
            by = 'admin'
    except services.ClaimError as e:
        AuditLog.objects.create(actor_user=None, device=device, action='DEVICE_CLAIM_FAILED', success=False,
                                severity='warning', metadata={'code': e.code, 'via': 'virtual_device_cli'})
        raise SystemExit(f'Claim thất bại [{e.code}]: {e.message}')

    _audit('DEVICE_CLAIMED', device, actor=who, target=who, severity='warning', by=by)
    services.notify(who, 'Đã thêm khoá vào tài khoản',
                    f'Khoá "{device.name}" ({device.device_code}) đã được gán cho bạn.',
                    device=device, type_='DEVICE')
    print(f'✔ Đã gán "{device.name}" ({device.device_code}) cho {who.email} (by {by}). Status = {device.status}.')
    if a.ping:
        _do_ping(device, who)


# ---------------------------------------------------------------------------- ping
def _do_ping(device, issuer, timeout=15):
    from smartlock import services
    from smartlock.models import DeviceCommand
    cmd = services.ping_device(device, issuer)
    if cmd.status != 'sent':
        print(f'✘ Không publish được PING: {getattr(cmd, "publish_error", "")}')
        return False
    end = time.time() + timeout
    while time.time() < end:
        cur = DeviceCommand.objects.get(pk=cmd.pk)
        if cur.status == 'acknowledged':
            print(f'✔ PING ack sau {(cur.acknowledged_at - cur.created_at).total_seconds():.2f}s (kết nối 2 chiều OK)')
            return True
        time.sleep(0.5)
    print('✘ Không thấy ack trong thời gian chờ (subscriber có chạy và xử lý topic /ack không?)')
    return False


def cmd_ping(a):
    ident = _need_identity(a)
    from .django_bridge import boot
    boot()
    _do_ping(_device(ident), _admin_user(a.admin))


# ---------------------------------------------------------------------------- release / rotate
def cmd_release(a):
    ident = _need_identity(a)
    from .django_bridge import boot
    boot()
    from smartlock import services
    d = _device(ident)
    try:
        d, prev, counts = services.release_device(d.pk)
    except services.ClaimError as e:
        raise SystemExit(f'[{e.code}] {e.message}')
    _audit('DEVICE_RELEASED', d, target=prev, severity='warning', counts=counts)
    print(f'✔ Đã gỡ chủ ({prev.email}). Status = {d.status}. Admin KHÔNG gán lại được; hãy claim bằng '
          f'"claim --as-user <email>".  Đã thu hồi: {counts}')


def cmd_rotate(a):
    ident = _need_identity(a)
    from .django_bridge import boot
    boot()
    from smartlock import services
    d = _device(ident)
    d, new_secret = services.rotate_secret(d.pk)
    ident['secret'] = new_secret
    _store(a).save_identity(ident)
    _audit('DEVICE_SECRET_ROTATED', d, severity='warning')
    print('✔ Đã xoay secret và cập nhật identity.json. Khởi động lại "run" để nối bằng secret mới '
          '(vé BLE/NFC cũ mất hiệu lực).')


# ---------------------------------------------------------------------------- run + REPL
HELP = '''Lệnh mô phỏng:
  status                    xem trạng thái khoá ảo
  lock | unlock             thao tác cơ khí tại chỗ (nút trong nhà)
  rfid <UID>                quẹt thẻ RFID          (cần online; server xác thực rồi gửi UNLOCK về)
  pin <mã>                  nhập PIN bàn phím      (cần online)
  face [n]                  quét mặt giả (embedding n chiều, mặc định 128)
  ticket ble|nfc <user_id>  tạo vé thử bằng secret của khoá (user_id = UUID của user, in ra để dùng)
  ble <vé> | nfc <vé>       đưa vé điện thoại vào khoá (OFFLINE vẫn mở được)
  offline | online          ngắt / bật lại mạng (mô phỏng mất Wi-Fi)
  battery <0-100>           đặt mức pin (0 = chết máy)
  tamper on|off             báo cạy phá
  jam on|off                kẹt / gỡ kẹt chốt khoá
  radio ble|nfc on|off      bật/tắt radio của khoá
  reboot                    khởi động lại
  help | quit               trợ giúp / rút điện thoát'''


def _repl(lock):
    print(HELP)
    while not lock._stop.is_set():
        try:
            line = input('virtual-lock> ').strip()
        except (EOFError, KeyboardInterrupt):
            break
        if not line:
            continue
        p = line.split()
        c, args = p[0].lower(), p[1:]
        try:
            if c in ('quit', 'exit', 'q'):
                break
            elif c == 'help':
                print(HELP)
            elif c == 'status':
                print(lock.summary())
            elif c == 'lock':
                lock.set_lock('locked', 'manual')
            elif c == 'unlock':
                lock.set_lock('unlocked', 'manual')
            elif c == 'rfid' and args:
                lock.tap_rfid(args[0])
            elif c == 'pin' and args:
                lock.enter_pin(args[0])
            elif c == 'face':
                n = int(args[0]) if args else 128
                lock.scan_face([round(random.uniform(-1, 1), 4) for _ in range(n)])
            elif c == 'ticket' and len(args) == 2 and args[0] in ('ble', 'nfc'):
                from . import tickets
                t, exp = tickets.mint(lock.sec_hash, lock.code, args[0], args[1].replace('-', ''))
                print(t)
            elif c in ('ble', 'nfc') and args:
                lock.phone_unlock(c, args[0])
            elif c == 'offline':
                lock.go_offline()
            elif c == 'online':
                lock.go_online()
            elif c == 'battery' and args:
                lock.set_battery(int(args[0]))
            elif c == 'tamper' and args:
                lock.set_tamper(args[0] == 'on')
            elif c == 'jam' and args:
                lock.set_jam(args[0] == 'on')
            elif c == 'radio' and len(args) == 2:
                lock.toggle_radio(args[0], args[1] == 'on')
            elif c == 'reboot':
                lock.reboot('manual')
            else:
                print('Lệnh không hiểu. Gõ "help".')
        except ValueError:
            print('Tham số không hợp lệ. Gõ "help".')


def cmd_run(a):
    from .device import VirtualLock
    lock = VirtualLock(a.profile, auto_lock=a.auto_lock, status_interval=a.status_interval,
                       battery_every=a.battery_every)
    if a.offline_start:
        lock.network_up = False
    lock.start()
    try:
        if a.no_repl or not sys.stdin.isatty():
            lock.wait()
        else:
            _repl(lock)
    except KeyboardInterrupt:
        pass
    finally:
        lock.stop()


def cmd_ui(a):
    from .device import VirtualLock
    from .ui import LockUI
    lock = VirtualLock(a.profile, auto_lock=a.auto_lock, status_interval=a.status_interval,
                       battery_every=a.battery_every)
    if a.offline_start:
        lock.network_up = False
    app = LockUI(lock)          # gắn bộ thu log TRƯỚC khi start để UI thấy cả log khởi động
    lock.start()
    try:
        app.serve(a.port, a.open)
    finally:
        lock.stop()


# ---------------------------------------------------------------------------- main
def build_parser():
    ap = argparse.ArgumentParser(prog='virtual_device', description='Khoá thông minh ảo cho smartlock_django')
    ap.add_argument('-v', '--verbose', action='store_true', help='log chi tiết (gồm cả heartbeat)')
    sub = ap.add_subparsers(dest='cmd', required=True)

    def add(name, fn, help_):
        sp = sub.add_parser(name, help=help_)
        sp.add_argument('--profile', default='default', help='tên bộ nhớ khoá ảo (chạy được nhiều khoá song song)')
        sp.set_defaults(fn=fn)
        return sp

    p = add('provision', cmd_provision, 'tạo khoá mới (DB + identity.json)')
    p.add_argument('--name', default='Khoá ảo')
    p.add_argument('--location', default='')
    p.add_argument('--mac', help='AA:BB:CC:DD:EE:FF (mặc định ngẫu nhiên)')
    p.add_argument('--code', help='tự đặt device_code (mặc định DEV-XXXXXXXX)')
    p.add_argument('--firmware', default=config.DEFAULT_FIRMWARE)
    p.add_argument('--force', action='store_true', help='ghi đè identity hiện có')

    add('info', cmd_info, 'xem thông tin kết nối & trạng thái server')

    p = add('run', cmd_run, 'chạy khoá ảo')
    p.add_argument('--no-repl', action='store_true', help='không mở dòng lệnh tương tác')
    p.add_argument('--offline-start', action='store_true', help='khởi động khi đang "mất mạng"')
    p.add_argument('--auto-lock', type=int, default=None, help='giây tự khoá lại (0 = tắt)')
    p.add_argument('--status-interval', type=int, default=None, help='giây giữa 2 lần gửi status')
    p.add_argument('--battery-every', type=int, default=None, help='giây hao 1%% pin (0 = tắt)')

    p = add('ui', cmd_ui, 'chạy khoá ảo kèm giao diện web')
    p.add_argument('--port', type=int, default=8765)
    p.add_argument('--open', action='store_true', help='tự mở trình duyệt ngoài')
    p.add_argument('--offline-start', action='store_true')
    p.add_argument('--auto-lock', type=int, default=None)
    p.add_argument('--status-interval', type=int, default=None)
    p.add_argument('--battery-every', type=int, default=None)

    p = add('claim', cmd_claim, 'gán khoá cho admin (hoặc user)')
    g = p.add_mutually_exclusive_group(required=True)
    g.add_argument('--admin', help='email/username tài khoản admin')
    g.add_argument('--as-user', help='email/username user tự claim bằng code+secret (dùng cho khoá đã revoked)')
    p.add_argument('--wait', type=int, default=60, help='giây chờ khoá online (mặc định 60)')
    p.add_argument('--ping', action='store_true', help='PING kiểm tra 2 chiều sau khi claim')

    p = add('ping', cmd_ping, 'PING hai chiều')
    p.add_argument('--admin', required=True)

    add('release', cmd_release, 'gỡ chủ (factory_reset -> revoked)')
    add('rotate-secret', cmd_rotate, 'xoay provisioning secret')
    return ap


def main():
    a = build_parser().parse_args()
    logging.basicConfig(level=logging.DEBUG if a.verbose else logging.INFO,
                        format='%(asctime)s %(levelname)-7s %(message)s', datefmt='%H:%M:%S')
    logging.getLogger('django').setLevel(logging.WARNING)
    a.fn(a)
