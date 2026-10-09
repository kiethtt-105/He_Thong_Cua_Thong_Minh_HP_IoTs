"""Đọc Wi-Fi THẬT của máy đang chạy giả lập (thay cho "mạng Wi-Fi ảo"), giống ESP32 dùng Wi-Fi của chính nó.
Chỉ đọc (SSID đang nối, cường độ tín hiệu, danh sách mạng xung quanh) - KHÔNG đổi Wi-Fi của máy.
  Windows : netsh wlan show interfaces / networks
  Linux   : nmcli (NetworkManager), dự phòng iwgetid
  macOS   : airport -I / networksetup (macOS mới bị Apple ẩn SSID thì sẽ báo không đọc được)
Không đọc được (máy cắm dây LAN, thiếu quyền vị trí trên Windows 11...) -> error có lời giải thích; UI cho nhập SSID tay.
"""
import platform
import re
import shutil
import subprocess
import threading
import time

_cache = {'t': 0.0, 'v': None}
_mtx = threading.Lock()
TTL = 8.0


def pct_to_dbm(p):
    return int(round(max(0, min(100, int(p))) / 2 - 100))        # công thức Microsoft: RSSI ≈ chất lượng/2 - 100


def _run(cmd, timeout=8):
    try:
        r = subprocess.run(cmd, capture_output=True, timeout=timeout)
    except (OSError, subprocess.SubprocessError):
        return None
    return (r.stdout or b'').decode('utf-8', 'replace') + (('\n' + r.stderr.decode('utf-8', 'replace')) if not r.stdout else '')


# ------------------------------------------------------------------ Windows
def parse_win_interfaces(txt):
    """-> {'ssid','rssi'} hoặc None. Nhãn netsh có thể bị dịch -> chỉ dựa vào 'SSID' (không dịch) và dấu %."""
    ssid, pct = None, None
    for line in txt.splitlines():
        m = re.match(r'^\s*SSID\s*:\s*(.*?)\s*$', line)
        if m and ssid is None:
            ssid = m.group(1)
        m = re.match(r'^\s*[^:]+:\s*(\d{1,3})\s*%\s*$', line)
        if m and pct is None:
            pct = int(m.group(1))
    if not ssid:
        return None
    return {'ssid': ssid, 'rssi': pct_to_dbm(pct) if pct is not None else None}


def parse_win_networks(txt):
    out, cur = [], None
    for line in txt.splitlines():
        m = re.match(r'^\s*SSID\s+\d+\s*:\s*(.*?)\s*$', line)
        if m:
            cur = {'ssid': m.group(1), 'rssi': None, 'secured': True}
            out.append(cur)
            continue
        if cur is None:
            continue
        m = re.match(r'^\s*[^:]+:\s*(.*?)\s*$', line)
        if not m:
            continue
        val = m.group(1)
        pm = re.fullmatch(r'(\d{1,3})\s*%', val)
        if pm:
            d = pct_to_dbm(int(pm.group(1)))
            cur['rssi'] = d if cur['rssi'] is None else max(cur['rssi'], d)
        elif re.match(r'^\s*[A-Za-z][^:]*:', line) and val.lower() in ('open', 'mở'):
            cur['secured'] = False
    return [n for n in out if n['ssid']]


# ------------------------------------------------------------------ Linux (nmcli -t)
def _split_nm(line):
    return [p.replace('\\:', ':').replace('\\\\', '\\') for p in re.split(r'(?<!\\):', line)]


def parse_nmcli(txt):
    """Dòng: IN-USE:SSID:SIGNAL:SECURITY  (-t, dấu ':' trong SSID được escape bằng '\\:')."""
    nets = []
    for line in txt.splitlines():
        p = _split_nm(line)
        if len(p) < 3 or not p[1]:
            continue
        sig = int(p[2]) if p[2].isdigit() else None
        nets.append({'ssid': p[1], 'rssi': pct_to_dbm(sig) if sig is not None else None,
                     'secured': bool(len(p) > 3 and p[3].strip() not in ('', '--')), 'connected': p[0].strip() == '*'})
    return nets


# ------------------------------------------------------------------ macOS
def parse_airport_i(txt):
    ssid = re.search(r'^\s*SSID:\s*(.+?)\s*$', txt, re.M)
    rssi = re.search(r'agrCtlRSSI:\s*(-?\d+)', txt)
    if not ssid:
        return None
    return {'ssid': ssid.group(1), 'rssi': int(rssi.group(1)) if rssi else None}


# ------------------------------------------------------------------ gom lại
def _read():
    sysname = platform.system()
    res = {'platform': sysname, 'connected': None, 'networks': [], 'error': ''}
    if sysname == 'Windows':
        txt = _run(['netsh', 'wlan', 'show', 'interfaces'])
        if txt is None:
            res['error'] = 'Không chạy được netsh.'
        else:
            res['connected'] = parse_win_interfaces(txt)
            if not res['connected']:
                res['error'] = ('Máy không nối Wi-Fi (đang dùng cáp LAN?) hoặc Windows chặn đọc SSID: bật Cài đặt → Quyền riêng tư → Vị trí '
                                '(cho phép ứng dụng truy cập vị trí) rồi thử lại.')
            nets = _run(['netsh', 'wlan', 'show', 'networks', 'mode=bssid'], timeout=12)
            if nets:
                res['networks'] = parse_win_networks(nets)
    elif sysname == 'Linux':
        if shutil.which('nmcli'):
            txt = _run(['nmcli', '-t', '-f', 'IN-USE,SSID,SIGNAL,SECURITY', 'dev', 'wifi', 'list'], timeout=12)
            if txt:
                res['networks'] = parse_nmcli(txt)
        cur = next((n for n in res['networks'] if n.get('connected')), None)
        if cur:
            res['connected'] = {'ssid': cur['ssid'], 'rssi': cur['rssi']}
        elif shutil.which('iwgetid'):
            s = (_run(['iwgetid', '-r']) or '').strip()
            if s:
                res['connected'] = {'ssid': s, 'rssi': None}
        if not res['connected']:
            res['error'] = 'Không đọc được Wi-Fi (máy dùng cáp LAN, hoặc thiếu nmcli/iwgetid).'
    elif sysname == 'Darwin':
        ap = '/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport'
        res['connected'] = parse_airport_i(_run([ap, '-I']) or '')
        if not res['connected']:
            m = re.search(r':\s*(.+)$', (_run(['networksetup', '-getairportnetwork', 'en0']) or '').strip())
            if m and 'not associated' not in m.group(0).lower():
                res['connected'] = {'ssid': m.group(1).strip(), 'rssi': None}
        if not res['connected']:
            res['error'] = 'Không đọc được Wi-Fi (macOS mới ẩn SSID với ứng dụng dòng lệnh, hoặc máy dùng LAN).'
    else:
        res['error'] = f'Hệ điều hành {sysname} chưa hỗ trợ đọc Wi-Fi.'
    c = res['connected']
    if c:
        for n in res['networks']:
            n['connected'] = n['ssid'] == c['ssid']
        if not any(n['ssid'] == c['ssid'] for n in res['networks']):
            res['networks'].insert(0, {'ssid': c['ssid'], 'rssi': c['rssi'], 'secured': True, 'connected': True})
    res['networks'].sort(key=lambda n: (not n.get('connected'), -(n['rssi'] if n['rssi'] is not None else -200)))
    return res


def status(force=False):
    """Kết quả có cache vài giây (gọi lệnh hệ thống khá chậm)."""
    with _mtx:
        if not force and _cache['v'] and time.time() - _cache['t'] < TTL:
            return _cache['v']
    v = _read()
    with _mtx:
        _cache['v'], _cache['t'] = v, time.time()
    return v
