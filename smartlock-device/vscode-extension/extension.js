// SmartLock Device Simulator - điều khiển khoá (giả lập hoặc thiết bị thật) qua API cục bộ của firmware.
// Không cần build: JavaScript thuần, chỉ dùng module có sẵn của Node/VS Code.
const vscode = require('vscode');
const http = require('http');
const fs = require('fs');
const path = require('path');

let out, bar, tree, terminal, panel, sse, retry;
const S = { state: null, cfg: null, logs: [], online: false };
const LEVEL_ICON = { ok: 'pass', info: 'info', warn: 'warning', crit: 'error' };
const LOCK_TEXT = { locked: 'ĐÃ KHOÁ', unlocked: 'ĐANG MỞ', jammed: 'KẸT CHỐT' };

const conf = () => vscode.workspace.getConfiguration('smartlock');
const base = () => ({ host: conf().get('host') || '127.0.0.1', port: conf().get('port') || 8765 });
const tokenQ = () => (conf().get('token') ? `?token=${encodeURIComponent(conf().get('token'))}` : '');

// ---------------------------------------------------------------- HTTP
function call(method, p, body) {
  return new Promise((resolve, reject) => {
    const { host, port } = base();
    const data = body ? JSON.stringify(body) : null;
    const headers = { 'Content-Type': 'application/json' };
    if (conf().get('token')) headers['X-Token'] = conf().get('token');
    if (data) headers['Content-Length'] = Buffer.byteLength(data);
    const req = http.request({ host, port, path: p, method, headers, timeout: 4000 }, res => {
      let buf = ''; res.on('data', c => (buf += c));
      res.on('end', () => { try { resolve(JSON.parse(buf || '{}')); } catch (e) { reject(e); } });
    });
    req.on('timeout', () => req.destroy(new Error('timeout')));
    req.on('error', reject);
    if (data) req.write(data);
    req.end();
  });
}
const post = (p, b) => call('POST', p, b || {}).catch(() => { vscode.window.showWarningMessage('Khoá chưa chạy hoặc sai cổng. Chạy "SmartLock: Chạy khoá".'); return {}; });

// ---------------------------------------------------------------- SSE (live)
function connectSse() {
  clearTimeout(retry);
  if (sse) { try { sse.destroy(); } catch (_) {} }
  const { host, port } = base();
  const headers = conf().get('token') ? { 'X-Token': conf().get('token') } : {};
  sse = http.get({ host, port, path: '/api/stream', headers }, res => {
    S.online = true; refresh();
    let buf = '';
    res.setEncoding('utf8');
    res.on('data', chunk => {
      buf += chunk; let i;
      while ((i = buf.indexOf('\n\n')) >= 0) {
        const block = buf.slice(0, i); buf = buf.slice(i + 2);
        const line = block.split('\n').find(l => l.startsWith('data: '));
        if (line) { try { onMsg(JSON.parse(line.slice(6))); } catch (_) {} }
      }
    });
    res.on('end', lost); res.on('error', lost);
  });
  sse.on('error', lost);
}
function lost() { S.online = false; refresh(); retry = setTimeout(connectSse, 2000); }
let lastLock = null;
function onMsg(m) {
  if (m.t === 'hello') { S.state = m.s; S.cfg = m.cfg; S.logs = m.logs.slice(-40).reverse(); lastLock = m.s.lock_state; }
  else if (m.t === 'state') {
    S.state = m.s;
    if (lastLock && lastLock !== m.s.lock_state && conf().get('notifyDoor')) {
      if (m.s.lock_state === 'unlocked') vscode.window.setStatusBarMessage('$(unlock) Cửa vừa MỞ', 4000);
      if (m.s.lock_state === 'jammed') vscode.window.showWarningMessage('SmartLock: KẸT CHỐT!');
    }
    lastLock = m.s.lock_state;
  } else if (m.t === 'log') {
    S.logs.unshift(m.e); S.logs.length = Math.min(S.logs.length, 40);
    out.appendLine(`[${new Date(m.e.ts * 1000).toLocaleTimeString()}] ${m.e.kind.toUpperCase()} ${m.e.text}`);
    if (conf().get('notifyDoor') && m.e.level === 'crit') vscode.window.showErrorMessage(`SmartLock: ${m.e.text}`);
  }
  refresh();
}

// ---------------------------------------------------------------- Tree + status bar
class Provider {
  constructor() { this._e = new vscode.EventEmitter(); this.onDidChangeTreeData = this._e.event; }
  fire() { this._e.fire(); }
  getTreeItem(x) { return x; }
  getChildren(el) {
    const it = (label, desc, icon, cmd) => {
      const t = new vscode.TreeItem(label, vscode.TreeItemCollapsibleState.None);
      t.description = desc; t.iconPath = new vscode.ThemeIcon(icon);
      if (cmd) t.command = { command: cmd, title: label };
      return t;
    };
    const grp = (label, id, icon) => { const t = new vscode.TreeItem(label, vscode.TreeItemCollapsibleState.Expanded); t.id = id; t.iconPath = new vscode.ThemeIcon(icon); return t; };
    if (!el) {
      if (!S.online || !S.state) return [it('Khoá chưa chạy', 'bấm ▶ để khởi động', 'circle-slash', 'smartlock.start'), it('Mở device.conf', '', 'gear', 'smartlock.openConf')];
      return [grp('Trạng thái', 'g1', 'dashboard'), grp('Điều khiển & mô phỏng', 'g2', 'beaker'), grp('Sự kiện gần đây', 'g3', 'history')];
    }
    const s = S.state;
    if (el.id === 'g1') {
      const mq = s.standalone ? 'độc lập' : s.mqtt.connected ? 'online' : 'offline';
      return [
        it(s.name, `${s.code} · ${s.standalone ? 'standalone' : 'MQTT'}`, 'symbol-key'),
        it('Khoá', LOCK_TEXT[s.lock_state] + (s.lockout_remaining ? ` · khoá tạm ${s.lockout_remaining}s` : ''), s.lock_state === 'unlocked' ? 'unlock' : 'lock'),
        it('Pin', `${s.battery}%`, s.battery <= 20 ? 'warning' : 'plug'),
        it('Nhiệt độ', s.temperature == null ? '—' : `${s.temperature} °C`, 'flame'),
        it('Wi-Fi', !s.wifi.enabled ? 'tắt' : s.wifi.connected ? `${s.wifi.ssid} ${s.rssi == null ? '' : s.rssi + ' dBm'}` : 'mất mạng', 'broadcast'),
        it('MQTT', mq, 'cloud'),
        it('Bluetooth', !s.bluetooth.enabled ? 'tắt' : s.bluetooth.advertising ? 'đang quảng bá' : 'bật', 'bluetooth'),
        it('NFC', s.nfc.enabled ? 'bật' : 'tắt', 'credit-card'),
        it('Chống cạy', s.tamper ? '⚠ CẠY PHÁ' : 'bình thường', s.tamper ? 'error' : 'shield'),
        it('Sự kiện chờ gửi', String(s.events_queued), 'inbox'),
      ];
    }
    if (el.id === 'g2') return [
      it('Quẹt thẻ', '', 'credit-card', 'smartlock.tapCard'), it('Nhập PIN', '', 'symbol-numeric', 'smartlock.enterPin'),
      it('Quét khuôn mặt', '', 'account', 'smartlock.scanFace'), it('Vé điện thoại (BLE/NFC)', '', 'device-mobile', 'smartlock.phoneTicket'),
      it('Mở bằng núm trong nhà', '', 'unlock', 'smartlock.knobUnlock'), it('Khoá bằng núm', '', 'lock', 'smartlock.knobLock'),
      it('Bật/tắt Wi-Fi/BT/NFC', '', 'settings', 'smartlock.toggleRadio'), it('Giả lập cạy phá', '', 'bell', 'smartlock.tamper'),
      it('Giả lập kẹt chốt', '', 'tools', 'smartlock.jam'), it('Live View', '', 'preview', 'smartlock.openLive'),
    ];
    if (el.id === 'g3') return S.logs.slice(0, 12).map(e => it(e.text, new Date(e.ts * 1000).toLocaleTimeString(), LEVEL_ICON[e.level] || 'info'));
    return [];
  }
}
function refresh() {
  tree && tree.fire();
  const s = S.state;
  if (!S.online || !s) { bar.text = '$(circle-slash) SmartLock'; bar.tooltip = 'Khoá chưa chạy - bấm để chạy'; bar.command = 'smartlock.start'; }
  else {
    bar.text = `$(${s.lock_state === 'unlocked' ? 'unlock' : 'lock'}) ${LOCK_TEXT[s.lock_state]} · $(plug) ${s.battery}%` + (s.standalone ? '' : s.mqtt.connected ? ' · $(cloud)' : ' · $(debug-disconnect)');
    bar.tooltip = `${s.name} (${s.code})\nBấm để mở Live View`; bar.command = 'smartlock.openLive';
  }
  bar.backgroundColor = S.state && S.state.lock_state === 'jammed' ? new vscode.ThemeColor('statusBarItem.warningBackground') : undefined;
  bar.show();
}

// ---------------------------------------------------------------- chạy / dừng
function firmwareDir() {
  const c = conf().get('firmwarePath');
  if (c) return c;
  for (const f of vscode.workspace.workspaceFolders || []) {
    for (const cand of [f.uri.fsPath, path.join(f.uri.fsPath, 'firmware')]) {
      if (fs.existsSync(path.join(cand, 'smartlock_fw', '__main__.py'))) return cand;
    }
  }
  return null;
}
const confPath = fw => conf().get('configPath') || path.join(fw, 'device.conf');
const q = s => `"${s}"`;

function getTerminal(fw) {
  if (!terminal || terminal.exitStatus) terminal = vscode.window.createTerminal({ name: 'SmartLock Device', cwd: fw });
  return terminal;
}
function needFw() {
  const fw = firmwareDir();
  if (!fw) vscode.window.showErrorMessage('Không tìm thấy thư mục firmware (smartlock_fw). Đặt "smartlock.firmwarePath" trong Settings.');
  return fw;
}
function runCli(args, show = true) {
  const fw = needFw(); if (!fw) return;
  const t = getTerminal(fw); if (show) t.show(true);
  t.sendText(`${conf().get('python')} -m smartlock_fw -c ${q(confPath(fw))} ${args}`);
}

async function startDevice() {
  if (S.online) return vscode.window.showInformationMessage('Khoá đang chạy.');
  const fw = needFw(); if (!fw) return;
  if (!fs.existsSync(confPath(fw))) {
    const pick = await vscode.window.showWarningMessage('Chưa có device.conf. Tạo mới (sinh secret) ngay?', 'Tạo', 'Huỷ');
    if (pick !== 'Tạo') return;
    return initConf();
  }
  runCli('run');
}
function stopDevice() {
  if (terminal && !terminal.exitStatus) { terminal.sendText('\u0003', false); vscode.window.setStatusBarMessage('Đã gửi Ctrl+C cho khoá', 3000); }
}
function initConf() {
  const fw = needFw(); if (!fw) return;
  runCli('init --force');
  vscode.window.showInformationMessage('Đã tạo device.conf. Xem terminal để lấy lệnh đăng ký khoá lên máy chủ; chỉnh file rồi chạy khoá.', 'Mở device.conf')
    .then(p => p && openConf());
}
async function openConf() {
  const fw = needFw(); if (!fw) return;
  const p = confPath(fw);
  if (!fs.existsSync(p)) return vscode.window.showWarningMessage('Chưa có device.conf - chạy "SmartLock: Tạo device.conf mới".');
  vscode.window.showTextDocument(await vscode.workspace.openTextDocument(p));
}

// ---------------------------------------------------------------- Live view
async function openLive() {
  const { host, port } = base();
  const ext = await vscode.env.asExternalUri(vscode.Uri.parse(`http://${host}:${port}/${tokenQ()}${tokenQ() ? '&' : '?'}embed=1`));
  if (panel) { panel.reveal(); return; }
  panel = vscode.window.createWebviewPanel('smartlockLive', 'SmartLock Live', vscode.ViewColumn.Beside, { enableScripts: true, retainContextWhenHidden: true });
  panel.onDidDispose(() => (panel = undefined));
  panel.webview.html = `<!doctype html><html><head><meta charset="utf-8">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; frame-src http: https:; style-src 'unsafe-inline';">
<style>html,body,iframe{margin:0;padding:0;width:100%;height:100%;border:0;background:transparent}</style></head>
<body><iframe src="${ext.toString(true)}"></iframe></body></html>`;
}
function openBrowser() { const { host, port } = base(); vscode.env.openExternal(vscode.Uri.parse(`http://${host}:${port}/${tokenQ()}`)); }

// ---------------------------------------------------------------- lệnh mô phỏng
async function tapCard() {
  const cards = Object.entries((S.cfg && S.cfg.cards) || {}).map(([k, v]) => ({ label: k, description: v, uid: v }));
  cards.push({ label: '$(edit) Nhập UID khác…', uid: null }, { label: '$(question) Thẻ lạ ngẫu nhiên', uid: 'RAND' });
  const p = await vscode.window.showQuickPick(cards, { placeHolder: 'Chọn thẻ để quẹt' }); if (!p) return;
  let uid = p.uid;
  if (uid === null) uid = await vscode.window.showInputBox({ prompt: 'UID thẻ (hex)', placeHolder: '04A1B2C3' });
  if (uid === 'RAND') uid = Math.floor(Math.random() * 0xffffffff).toString(16).toUpperCase().padStart(8, '0');
  if (uid) post('/api/sim/rfid', { uid });
}
async function enterPin() {
  const pin = await vscode.window.showInputBox({ prompt: 'Nhập PIN (4-8 số) - tương đương bấm phím rồi #', password: true, validateInput: v => (/^\d{4,8}$/.test(v) ? null : '4-8 chữ số') });
  if (pin) post('/api/sim/pin', { pin });
}
async function scanFace() {
  const items = [...((S.cfg && S.cfg.faces) || []).map(f => ({ label: f, who: f })), { label: 'Người lạ', who: 'stranger' }];
  const p = await vscode.window.showQuickPick(items, { placeHolder: 'Ai đứng trước camera?' }); if (p) post('/api/sim/face', { who: p.who });
}
async function phoneTicket() {
  const k = await vscode.window.showQuickPick([{ label: 'Bluetooth', v: 'ble' }, { label: 'NFC (điện thoại giả lập thẻ)', v: 'nfc' }], { placeHolder: 'Kênh' }); if (!k) return;
  const ticket = await vscode.window.showInputBox({ prompt: 'Dán vé lấy từ app (POST /devices/<id>/' + k.v + '-ticket/)', ignoreFocusOut: true }); if (!ticket) return;
  post('/api/sim/' + k.v, { ticket: ticket.trim() });
}
async function mintTicket() {
  const k = await vscode.window.showQuickPick([{ label: 'Bluetooth', v: 'ble' }, { label: 'NFC', v: 'nfc' }], { placeHolder: 'Kênh' }); if (!k) return;
  const user = await vscode.window.showInputBox({ prompt: 'user_id (UUID) của tài khoản có quyền; trống = mặc định standalone', ignoreFocusOut: true });
  const ttl = await vscode.window.showQuickPick([{ label: '1 giờ', v: 3600 }, { label: '60 giây', v: 60 }, { label: 'Đã hết hạn (test từ chối)', v: -5 }], { placeHolder: 'Hiệu lực' }); if (!ttl) return;
  const r = await post('/api/ticket', { kind: k.v, user_id: user || undefined, ttl: ttl.v });
  if (!r.ticket) return;
  await vscode.env.clipboard.writeText(r.ticket);
  const pick = await vscode.window.showInformationMessage('Đã sao chép vé vào clipboard.', 'Dùng ngay');
  if (pick) post('/api/sim/' + k.v, { ticket: r.ticket });
}
async function toggleRadio() {
  const s = S.state; if (!s) return;
  const items = [['wifi', 'Wi-Fi', s.wifi.enabled], ['bluetooth', 'Bluetooth', s.bluetooth.enabled], ['nfc', 'NFC', s.nfc.enabled]]
    .map(([id, label, on]) => ({ label: `${label}: ${on ? 'BẬT → tắt' : 'TẮT → bật'}`, id, on }));
  const p = await vscode.window.showQuickPick(items); if (p) post('/api/radio', { name: p.id, on: !p.on });
}

function activate(ctx) {
  out = vscode.window.createOutputChannel('SmartLock');
  bar = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Left, 50);
  tree = new Provider();
  ctx.subscriptions.push(out, bar, vscode.window.registerTreeDataProvider('smartlock.device', tree));
  const reg = (id, fn) => ctx.subscriptions.push(vscode.commands.registerCommand(id, fn));
  reg('smartlock.start', startDevice); reg('smartlock.stop', stopDevice); reg('smartlock.init', initConf);
  reg('smartlock.openConf', openConf); reg('smartlock.openLive', openLive); reg('smartlock.openBrowser', openBrowser);
  reg('smartlock.tapCard', tapCard); reg('smartlock.enterPin', enterPin); reg('smartlock.scanFace', scanFace);
  reg('smartlock.phoneTicket', phoneTicket); reg('smartlock.mintTicket', mintTicket); reg('smartlock.toggleRadio', toggleRadio);
  reg('smartlock.tamper', () => post('/api/sim/tamper', { on: !(S.state && S.state.tamper) }));
  reg('smartlock.jam', () => post('/api/sim/jam', { on: !(S.state && S.state.jammed) }));
  reg('smartlock.knobUnlock', () => post('/api/unlock')); reg('smartlock.knobLock', () => post('/api/lock'));
  reg('smartlock.reboot', () => post('/api/reboot')); reg('smartlock.doctor', () => runCli('doctor'));
  ctx.subscriptions.push(vscode.workspace.onDidChangeConfiguration(e => { if (e.affectsConfiguration('smartlock')) connectSse(); }));
  refresh(); connectSse();
  if (conf().get('autoStart')) setTimeout(() => !S.online && startDevice(), 1500);
}
function deactivate() { clearTimeout(retry); if (sse) sse.destroy(); }
module.exports = { activate, deactivate };
