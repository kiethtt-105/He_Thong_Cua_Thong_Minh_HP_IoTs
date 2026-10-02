const vscode = require('vscode');
const cp = require('child_process');
const fs = require('fs');
const path = require('path');
const { html } = require('./webview');

let proc = null, buf = '', last = null;
const views = new Set();
const post = (m) => views.forEach((w) => w.postMessage(m));
const cfg = (k) => vscode.workspace.getConfiguration('smartlockVirtual').get(k);

function findDir() {
  const dirs = [cfg('deviceDir'), ...(vscode.workspace.workspaceFolders || []).flatMap((f) =>
    [path.join(f.uri.fsPath, 'virtual_device'), f.uri.fsPath]), path.join(__dirname, '..')];
  return dirs.find((d) => d && fs.existsSync(path.join(d, 'virtual_lock.py')));
}

function start() {
  if (proc) return;
  const dir = findDir();
  if (!dir) return vscode.window.showErrorMessage('Không thấy virtual_lock.py (đặt smartlockVirtual.deviceDir).');
  proc = cp.spawn(cfg('pythonPath') || 'python', ['virtual_lock.py', '--json'], {
    cwd: dir, env: { ...process.env, PYTHONIOENCODING: 'utf-8', PYTHONUNBUFFERED: '1' } });
  proc.stdout.setEncoding('utf8');
  proc.stdout.on('data', (d) => {
    buf += d;
    for (let i; (i = buf.indexOf('\n')) >= 0;) {
      const line = buf.slice(0, i).trim(); buf = buf.slice(i + 1);
      try { const m = JSON.parse(line); if (m.ev === 'state') last = m; post({ type: m.ev, m }); }
      catch { post({ type: 'log', m: { msg: line } }); }
    }
  });
  proc.stderr.on('data', (d) => post({ type: 'log', m: { msg: '⚠ ' + d } }));
  proc.on('error', (e) => post({ type: 'log', m: { msg: '❌ ' + e.message } }));
  proc.on('exit', () => { proc = null; last = null; post({ type: 'proc', running: false }); });
  post({ type: 'proc', running: true });
}

function send(cmd, args = []) { if (proc) proc.stdin.write(JSON.stringify({ cmd, args }) + '\n'); }

exports.activate = (ctx) => {
  ctx.subscriptions.push(vscode.window.registerWebviewViewProvider('smartlockVirtual.view', {
    resolveWebviewView(v) {
      views.add(v.webview);
      v.onDidDispose(() => views.delete(v.webview));
      v.webview.options = { enableScripts: true };
      v.webview.html = html();
      v.webview.onDidReceiveMessage((m) => {
        if (m.type === 'start') start();
        else if (m.type === 'stop') send('quit');
        else if (m.type === 'cmd') send(m.cmd, m.args);
        else if (m.type === 'ready') { v.webview.postMessage({ type: 'proc', running: !!proc }); if (last) v.webview.postMessage({ type: 'state', m: last }); }
      });
    } }, { webviewOptions: { retainContextWhenHidden: true } }));
};
exports.deactivate = () => proc && proc.kill();
