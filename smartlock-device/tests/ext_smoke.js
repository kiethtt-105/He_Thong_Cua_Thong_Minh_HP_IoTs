// Chạy thử extension với vscode giả: node tests/ext_smoke.js   (cần firmware đang chạy ở cổng 8799)
const Module = require('module'); const path = require('path');
const calls = []; const cmds = {};
const vscode = {
  EventEmitter: class { constructor() { this.event = () => {}; } fire() {} },
  TreeItem: class { constructor(l, c) { this.label = l; this.collapsibleState = c; } },
  ThemeIcon: class { constructor(i) { this.id = i; } }, ThemeColor: class {},
  TreeItemCollapsibleState: { None: 0, Expanded: 2 }, StatusBarAlignment: { Left: 1 }, ViewColumn: { Beside: 2 },
  window: { createOutputChannel: () => ({ appendLine() {}, dispose() {} }), createStatusBarItem: () => ({ show() {}, dispose() {} }),
    registerTreeDataProvider: (id, p) => { vscode.provider = p; return { dispose() {} }; }, setStatusBarMessage() {},
    showWarningMessage: m => calls.push('warn:' + m), showErrorMessage: m => calls.push('err:' + m), showInformationMessage: () => Promise.resolve() },
  workspace: { getConfiguration: () => ({ get: k => ({ port: 8799, host: '127.0.0.1', notifyDoor: true, python: 'python3' }[k]) }), onDidChangeConfiguration: () => ({ dispose() {} }), workspaceFolders: [] },
  commands: { registerCommand: (id, fn) => { cmds[id] = fn; return { dispose() {} }; } }, env: {}, Uri: {},
};
const orig = Module._load; Module._load = function (r, ...a) { return r === 'vscode' ? vscode : orig.call(this, r, ...a); };
const ext = require(path.join(__dirname, '..', 'vscode-extension', 'extension.js'));
ext.activate({ subscriptions: [] });
(async () => {
  await new Promise(r => setTimeout(r, 800));
  const roots = vscode.provider.getChildren(); console.log('root:', roots.map(x => x.label));
  console.log('trạng thái:', vscode.provider.getChildren(roots[0]).slice(0, 4).map(x => `${x.label}=${x.description}`));
  await cmds['smartlock.knobUnlock'](); await new Promise(r => setTimeout(r, 500));
  console.log('khoá sau knobUnlock:', vscode.provider.getChildren(roots[0]).find(x => x.label === 'Khoá') ? vscode.provider.getChildren(vscode.provider.getChildren()[0])[1].description : '?');
  console.log('sự kiện:', vscode.provider.getChildren(vscode.provider.getChildren()[2]).slice(0, 2).map(x => x.label));
  ext.deactivate(); process.exit(0);
})();
