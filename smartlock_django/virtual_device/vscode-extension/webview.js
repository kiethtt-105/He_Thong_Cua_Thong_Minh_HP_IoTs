exports.html = () => `<!DOCTYPE html><html><head><meta charset="UTF-8">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'">
<style>
body{font:13px var(--vscode-font-family);color:var(--vscode-foreground);padding:8px}
button{background:var(--vscode-button-secondaryBackground);color:var(--vscode-button-secondaryForeground);border:0;border-radius:3px;padding:5px 9px;cursor:pointer}
button.p{background:var(--vscode-button-background);color:var(--vscode-button-foreground)}
input{background:var(--vscode-input-background);color:var(--vscode-input-foreground);border:1px solid var(--vscode-input-border,#555);border-radius:3px;padding:4px;width:100%;box-sizing:border-box}
.r{display:flex;gap:5px;margin:5px 0}.r>*{flex:1}
h4{margin:12px 0 4px;font-size:11px;opacity:.7;text-transform:uppercase}
#lock{text-align:center}#lock svg{width:110px}
#sh{transition:transform .4s;transform-origin:50px 50px}.open #sh{transform:translateY(-12px) rotate(-22deg)}
#bd{fill:#4a5568;transition:fill .3s}.open #bd{fill:#2f855a}.warn #bd{fill:#9b2c2c}
#pin{text-align:center;letter-spacing:.3em;min-height:22px;background:var(--vscode-input-background);padding:3px;border-radius:3px}
.k{display:grid;grid-template-columns:repeat(3,1fr);gap:4px}
#log{height:140px;overflow:auto;font:11px monospace;white-space:pre-wrap;border:1px solid #555;padding:3px}
.off{opacity:.4;pointer-events:none}
</style></head><body>
<div class="r"><button class="p" id="go">▶ Khởi động</button><button id="no">■ Tắt</button></div>
<div id="ui" class="off">
<div id="lock"><svg viewBox="0 0 100 120"><path id="sh" d="M28 52V34a22 22 0 0 1 44 0v18" fill="none" stroke="#a0aec0" stroke-width="9" stroke-linecap="round"/><rect id="bd" x="12" y="50" width="76" height="62" rx="10"/><circle cx="50" cy="76" r="8" fill="#1a202c"/></svg>
<div><b id="st">—</b></div><div id="info" style="opacity:.7;font-size:11px"></div></div>
<div class="r"><button id="lk">🔒 Khoá</button><button id="ul">🔓 Mở</button></div>
<div class="r"><button id="tp">🛠 Cạy phá</button><button id="nt">📴 Mạng</button></div>
<input id="bt" type="range" min="0" max="100" value="100" title="Pin">
<h4>PIN</h4><div id="pin"></div><div class="k" id="kp"></div>
<h4>Thẻ RFID</h4><div class="r"><input id="uid" value="04:A1:B2:C3"><button class="p" id="tap" style="flex:0">Quẹt</button></div>
<h4>Vé BLE / NFC</h4><input id="tk" placeholder="userhex.exp.sig"><div class="r"><button id="ble">BLE</button><button id="nfc">NFC</button></div>
</div>
<h4>Nhật ký</h4><div id="log"></div>
<script>
const vs=acquireVsCodeApi(),$=i=>document.getElementById(i);let s={},pin='';
const c=(cmd,...args)=>vs.postMessage({type:'cmd',cmd,args});
$('go').onclick=()=>vs.postMessage({type:'start'});$('no').onclick=()=>vs.postMessage({type:'stop'});
$('lk').onclick=()=>c('lock');$('ul').onclick=()=>c('unlock');
$('tp').onclick=()=>c('tamper',s.tamper_detected?'off':'on');$('nt').onclick=()=>c(s.connected?'offline':'online');
$('bt').onchange=()=>c('battery',$('bt').value);
$('tap').onclick=()=>c('tap',$('uid').value);
$('ble').onclick=()=>c('ble',$('tk').value);$('nfc').onclick=()=>c('nfc',$('tk').value);
'123456789C0OK'.match(/OK|./g).forEach(k=>{const b=document.createElement('button');b.textContent=k;
 b.onclick=()=>{if(k=='C')pin='';else if(k=='OK'){if(pin)c('pin',pin);pin=''}else pin+=k;$('pin').textContent='•'.repeat(pin.length)};$('kp').appendChild(b)});
addEventListener('message',({data:d})=>{
 if(d.type=='state'){s=d.m;$('lock').className=(s.lock_state=='unlocked'?'open':'')+(s.tamper_detected?' warn':'');
  $('st').textContent=s.tamper_detected?'⚠ CẠY PHÁ':s.lock_state=='unlocked'?'ĐANG MỞ':'ĐÃ KHOÁ';
  $('info').textContent=s.device_code+' · 🔋'+s.battery+'% · '+(s.connected?'🟢 broker':'🔴 mất kết nối')+(s.buzzer?' · 🚨':'');}
 else if(d.type=='log'){const e=document.createElement('div');e.textContent=(d.m.t||'')+' '+d.m.msg;$('log').appendChild(e);$('log').scrollTop=1e9}
 else if(d.type=='proc'){$('ui').classList.toggle('off',!d.running);$('go').disabled=d.running;$('no').disabled=!d.running}});
vs.postMessage({type:'ready'});
</script></body></html>`;
