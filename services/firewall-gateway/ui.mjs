import {publicCatalog,publicClients} from './policy.mjs';
const escapeHtml=v=>String(v??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
export function renderConsole({nonce,protectedView=false,canaryEnabled=false,configuredIds=new Set()}={}){
 const catalog=publicCatalog(),registry=publicClients(configuredIds);
 const clientRows=registry.clients.map(c=>`<tr><td><strong>${escapeHtml(c.label)}</strong><small>${escapeHtml(c.id)}</small></td>
 <td><small>${escapeHtml(c.repository)}</small></td><td>${escapeHtml(c.routes.length?c.routes.join(', '):'-')}</td>
 <td><span class="pill ${c.keyConfigured?'safe':'hold'}">${c.keyConfigured?'KEY SET':'KEY UNSET'}</span></td></tr>`).join('');
 const rows=catalog.routes.map((r,i)=>`<tr><td><span class="code">${escapeHtml(String(i+1).padStart(2,'0'))}</span></td>
 <td><strong>${escapeHtml(r.label)}</strong><small>${escapeHtml(r.id)}</small></td>
 <td>${escapeHtml(r.owner)}</td><td>${escapeHtml(r.provider)}</td>
 <td><span class="pill hold">SHADOW HOLD</span></td></tr>`).join('');
 const exceptions=catalog.directExceptions.map(r=>`<div class="exception"><span>${escapeHtml(r.id)}</span><strong>${escapeHtml(r.owner)}</strong></div>`).join('');
 return `<!doctype html><html lang="ja"><head><meta charset="utf-8"/><meta name="viewport" content="width=device-width,initial-scale=1"/>
 <meta name="robots" content="noindex,nofollow"/><title>Federation | Firewall Gateway</title>
 <style nonce="${escapeHtml(nonce)}">
 :root{color-scheme:dark;font-family:Inter,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;background:#090f19;color:#e6edf6}
 *{box-sizing:border-box}body{margin:0;min-height:100vh;background:radial-gradient(ellipse at 70% -20%,#1c4f69 0,transparent 42%),radial-gradient(ellipse at -10% 85%,#1b2942 0,transparent 50%),#090f19}
 .shell{max-width:1300px;margin:auto;display:grid;grid-template-columns:222px minmax(0,1fr);min-height:100vh}
 aside{border-right:1px solid #263447b0;padding:34px 20px;display:flex;flex-direction:column;gap:38px;background:#0b1521aa}
 .brand{display:flex;align-items:center;gap:11px;font-weight:800;letter-spacing:.045em;font-size:16px}
 .brand-sub{font-size:10px;color:#8cbdc0;letter-spacing:.15em}
 .mark{width:34px;height:34px;border:1px solid #63e4c9;border-radius:10px;display:grid;place-items:center;background:#0f504a66;font-size:20px;color:#87ffe3}
 .eyebrow{font-size:10px;letter-spacing:.18em;color:#79a5b4;text-transform:uppercase;margin:0 0 10px}
 .nav{display:grid;gap:8px}.nav a{color:#99aec2;text-decoration:none;padding:12px 14px;font-size:13px;border-radius:9px}
 .nav a.on{color:#d8fff4;background:#1d4e4b88;border:1px solid #36857a66}.nav a:hover{color:white;background:#25405677}
 .side-note{margin-top:auto;color:#8b9db0;font-size:11px;line-height:1.75;border-top:1px solid #253648;padding-top:20px}
 main{padding:44px min(5vw,70px) 60px;min-width:0}h1{font-size:clamp(26px,3vw,42px);line-height:1.17;letter-spacing:-.042em;margin:4px 0 14px;font-weight:700}
 h2{font-size:15px;letter-spacing:.01em;margin:0;color:#edf5fc}.intro{color:#9eb2c7;max-width:800px;line-height:1.8;font-size:13px;margin-bottom:32px}
 .top{display:flex;justify-content:space-between;gap:15px;align-items:center}.mode{border:1px solid #f3c27a55;background:#3c2b1a77;color:#f8d9a1;padding:10px 13px;border-radius:24px;font-size:11px;font-weight:700;white-space:nowrap}
 .grid{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:13px;margin-bottom:27px}
 .metric{border:1px solid #26384c;border-radius:15px;padding:20px;background:linear-gradient(150deg,#142338ed,#0d1927e8);min-height:117px}
 .metric .name{color:#9eb1c7;font-size:12px}.metric .value{display:block;margin-top:10px;font-size:26px;font-weight:750;letter-spacing:-.04em}.metric .value.green{color:#81e8cb}.metric .value.amber{color:#ffcf8f}
 .metric .sub{color:#8194aa;font-size:11px;margin-top:6px}
 .panel{border:1px solid #26384c;border-radius:16px;background:#111d2bdc;margin-bottom:20px;overflow:hidden}
 .panel-header{padding:19px 23px;border-bottom:1px solid #26374a;display:flex;justify-content:space-between;align-items:center;gap:12px}
 .panel-header p{margin:6px 0 0;font-size:11px;color:#8198ac}
 .pill{font-size:9px;font-weight:700;letter-spacing:.06em;padding:6px 8px;border-radius:20px;border:1px solid}
 .pill.hold{color:#f8c989;background:#b5792a14;border-color:#c9983e55}
 .pill.safe{color:#7eecc8;background:#1d85611d;border-color:#3c9e8677}
 table{width:100%;border-collapse:collapse;text-align:left;font-size:12px}
 th{font-size:10px;letter-spacing:.1em;text-transform:uppercase;color:#8599ae;font-weight:700}
 th,td{padding:14px 20px;border-bottom:1px solid #26374a}tbody tr:last-child td{border-bottom:0}
 td strong{font-size:12px;font-weight:600;display:block}td small{display:block;font-size:10px;color:#728ca3;margin-top:4px}
 .code{font-family:monospace;font-size:11px;color:#6b88a0}
 .split{display:grid;grid-template-columns:1fr 1fr;gap:20px}
 .exceptions{padding:10px 20px 18px}.exception{display:flex;justify-content:space-between;gap:8px;border-bottom:1px solid #26374a;padding:10px 0;font-size:11px;color:#a8bbcd}.exception:last-child{border:0}.exception strong{color:#8ee0c3}
 .guard{padding:20px 23px;display:grid;gap:12px}.guard div{display:flex;gap:10px;align-items:flex-start;color:#a8bacb;font-size:12px;line-height:1.5}
 .check{color:#81e8cb;font-size:14px}.footer{color:#6c8297;font-size:11px;margin-top:26px;line-height:1.8}
 @media(max-width:950px){.shell{grid-template-columns:1fr}aside{padding:16px 20px;gap:12px;border-bottom:1px solid #263447;border-right:0}.nav{display:flex;gap:6px;flex-wrap:wrap}.side-note{display:none}main{padding:27px 18px}.split{grid-template-columns:1fr}}
 @media(max-width:610px){.grid{grid-template-columns:1fr}.top{align-items:flex-start;flex-direction:column}.panel{overflow-x:auto}table{min-width:570px}}
 </style></head><body><div class="shell">
 <aside><div class="brand"><div class="mark">◇</div><div>FEDERATION<br/><span class="brand-sub">FIREWALL</span></div></div>
 <nav class="nav"><a class="on" href="/">Security Overview</a><a href="/#registry">API Registry</a><a href="/#clients">App Clients</a><a href="/#exceptions">Direct Exceptions</a><a href="/#controls">Protection Layers</a></nav>
 <div class="side-note">Independent security service<br/>No Base44 credential forwarding<br/>No production consumer cutover</div></aside>
 <main><div class="top"><p class="eyebrow">FEDERATION / SECURITY OPERATIONS</p><div class="mode">● SHADOW · NO CUTOVER</div></div>
 <h1>Firewall Gateway<br/>Security Operations</h1>
 <p class="intro">外部API接続を安全に統制する独立サービス。現在は接続経路を変更しない隔離検証段階です。旧経路はすべて維持し、実通信・同値性・UI・復旧を確認した対象だけ段階移行します。</p>
 <section class="grid">
 <div class="metric"><div class="name">Legacy connectivity</div><span class="value green">PRESERVED</span><div class="sub">既存の接続先・認証に変更なし</div></div>
 <div class="metric"><div class="name">API migration</div><span class="value amber">0 / ${catalog.routes.length}</span><div class="sub">未検証経路の切替を禁止</div></div>
 <div class="metric"><div class="name">Egress Canary</div><span class="value">${canaryEnabled?'ARMED':'LOCKED'}</span><div class="sub">${canaryEnabled?'署名付き読み取りだけ許可':'初期状態は外部通信停止'}</div></div>
 </section>
 <section class="panel" id="registry"><div class="panel-header"><div><h2>API Connection Registry</h2><p>取得責任は各アプリ、通信防御はFirewallに集約</p></div><span class="pill hold">CUTOVER DISABLED</span></div>
 <table><thead><tr><th>No</th><th>Upstream source</th><th>Owner</th><th>Provider</th><th>Migration status</th></tr></thead><tbody>${rows}</tbody></table></section>
 <section class="panel" id="clients"><div class="panel-header"><div><h2>App Client Registry</h2><p>10アプリ = 署名クライアント${registry.clients.length}件 + Gateway本体。鍵の値は表示しない</p></div><span class="pill hold">${registry.clients.filter(c=>c.keyConfigured).length} / ${registry.clients.length} KEYS</span></div>
 <table><thead><tr><th>App client</th><th>Repository</th><th>Permitted routes</th><th>HMAC key</th></tr></thead><tbody>${clientRows}</tbody></table></section>
 <div class="split"><section class="panel" id="exceptions"><div class="panel-header"><div><h2>Protected Direct Connections</h2><p>業務特性上、直接接続を正規経路とする対象</p></div></div><div class="exceptions">${exceptions}</div></section>
 <section class="panel" id="controls"><div class="panel-header"><div><h2>Security Control Layers</h2><p>コード側防御と基盤側の未検証を区別</p></div></div>
 <div class="guard"><div><span class="check">✓</span>署名付きサービス認証・短期リプレイ防止</div>
 <div><span class="check">✓</span>固定HTTPS許可先・リダイレクト拒否・応答上限</div>
 <div><span class="check">✓</span>同時要求・上流取得頻度・障害時の遮断</div>
 <div><span class="check">✓</span>デフォルト転送OFF・有料API/書込禁止</div>
 <div><span class="pill hold">PENDING</span>WAF・分散レート制限・複数ノード監査</div>
 <div><span class="pill hold">PENDING</span>実アプリ間の認証付きE2E・本番UI</div></div></section></div>
 <p class="footer">Mode: ${protectedView?'Authenticated operator read-only':'Public preview, sensitive operations disabled'} · No billing changes · No claim of production-ready network firewall.<br/>Network-layer enforcement and distributed replay protection must be configured before moving actual consumer traffic.</p>
 </main></div></body></html>`;
}
