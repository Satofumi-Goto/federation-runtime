// 危ないAPIの検知と遮断（ファイアーウォールゲートウェイの全AI枠で共有）。
// - 収集：dangerous-apis.json（公開情報から集めた危険情報。収集スクリプトが更新し、レビューを経て配布）と
//   環境変数 FIREWALL_BLOCKED_PROVIDERS・FIREWALL_BLOCKED_SOURCES（カンマ区切り、本人・運用者が即時に止める）を読む。
//   誤った自動遮断は FIREWALL_UNBLOCK で外す。
// - 検知：接続先ごとの応答の異常（リダイレクト・想定外の形式・過大な応答・課金表示・認証拒否・連続失敗）と、
//   応答本文の危険（指示の乗っ取り文・スクリプト・危険なコマンド・秘密情報の形）を点数にする。
// - 遮断：1時間の点数が閾値以上になった接続先を期限付きで止め、他の枠で処理を続ける。理由は固定の短い符号だけで、
//   プロンプト・応答・鍵は記録しない。
import {readFileSync} from 'node:fs';
import {fileURLToPath} from 'node:url';
import {redactSecrets} from './hardening.mjs';

export const RISK_WEIGHTS=Object.freeze({
 'redirect-refused':3,'invalid-content-type':2,'response-too-large':2,'invalid-json-shape':2,
 'unsafe-answer':4,'secret-in-answer':4,'paid-usage-reported':10,'auth-refused':3,'failure':1,
});
export const RISK_THRESHOLD=6;
const WINDOW_MS=3600000,BLOCK_MS=6*3600000,PAID_BLOCK_MS=24*3600000;
// データ源（外部API）は空き状況の揺れ（429・5xx・時間切れ）を点数にせず、既存の cooldown に任せる。
// 遮断も短く（30分）して、正常な情報源を長く止めない。
export const SOURCE_BLOCK_MS=30*60000;
const AVAILABILITY=new Set(['failure']);
const ALWAYS_SCORED=new Set(['paid-usage-reported','unsafe-answer','secret-in-answer']);
// 応答本文に現れた時、利用側のAIや画面を乗っ取る恐れが高いもの。
export const UNSAFE_ANSWER_PATTERNS=Object.freeze([
 ['instruction-override',/\b(?:ignore|disregard|forget)\s+(?:all\s+|any\s+)?(?:the\s+)?(?:previous|prior|above|earlier)\s+(?:instructions?|prompts?|rules?)/i],
 ['instruction-override-ja',/(?:これまで|以前|前|上記)の(?:指示|命令|ルール)を(?:無視|忘れ)/],
 ['system-prompt-exfiltration',/\b(?:reveal|print|show|output)\s+(?:your\s+|the\s+)?(?:system\s+prompt|hidden\s+instructions|api\s*key)/i],
 ['script-tag',/<\s*script\b|javascript\s*:/i],
 ['pipe-to-shell',/\b(?:curl|wget)\b[^\n|]{0,200}\|\s*(?:sudo\s+)?(?:ba|z)?sh\b/i],
 ['destructive-command',/\brm\s+-rf\s+(?:\/|~|\$HOME)(?:\s|$)/],
]);
export function unsafeAnswer(text){
 if(typeof text!=='string'||!text)return null;
 for(const [id,re] of UNSAFE_ANSWER_PATTERNS)if(re.test(text))return id;
 return null;
}
const ID=/^[a-z][a-z0-9]{1,31}$/;
// データ源（外部API）は接続先のホスト名で数え、AI枠の provider 名と混ざらないよう "host:" を付けて持つ。
const HOST=/^(?=.{4,253}$)[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$/;
// 設定の書き方の揺れ（末尾のドット、ポート、URL）を受け付け、ホスト名だけにそろえる。
const hostOf=value=>{let h=String(value||'').trim().toLowerCase();if(/^[a-z][a-z0-9+.-]*:\/\//.test(h)){try{h=new URL(h).hostname;}catch{return '';}}
 return h.replace(/:\d{1,5}$/,'').replace(/\.$/,'');};
export const sourceKey=host=>{const h=hostOf(host);return HOST.test(h)?'host:'+h:null;};
const KEY=k=>ID.test(k)||(k.startsWith('host:')&&HOST.test(k.slice(5)));
const entryKey=e=>e?.provider&&ID.test(e.provider)?e.provider:(e?.host?sourceKey(e.host):null);
const validEntry=e=>e&&entryKey(e)&&/^[a-z0-9-]{3,48}$/.test(e.reason)&&(e.until===undefined||!Number.isNaN(Date.parse(e.until)));
export function loadDangerousApis(file=fileURLToPath(new URL('./dangerous-apis.json',import.meta.url))){
 try{
  const data=JSON.parse(readFileSync(file,'utf8'));
  if(data?.schema!=='federation.dangerous-apis/1'||!Array.isArray(data.entries))return [];
  return data.entries.filter(validEntry).slice(0,200);
 }catch{return [];}
}
export function createRiskGuard({env=process.env,clock=Date.now,dangerous=loadDangerousApis(),onBlock=null}={}){
 // 即時停止：AI枠は FIREWALL_BLOCKED_PROVIDERS、データ源（外部API）は FIREWALL_BLOCKED_SOURCES（ホスト名）。
 const list=v=>String(v||'').split(',').map(s=>s.trim()).filter(Boolean);
 const manualProviders=list(env.FIREWALL_BLOCKED_PROVIDERS),manualSources=list(env.FIREWALL_BLOCKED_SOURCES);
 const manual=new Set([...manualProviders.filter(s=>ID.test(s)),...manualSources.map(sourceKey).filter(Boolean)]);
 // 書き間違いで黙って無視されないよう、読めなかった件数を info() に出す。
 const ignoredManual=manualProviders.filter(s=>!ID.test(s)).length+manualSources.filter(s=>!sourceKey(s)).length;
 // 誤った自動遮断の解除：FIREWALL_UNBLOCK（provider 名かホスト名、カンマ区切り）。起動時の復元から外し、
 // 誤検知しやすい異常（リダイレクト・形式・認証拒否など）では自動の遮断もしない。課金表示・危険な応答・
 // 応答内の秘密は解除の対象でも止める。即時停止・危険情報の一覧は別で、そちらが優先。
 const unblock=new Set(list(env.FIREWALL_UNBLOCK).map(s=>ID.test(s)?s:sourceKey(s)).filter(Boolean));
 const state=new Map();
 let collected=[],collectedAt=null;
 // 日次収集（tools/collect-dangerous-apis.mjs の collect）の結果。期限付きで、次の収集で置き換える。
 function setCollected(entries,at=clock()){
  collected=(Array.isArray(entries)?entries:[]).filter(validEntry).slice(0,200);
  collectedAt=new Date(at).toISOString();
  return collected.length;
 }
 const get=p=>{if(!state.has(p))state.set(p,{events:[],blockedUntil:0,reason:null,blocks:0});return state.get(p);};
 function blocked(p){
  if(manual.has(p))return 'manual-block';
  const t=clock();
  const listed=[...dangerous,...collected].find(e=>entryKey(e)===p&&(!e.until||Date.parse(e.until)>t));
  if(listed)return 'listed:'+listed.reason;
  const s=state.get(p);
  return s&&s.blockedUntil>t?'auto:'+s.reason:null;
 }
 function observe(p,code){
  // 解除の対象でも、課金表示・危険な応答・応答内の秘密は止める（解除は誤検知しやすい異常だけを外す）。
  if(unblock.has(p)&&!ALWAYS_SCORED.has(code))return {blocked:false,score:0,unblocked:true};
  const source=p.startsWith('host:');
  if(source&&AVAILABILITY.has(code))return {blocked:false,score:0};
  const weight=RISK_WEIGHTS[code]??(String(code).startsWith('upstream-40')?RISK_WEIGHTS['auth-refused']:RISK_WEIGHTS.failure);
  const s=get(p),t=clock();
  s.events=s.events.filter(e=>t-e.at<WINDOW_MS);
  s.events.push({at:t,code,weight});
  const score=s.events.reduce((n,e)=>n+e.weight,0);
  if(score>=RISK_THRESHOLD&&s.blockedUntil<=t){
   s.blockedUntil=t+(code==='paid-usage-reported'?PAID_BLOCK_MS:source?SOURCE_BLOCK_MS:BLOCK_MS);s.reason=code;s.blocks++;s.events=[];
   const until=new Date(s.blockedUntil).toISOString();
   // 再起動で遮断を失わないよう、呼び出し側の保存先に残す（理由は固定の符号だけ）。
   if(typeof onBlock==='function'){try{Promise.resolve(onBlock({key:p,reason:code,until},autoBlockRecords())).catch(()=>{});}catch{}}
   return {blocked:true,reason:code,until};
  }
  return {blocked:false,score};
 }
 function success(p){const s=state.get(p);if(s)s.events=s.events.filter(e=>e.weight>1);}
 // 応答本文を検査する。危険なら遮断の点数を加え、その応答は使わない（呼び出し側は次の枠へ進む）。
 function screenAnswer(p,text){
  const unsafe=unsafeAnswer(text);
  if(unsafe){observe(p,'unsafe-answer');return {ok:false,reason:'unsafe-answer'};}
  const safe=redactSecrets(text);
  if(safe.redacted)observe(p,'secret-in-answer');
  return {ok:true,text:safe.text,redacted:safe.redacted};
 }
 // 期限内の自動遮断（保存先に丸ごと書く形）。
 function autoBlockRecords(){
  const t=clock();
  return [...state].filter(([,s])=>s.blockedUntil>t).map(([key,s])=>({key,reason:s.reason,until:new Date(s.blockedUntil).toISOString()}));
 }
 const listedRow=e=>({key:entryKey(e),provider:e.provider||null,host:e.host||null,reason:e.reason,until:e.until||null});
 function info(){
  const t=clock();
  return {threshold:RISK_THRESHOLD,manualBlocks:[...manual].sort(),listed:dangerous.filter(e=>!e.until||Date.parse(e.until)>t)
   .map(listedRow),
   collected:collected.filter(e=>!e.until||Date.parse(e.until)>t).map(listedRow),
   ignoredManual,unblocked:[...unblock].sort(),
   collectedAt,
   autoBlocks:[...state].filter(([,s])=>s.blockedUntil>t).map(([p,s])=>({provider:p,reason:s.reason,until:new Date(s.blockedUntil).toISOString()}))};
 }
 // 保存先に残した遮断を、起動時に戻す（期限の切れたもの・形の違うものは捨てる）。
 function restore(records){
  const t=clock();let n=0;
  for(const r of Array.isArray(records)?records:[]){
   if(!r||typeof r.key!=='string'||!KEY(r.key)||unblock.has(r.key)||!/^[a-z0-9-]{3,48}$/.test(String(r.reason))||Number.isNaN(Date.parse(r.until)))continue;
   const until=Date.parse(r.until);if(until<=t)continue;
   const s=get(r.key);if(s.blockedUntil<until){s.blockedUntil=Math.min(until,t+PAID_BLOCK_MS);s.reason=r.reason;n++;}
  }
  return n;
 }
 // データ源（外部API）用：ホスト名で同じ点数・遮断を使う。
 const blockedSource=host=>{const k=sourceKey(host);return k?blocked(k):null;};
 const observeSource=(host,code)=>{const k=sourceKey(host);return k?observe(k,code):{blocked:false,score:0};};
 const successSource=host=>{const k=sourceKey(host);if(k)success(k);};
 return {blocked,observe,success,screenAnswer,info,setCollected,restore,autoBlockRecords,blockedSource,observeSource,successSource};
}
