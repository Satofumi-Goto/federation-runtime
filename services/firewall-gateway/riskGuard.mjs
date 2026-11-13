// 危ないAPIの検知と遮断（ファイアーウォールゲートウェイの全AI枠で共有）。
// - 収集：dangerous-apis.json（公開情報から集めた危険情報。収集スクリプトが更新し、レビューを経て配布）と
//   環境変数 FIREWALL_BLOCKED_PROVIDERS（カンマ区切り、本人・運用者が即時に止める）を読む。
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
export function loadDangerousApis(file=fileURLToPath(new URL('./dangerous-apis.json',import.meta.url))){
 try{
  const data=JSON.parse(readFileSync(file,'utf8'));
  if(data?.schema!=='federation.dangerous-apis/1'||!Array.isArray(data.entries))return [];
  return data.entries.filter(e=>e&&ID.test(e.provider)&&/^[a-z0-9-]{3,48}$/.test(e.reason)
   &&(e.until===undefined||!Number.isNaN(Date.parse(e.until)))).slice(0,200);
 }catch{return [];}
}
export function createRiskGuard({env=process.env,clock=Date.now,dangerous=loadDangerousApis()}={}){
 const manual=new Set(String(env.FIREWALL_BLOCKED_PROVIDERS||'').split(',').map(s=>s.trim()).filter(s=>ID.test(s)));
 const state=new Map();
 const get=p=>{if(!state.has(p))state.set(p,{events:[],blockedUntil:0,reason:null,blocks:0});return state.get(p);};
 function blocked(p){
  if(manual.has(p))return 'manual-block';
  const t=clock();
  const listed=dangerous.find(e=>e.provider===p&&(!e.until||Date.parse(e.until)>t));
  if(listed)return 'listed:'+listed.reason;
  const s=state.get(p);
  return s&&s.blockedUntil>t?'auto:'+s.reason:null;
 }
 function observe(p,code){
  const weight=RISK_WEIGHTS[code]??(String(code).startsWith('upstream-40')?RISK_WEIGHTS['auth-refused']:RISK_WEIGHTS.failure);
  const s=get(p),t=clock();
  s.events=s.events.filter(e=>t-e.at<WINDOW_MS);
  s.events.push({at:t,code,weight});
  const score=s.events.reduce((n,e)=>n+e.weight,0);
  if(score>=RISK_THRESHOLD&&s.blockedUntil<=t){
   s.blockedUntil=t+(code==='paid-usage-reported'?PAID_BLOCK_MS:BLOCK_MS);s.reason=code;s.blocks++;s.events=[];
   return {blocked:true,reason:code,until:new Date(s.blockedUntil).toISOString()};
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
 function info(){
  const t=clock();
  return {threshold:RISK_THRESHOLD,manualBlocks:[...manual].sort(),listed:dangerous.filter(e=>!e.until||Date.parse(e.until)>t)
   .map(e=>({provider:e.provider,reason:e.reason,until:e.until||null})),
   autoBlocks:[...state].filter(([,s])=>s.blockedUntil>t).map(([p,s])=>({provider:p,reason:s.reason,until:new Date(s.blockedUntil).toISOString()}))};
 }
 return {blocked,observe,success,screenAnswer,info};
}
