// 危ないAPIの情報収集（1日1回程度、登録不要・費用0の公開情報だけ）。
// 対象：FREE_AI_PROVIDERS・REGISTERED_AI_PROVIDERS の接続先ドメイン。
// 情報源：RDAP（rdap.org、ドメインの状態・失効日）。保留・削除予定・30日以内の失効を危険候補にする。
// 出力：候補のJSON（標準出力）。--apply を付けた時だけ dangerous-apis.json に書き込む（配布前にレビューする）。
// プロンプト・鍵・個人情報は扱わない。
import {readFileSync,writeFileSync} from 'node:fs';
import {fileURLToPath} from 'node:url';
import {FREE_AI_PROVIDERS} from '../freeAi.mjs';
import {REGISTERED_AI_PROVIDERS} from '../registeredAi.mjs';

const RDAP='https://rdap.org/domain/';
const DANGER_STATUS=/client hold|server hold|pending delete|redemption period|inactive/i;
export function providerDomains(){
 const out=new Map();
 const add=(id,url)=>{try{const h=new URL(url).hostname.split('.');out.set(id,h.slice(-2).join('.'));}catch{}};
 for(const [id,p] of Object.entries(FREE_AI_PROVIDERS))add(id,p.url);
 for(const [id,p] of Object.entries(REGISTERED_AI_PROVIDERS))add(id,p.url||'https://api.cloudflare.com/');
 return out;
}
export function judgeRdap(data,now=Date.now()){
 const status=Array.isArray(data?.status)?data.status.join(','):'';
 if(DANGER_STATUS.test(status))return 'domain-status-hold';
 const exp=(Array.isArray(data?.events)?data.events:[]).find(e=>e?.eventAction==='expiration')?.eventDate;
 const t=Date.parse(exp||'');
 if(Number.isFinite(t)&&t-now<30*86400000)return t<now?'domain-expired':'domain-expiring';
 return null;
}
export async function collect({fetchImpl=fetch,now=Date.now()}={}){
 const domains=providerDomains(),cache=new Map(),entries=[],checked=[];
 for(const [provider,domain] of domains){
  if(!cache.has(domain)){
   let reason=null,ok=false;
   try{
    const r=await fetchImpl(RDAP+encodeURIComponent(domain),{redirect:'follow',headers:{Accept:'application/rdap+json'},signal:AbortSignal.timeout(10000)});
    if(r.ok){const text=await r.text();if(text.length<512000){reason=judgeRdap(JSON.parse(text),now);ok=true;}}
   }catch{/* 取れなかった時は候補にしない（誤遮断を避ける）。 */}
   cache.set(domain,{reason,ok});
  }
  const c=cache.get(domain);
  checked.push({provider,domain,checked:c.ok});
  if(c.reason)entries.push({provider,reason:c.reason,source:'rdap',until:new Date(now+7*86400000).toISOString()});
 }
 return {schema:'federation.dangerous-apis/1',updatedAt:new Date(now).toISOString().slice(0,10),entries,checked};
}
if(process.argv[1]&&fileURLToPath(import.meta.url)===process.argv[1]){
 const result=await collect();
 if(process.argv.includes('--apply')){
  const file=fileURLToPath(new URL('../dangerous-apis.json',import.meta.url));
  const current=JSON.parse(readFileSync(file,'utf8'));
  writeFileSync(file,JSON.stringify({...current,updatedAt:result.updatedAt,entries:result.entries},null,2)+'\n');
 }
 console.log(JSON.stringify(result,null,1));
}
