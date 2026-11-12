import {randomUUID} from 'node:crypto';
import {createRenderValkeyStore} from './renderValkey.mjs';
// Every audit line gets a unique id so identical events (same type, time and
// client) stay distinct when the durable sink deduplicates by line hash.
export const auditLine=record=>JSON.stringify({...record,id:randomUUID()});
// Shared state for replay protection, request budgets and audit records.
// The memory store is per-process only and reports distributed:false.
// The Redis REST store (Upstash-compatible) is shared across instances and
// fails closed: any store error denies the request instead of allowing it.
const KEY=/^[a-z0-9:_.-]{1,200}$/i;
const STORE_HOST=/^[a-z0-9-]+(?:\.[a-z0-9-]+)*\.upstash\.io$/;

function checkKey(key){if(typeof key!=='string'||!KEY.test(key))throw Error('invalid-store-key');}
function checkTtl(ms){if(!Number.isInteger(ms)||ms<1000||ms>86400000)throw Error('invalid-store-ttl');}

export function createMemoryStore({clock=Date.now,maxKeys=5000,maxAudit=500}={}){
 const keys=new Map(),audit=[];
 function sweep(now){for(const [k,v] of keys)if(v.expiresAt<=now)keys.delete(k);}
 return {
  kind:'memory',distributed:false,
  async claimOnce(key,ttlMs){
   checkKey(key);checkTtl(ttlMs);
   const now=clock();sweep(now);
   if(keys.has(key))return {ok:true,claimed:false};
   if(keys.size>=maxKeys)return {ok:false,reason:'store-full'};
   keys.set(key,{value:1,expiresAt:now+ttlMs});
   return {ok:true,claimed:true};
  },
  async increment(key,windowMs){
   checkKey(key);checkTtl(windowMs);
   const now=clock();sweep(now);
   const hit=keys.get(key);
   if(hit){hit.value++;return {ok:true,count:hit.value};}
   if(keys.size>=maxKeys)return {ok:false,reason:'store-full'};
   keys.set(key,{value:1,expiresAt:now+windowMs});
   return {ok:true,count:1};
  },
  async appendAudit(record){
   audit.push(auditLine(record));
   if(audit.length>maxAudit)audit.shift();
   return {ok:true};
  },
  auditSnapshot:()=>audit.slice(),
  // Newest first, same order as the distributed list.
  async readAudit(limit){return {ok:true,lines:audit.slice(-limit).reverse()};},
 };
}

export function createRedisRestStore({url,token,fetchImpl=fetch,timeoutMs=1500,prefix='fw:',auditKey='audit',maxAudit=5000,notifyChanges=false}={}){
 let parsed;
 try{parsed=new URL(url);}catch{throw Error('invalid-store-url');}
 if(parsed.protocol!=='https:'||parsed.username||parsed.password||parsed.port&&parsed.port!=='443'
   ||!STORE_HOST.test(parsed.hostname)||parsed.pathname!=='/'||parsed.search||parsed.hash)
  throw Error('invalid-store-url');
 if(typeof token!=='string'||!/^[A-Za-z0-9_=-]{20,512}$/.test(token))throw Error('invalid-store-token');
 if(!/^[a-z0-9:_-]{1,32}$/.test(prefix))throw Error('invalid-store-prefix');
 const endpoint=parsed.origin+'/pipeline';
 async function pipeline(commands,{maxBytes=16384}={}){
  let response;
  try{
   response=await fetchImpl(endpoint,{method:'POST',redirect:'manual',credentials:'omit',
    headers:{Authorization:'Bearer '+token,'Content-Type':'application/json',Accept:'application/json'},
    body:JSON.stringify(commands),signal:AbortSignal.timeout(timeoutMs)});
  }catch{return null;}
  if(!response||response.status!==200)return null;
  if(!/^application\/json\b/i.test(response.headers.get('content-type')||''))return null;
  const declared=Number(response.headers.get('content-length'));
  if(Number.isFinite(declared)&&declared>maxBytes)return null;
  let data;
  try{const text=await response.text();if(text.length>maxBytes)return null;data=JSON.parse(text);}catch{return null;}
  if(!Array.isArray(data)||data.length!==commands.length||data.some(x=>!x||typeof x!=='object'||'error' in x))
   return null;
  return data.map(x=>x.result);
 }
 return {
  kind:'redis-rest',distributed:true,
  async claimOnce(key,ttlMs){
   checkKey(key);checkTtl(ttlMs);
   const out=await pipeline([['SET',prefix+key,'1','NX','PX',String(ttlMs)]]);
   if(!out)return {ok:false,reason:'store-unavailable'};
   if(out[0]==='OK')return {ok:true,claimed:true};
   if(out[0]===null)return {ok:true,claimed:false};
   return {ok:false,reason:'store-unavailable'};
  },
  async increment(key,windowMs){
   checkKey(key);checkTtl(windowMs);
   // INCR then PEXPIRE NX: the window starts at the first hit and never extends.
   const out=await pipeline([['INCR',prefix+key],['PEXPIRE',prefix+key,String(windowMs),'NX']]);
   if(!out||!Number.isInteger(out[0])||out[0]<1)return {ok:false,reason:'store-unavailable'};
   return {ok:true,count:out[0]};
  },
  async appendAudit(record){
   const line=auditLine(record);
   if(line.length>2048)return {ok:false,reason:'audit-record-too-large'};
   if(notifyChanges&&/^[a-z0-9-]{1,40}$/.test(record.kind||'')&&record.kind!=='audit-export'){
    const marker=JSON.stringify({eventId:JSON.parse(line).id,kind:record.kind});
    const script="redis.call('LPUSH',KEYS[1],ARGV[1]);redis.call('LTRIM',KEYS[1],0,tonumber(ARGV[2])-1);redis.call('SET',KEYS[2],ARGV[3]);return 1";
    const result=await pipeline([['EVAL',script,'2',prefix+auditKey,prefix+'ten-app-change',line,String(maxAudit),marker]]);
    return result?.[0]===1?{ok:true,changePending:true}:{ok:false,reason:'store-unavailable'};
   }
   const out=await pipeline([['LPUSH',prefix+auditKey,line],['LTRIM',prefix+auditKey,'0',String(maxAudit-1)]]);
   return out?{ok:true}:{ok:false,reason:'store-unavailable'};
  },
  async readPendingChange(){const reply=await pipeline([['GET',prefix+'ten-app-change']]);return reply&&(reply[0]===null||typeof reply[0]==='string')?{ok:true,marker:reply[0]}:{ok:false,reason:'store-unavailable'};},
  async ackPendingChange(marker){if(typeof marker!=='string'||marker.length>300)return {ok:false,reason:'marker-invalid'};const script="if redis.call('GET',KEYS[1])==ARGV[1] then return redis.call('DEL',KEYS[1]) else return 0 end";const reply=await pipeline([['EVAL',script,'1',prefix+'ten-app-change',marker]]);return reply&&[0,1].includes(reply[0])?{ok:true,cleared:reply[0]===1}:{ok:false,reason:'store-unavailable'};},
  async readAudit(limit){
   const out=await pipeline([['LRANGE',prefix+auditKey,'0',String(limit-1)]],{maxBytes:limit*2400+64});
   return Array.isArray(out?.[0])?{ok:true,lines:out[0].filter(l=>typeof l==='string')}:{ok:false,reason:'store-unavailable'};
  },
 };
}

// FIREWALL_STORE=redis-rest selects the shared store. Missing or invalid
// settings never fall back to memory silently: the result reports the error.
export function storeFromEnv(env=process.env,{fetchImpl=fetch,clock=Date.now}={}){
 const mode=env.FIREWALL_STORE||'memory';
 if(mode==='memory')return {store:createMemoryStore({clock}),error:null};
 if(mode==='render-valkey'){
  try{return {store:createRenderValkeyStore({
    url:env.FIREWALL_STORE_INTERNAL_URL,notifyChanges:env.FIREWALL_TEN_APP_CHANGE_NOTIFY_ENABLED==='true'
  }),error:null};}
  catch{return {store:null,error:'render-valkey-config-invalid'};}
 }
 if(mode!=='redis-rest')return {store:null,error:'store-mode-invalid'};
 try{
  return {store:createRedisRestStore({url:env.FIREWALL_STORE_REST_URL,token:env.FIREWALL_STORE_REST_TOKEN,fetchImpl,notifyChanges:env.FIREWALL_TEN_APP_CHANGE_NOTIFY_ENABLED==='true'}),error:null};
 }catch(error){return {store:null,error:String(error.message||'store-config-invalid')};}
}

// Async guards built on the store. Both deny when the store cannot answer.
// Keyless free-AI relays cost nothing upstream and have their own per-provider and per-client limits
// (freeAi.mjs), so they get a separate bucket instead of the paid-upstream budget.
export const SHARED_BUDGET_POOLS=Object.freeze({'free-ai':Object.freeze({total:60,perClient:30})});
export function createSharedGuards(store,{replayTtlMs=120000,windowMs=60000,limits={total:20,perClient:6},pools=SHARED_BUDGET_POOLS}={}){
 if(!store)throw Error('store-required');
 async function replay(client,nonce){
  const r=await store.claimOnce('nonce:'+client+':'+nonce,replayTtlMs);
  if(!r.ok)return {ok:false,status:503,reason:'replay-store-unavailable'};
  if(!r.claimed)return {ok:false,status:409,reason:'replay-refused'};
  return {ok:true};
 }
 async function budget(client,now=Date.now(),pool=null){
  const bucket=String(Math.floor(now/windowMs));
  const own=pool&&Object.hasOwn(pools,pool)?pools[pool]:null;
  const lim=own||limits,prefix=own?'budget:'+pool+':':'budget:';
  const total=await store.increment(prefix+'total:'+bucket,windowMs);
  if(!total.ok)return {ok:false,status:503,reason:'budget-store-unavailable'};
  if(total.count>lim.total)return {ok:false,status:429,reason:'upstream-budget-exhausted',retryAfterSeconds:Math.ceil(windowMs/1000)};
  const mine=await store.increment(prefix+'client:'+client+':'+bucket,windowMs);
  if(!mine.ok)return {ok:false,status:503,reason:'budget-store-unavailable'};
  if(mine.count>lim.perClient)return {ok:false,status:429,reason:'upstream-budget-exhausted',retryAfterSeconds:Math.ceil(windowMs/1000)};
  return {ok:true};
 }
 return {replay,budget,distributed:store.distributed,kind:store.kind};
}
