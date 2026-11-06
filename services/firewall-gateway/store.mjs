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
   audit.push(JSON.stringify(record));
   if(audit.length>maxAudit)audit.shift();
   return {ok:true};
  },
  auditSnapshot:()=>audit.slice(),
 };
}

export function createRedisRestStore({url,token,fetchImpl=fetch,timeoutMs=1500,prefix='fw:',auditKey='audit',maxAudit=5000}={}){
 let parsed;
 try{parsed=new URL(url);}catch{throw Error('invalid-store-url');}
 if(parsed.protocol!=='https:'||parsed.username||parsed.password||parsed.port&&parsed.port!=='443'
   ||!STORE_HOST.test(parsed.hostname)||parsed.pathname!=='/'||parsed.search||parsed.hash)
  throw Error('invalid-store-url');
 if(typeof token!=='string'||!/^[A-Za-z0-9_=-]{20,512}$/.test(token))throw Error('invalid-store-token');
 if(!/^[a-z0-9:_-]{1,32}$/.test(prefix))throw Error('invalid-store-prefix');
 const endpoint=parsed.origin+'/pipeline';
 async function pipeline(commands){
  let response;
  try{
   response=await fetchImpl(endpoint,{method:'POST',redirect:'manual',credentials:'omit',
    headers:{Authorization:'Bearer '+token,'Content-Type':'application/json',Accept:'application/json'},
    body:JSON.stringify(commands),signal:AbortSignal.timeout(timeoutMs)});
  }catch{return null;}
  if(!response||response.status!==200)return null;
  if(!/^application\/json\b/i.test(response.headers.get('content-type')||''))return null;
  const declared=Number(response.headers.get('content-length'));
  if(Number.isFinite(declared)&&declared>16384)return null;
  let data;
  try{data=JSON.parse(await response.text());}catch{return null;}
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
   const line=JSON.stringify(record);
   if(line.length>2048)return {ok:false,reason:'audit-record-too-large'};
   const out=await pipeline([['LPUSH',prefix+auditKey,line],['LTRIM',prefix+auditKey,'0',String(maxAudit-1)]]);
   return out?{ok:true}:{ok:false,reason:'store-unavailable'};
  },
 };
}

// FIREWALL_STORE=redis-rest selects the shared store. Missing or invalid
// settings never fall back to memory silently: the result reports the error.
export function storeFromEnv(env=process.env,{fetchImpl=fetch,clock=Date.now}={}){
 const mode=env.FIREWALL_STORE||'memory';
 if(mode==='memory')return {store:createMemoryStore({clock}),error:null};
 if(mode!=='redis-rest')return {store:null,error:'store-mode-invalid'};
 try{
  return {store:createRedisRestStore({url:env.FIREWALL_STORE_REST_URL,token:env.FIREWALL_STORE_REST_TOKEN,fetchImpl}),error:null};
 }catch(error){return {store:null,error:String(error.message||'store-config-invalid')};}
}

// Async guards built on the store. Both deny when the store cannot answer.
export function createSharedGuards(store,{replayTtlMs=120000,windowMs=60000,limits={total:20,perClient:6}}={}){
 if(!store)throw Error('store-required');
 async function replay(client,nonce){
  const r=await store.claimOnce('nonce:'+client+':'+nonce,replayTtlMs);
  if(!r.ok)return {ok:false,status:503,reason:'replay-store-unavailable'};
  if(!r.claimed)return {ok:false,status:409,reason:'replay-refused'};
  return {ok:true};
 }
 async function budget(client,now=Date.now()){
  const bucket=String(Math.floor(now/windowMs));
  const total=await store.increment('budget:total:'+bucket,windowMs);
  if(!total.ok)return {ok:false,status:503,reason:'budget-store-unavailable'};
  if(total.count>limits.total)return {ok:false,status:429,reason:'upstream-budget-exhausted',retryAfterSeconds:Math.ceil(windowMs/1000)};
  const mine=await store.increment('budget:client:'+client+':'+bucket,windowMs);
  if(!mine.ok)return {ok:false,status:503,reason:'budget-store-unavailable'};
  if(mine.count>limits.perClient)return {ok:false,status:429,reason:'upstream-budget-exhausted',retryAfterSeconds:Math.ceil(windowMs/1000)};
  return {ok:true};
 }
 return {replay,budget,distributed:store.distributed,kind:store.kind};
}
