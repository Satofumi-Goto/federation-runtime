import {ROUTES} from './policy.mjs';

export async function readBoundedJson(response,maxBytes){
 if(response.type==='opaqueredirect'||response.status>=300&&response.status<400)
  throw Error('redirect-refused');
 if(!response.ok)throw Error('upstream-unavailable');
 const contentType=response.headers.get('content-type')||'';
 if(!/^application\/(?:[\w.+-]+\+)?json\b/i.test(contentType))
  throw Error('invalid-content-type');
 const declared=Number(response.headers.get('content-length'));
 if(Number.isFinite(declared)&&declared>maxBytes)throw Error('response-too-large');
 if(!response.body?.getReader)throw Error('invalid-stream');
 const reader=response.body.getReader(),parts=[];let size=0;
 try{
  for(;;){
   const {value,done}=await reader.read();
   if(done)break;
   size+=value.byteLength;
   if(size>maxBytes){await reader.cancel().catch(()=>{});throw Error('response-too-large');}
   parts.push(value);
  }
 }finally{reader.releaseLock();}
 const bytes=new Uint8Array(size);let at=0;
 for(const p of parts){bytes.set(p,at);at+=p.byteLength;}
 const data=JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(bytes));
 if(data===null||typeof data!=='object')throw Error('invalid-json-shape');
 return data;
}
export function createEgress({env=process.env,fetchImpl=fetch,clock=Date.now,risk=null}={}){
 const started=new Map(),cache=new Map(),failures=new Map(),pending=new Map();
 let active=0,totalStarted=0,windowStart=clock();
 // This requires an explicit route and a short, non-renewing expiration.
 // The time window is validated ONCE at startup: an expiry far in the
 // future can never auto-arm later as time advances.
 const boot=clock();
 const rawExpiry=env.FIREWALL_CANARY_EXPIRES_AT||'';
 const expiration=/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/.test(rawExpiry)
   ?Date.parse(rawExpiry):NaN;
 const armedAtBoot=env.FIREWALL_CANARY_EGRESS==='true' &&
   env.FIREWALL_CANARY_ROUTE_IDS==='japan-holidays' &&
   Number.isFinite(expiration) && expiration>boot && expiration-boot<=600000;
 const liveEnabled=()=>armedAtBoot && clock()<expiration;
 const enabledRoutes=armedAtBoot?new Set(['japan-holidays']):new Set();
 const allowHost=new Set(Object.values(ROUTES).map(route=>new URL(route.url).hostname));
 function admit(client,id){
  const now=clock();
  if(now<windowStart||now-windowStart>=60000){windowStart=now;totalStarted=0;started.clear();}
  if(totalStarted>=20||active>=2||(started.get(client)||0)>=6)
   return false;
  totalStarted++;started.set(client,(started.get(client)||0)+1);
  return true;
 }
 async function probe(client,routeId){
  if(!liveEnabled())return {status:503,result:{ok:false,reason:'egress-disabled'}};
  if(!enabledRoutes.has(routeId))
   return {status:403,result:{ok:false,reason:'route-not-enabled'}};
  const route=ROUTES[routeId];
  if(!route||!route.consumers.includes(client))
   return {status:403,result:{ok:false,reason:'route-not-permitted'}};
  const url=new URL(route.url);
  if(url.protocol!=='https:'||url.username||url.password||!allowHost.has(url.hostname)
     ||url.port&&url.port!=='443')
   return {status:503,result:{ok:false,reason:'upstream-policy-invalid'}};
  if(risk?.blockedSource(url.hostname))
   return {status:503,result:{ok:false,reason:'source-risk-blocked'}};
  const now=clock(),hit=cache.get(routeId);
  if(hit&&now-hit.at<route.ttlMs)
   return {status:200,result:{...hit.result,cached:true}};
  const blocked=failures.get(routeId);
  if(blocked&&now<blocked)
   return {status:503,result:{ok:false,reason:'provider-circuit-open',retryAfterSeconds:60}};
  if(pending.has(routeId))return pending.get(routeId);
  if(!admit(client,routeId))
   return {status:429,result:{ok:false,reason:'upstream-budget-exhausted',retryAfterSeconds:60}};
  active++;
  const task=(async()=>{
   try{
    const response=await fetchImpl(url.href,{method:'GET',redirect:'manual',credentials:'omit',
      headers:{Accept:'application/json','User-Agent':'FederationFirewall/0.1 (shadow-canary)'},
      signal:AbortSignal.timeout(4500)});
    const data=await readBoundedJson(response,route.maxBytes);
    if(!liveEnabled())return {status:503,result:{ok:false,reason:'egress-expired'}};
    const recordCount=Array.isArray(data)?data.length:
      Array.isArray(data?.items)?data.items.length:Array.isArray(data?.events)?data.events.length:0;
    if(recordCount>route.maxRecords)throw Error('too-many-records');
    if(route.id==='japan-holidays'){
     const entries=Object.entries(data);
     if(Array.isArray(data)||entries.length<1||entries.length>route.maxRecords||
       entries.some(([date,name])=>!/^[0-9]{4}-[0-9]{2}-[0-9]{2}$/.test(date)
        ||typeof name!=='string'||!name.trim()||name.length>120))
      throw Error('invalid-holidays');
    }
    const result={ok:true,mode:'shadow-only',routeId:route.id,provider:route.provider,
      sourceUrl:route.url,fetchedAt:new Date(clock()).toISOString(),cached:false,
      basis:'public-source-not-operational-live-proof',data};
    cache.set(routeId,{at:clock(),result});
    if(cache.size>20)cache.delete(cache.keys().next().value);
    failures.delete(routeId);
    risk?.successSource(url.hostname);
    return {status:200,result};
   }catch(error){
    risk?.observeSource(url.hostname,['redirect-refused','response-too-large','invalid-content-type'].includes(error?.message)?error.message:'failure');
    failures.set(routeId,clock()+60000);
    if(failures.size>20)failures.delete(failures.keys().next().value);
    return {status:502,result:{ok:false,reason:'provider-unavailable',retryAfterSeconds:60}};
   }finally{active--;pending.delete(routeId);}
  })();
  pending.set(routeId,task);
  return task;
 }
 return {probe,get liveEnabled(){return liveEnabled();},
   info:()=>({egressEnabled:liveEnabled(),active,cacheEntries:cache.size})};
}
