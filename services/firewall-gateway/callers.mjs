// Caller-side hosts for the two gateway flows that still originate on Base44:
//  (1) Activity shadow comparison (japan-holidays, owner-only, manual)
//  (2) each app's AI question entry point (assistantAsk -> /api/v1/assistant/ask)
// The gateway accepts signed server-to-server calls from any host holding the
// client key, so the caller host is a deployment choice. Default stays Base44.
// Selecting "independent" here never switches a route by itself: each caller
// must be deployed on the shared backend and pass its own round-trip test.
import {createHash,createHmac,randomUUID} from 'node:crypto';
import {CLIENT_IDS} from './policy.mjs';
import {HOLIDAY_ROUTE,HOLIDAY_SOURCE,compareHolidays} from './holidayParity.mjs';

export const INDEPENDENT_API_ORIGIN='https://federation-api-standalone-staging.onrender.com';
export const GATEWAY_ORIGIN='https://federation-firewall-gateway.onrender.com';
export const CALLER_UPSTREAMS=Object.freeze(['base44','independent']);
export const SHADOW_PATH='/api/v1/shadow/probe';
export const ASSISTANT_PATH='/api/v1/assistant/ask';

const FLOWS=Object.freeze([
 Object.freeze({id:'activity-shadow-compare',client:'activity',gatewayPath:SHADOW_PATH,
  base44Function:'activityFirewallShadowCompare',independentPath:'/api/activity/functions/activityFirewallShadowCompare'}),
 ...CLIENT_IDS.map(client=>Object.freeze({id:client+'-assistant',client,gatewayPath:ASSISTANT_PATH,
  base44Function:'assistantAsk',independentPath:'/api/'+client+'/functions/assistantAsk'})),
]);
export const CALLER_FLOWS=FLOWS;

// FIREWALL_CALLER_UPSTREAM: "base44" (default) or "independent"; anything else is base44.
// FIREWALL_CALLER_UPSTREAM_<FLOW> (flow id upper-cased, "-" -> "_") overrides one flow.
export function callerUpstream(flowId,env=process.env){
 const key='FIREWALL_CALLER_UPSTREAM_'+flowId.toUpperCase().replaceAll('-','_');
 const pick=v=>CALLER_UPSTREAMS.includes(v)?v:null;
 return pick(env[key])||pick(env.FIREWALL_CALLER_UPSTREAM)||'base44';
}
export function callerPlan(env=process.env){
 const flows=FLOWS.map(f=>{
  const upstream=callerUpstream(f.id,env);
  return {id:f.id,client:f.client,gatewayPath:f.gatewayPath,upstream,
   callerHost:upstream==='independent'?INDEPENDENT_API_ORIGIN+f.independentPath:'base44:functions/'+f.base44Function,
   independentCandidate:INDEPENDENT_API_ORIGIN+f.independentPath,
   roundTripVerified:false,cutover:false,legacyRetained:true};
 });
 return {schema:'federation.firewall-caller-plan/1',independentApiOrigin:INDEPENDENT_API_ORIGIN,
  defaultUpstream:'base44',flowCount:flows.length,
  independentSelected:flows.filter(f=>f.upstream==='independent').length,roundTripVerified:0,flows};
}

function strictKey(raw){
 if(typeof raw!=='string'||!/^[A-Za-z0-9_-]{43}$/.test(raw))return null;
 const key=Buffer.from(raw,'base64url');
 return key.length===32&&key.toString('base64url')===raw?key:null;
}
function gatewayUrl(env,path){
 const raw=env.FIREWALL_GATEWAY_ORIGIN||GATEWAY_ORIGIN;
 let u;try{u=new URL(raw);}catch{return null;}
 const local=u.hostname==='127.0.0.1'||u.hostname==='localhost';
 if(!(u.protocol==='https:'||local&&u.protocol==='http:')||u.username||u.password||u.pathname!=='/'||u.search||u.hash)return null;
 return u.origin+path;
}
export function signedHeaders({client,key,body,path,time=Date.now(),nonce=randomUUID()}){
 const hash=createHash('sha256').update(body,'utf8').digest('hex');
 const message=['federation-firewall-hmac/1',client,'POST',path,String(time),nonce,hash].join('\n');
 return {'Content-Type':'application/json',Accept:'application/json','x-fw-client':client,
  'x-fw-time':String(time),'x-fw-nonce':nonce,'x-fw-signature':createHmac('sha256',key).update(message).digest('hex')};
}
async function boundedJson(response,limit){
 if(!response.ok||!/^application\/(?:[\w.+-]+\+)?json\b/i.test(response.headers.get('content-type')||''))
  throw Error('upstream-unavailable');
 const text=await response.text();
 if(text.length>limit)throw Error('upstream-too-large');
 return JSON.parse(text);
}

// Node port of the Activity owner-only shadow comparison for the shared backend.
// Owner authentication is the host's job (pass ownerAuthenticated after the
// independent Cookie session check). Off unless FIREWALL_ACTIVITY_SHADOW_ENABLED=true.
export function createActivityShadowCompare({env=process.env,fetchImpl=fetch,clock=Date.now,minIntervalMs=60_000}={}){
 let active=false,lastStartedAt=-Infinity;
 async function run({ownerAuthenticated=false,routeId}={}){
  const base={routeId:HOLIDAY_ROUTE,cutover:false,legacyRetained:true,host:'independent'};
  if(ownerAuthenticated!==true)return {status:403,body:{ok:false,reason:'owner-required'}};
  if(routeId!==HOLIDAY_ROUTE)return {status:400,body:{ok:false,reason:'unsupported-route'}};
  if(env.FIREWALL_ACTIVITY_SHADOW_ENABLED!=='true')return {status:503,body:{ok:false,reason:'shadow-not-enabled'}};
  const key=strictKey(env.FIREWALL_ACTIVITY_HMAC_KEY);
  if(!key)return {status:503,body:{ok:false,reason:'hmac-not-configured'}};
  const url=gatewayUrl(env,SHADOW_PATH);
  if(!url)return {status:503,body:{ok:false,reason:'gateway-origin-invalid'}};
  const now=clock();
  if(active||now-lastStartedAt<minIntervalMs)return {status:429,body:{ok:false,reason:'manual-budget-exhausted'}};
  active=true;lastStartedAt=now;
  try{
   const body=JSON.stringify({routeId:HOLIDAY_ROUTE});
   const gateway=await fetchImpl(url,{method:'POST',redirect:'error',credentials:'omit',signal:AbortSignal.timeout(7500),
    headers:signedHeaders({client:'activity',key,body,path:SHADOW_PATH,time:clock()}),body});
   if(!gateway.ok)return {status:502,body:{ok:false,reason:'gateway-not-ready',gatewayStatus:gateway.status}};
   const packet=await boundedJson(gateway,140000);
   const legacyRes=await fetchImpl(HOLIDAY_SOURCE,{method:'GET',redirect:'error',credentials:'omit',
    signal:AbortSignal.timeout(7500),headers:{Accept:'application/json'}});
   const legacyData=await boundedJson(legacyRes,140000);
   const result=compareHolidays({gatewayPacket:packet,legacyData,now:clock()});
   return {status:200,body:{ok:true,...base,...result}};
  }catch{
   return {status:502,body:{ok:false,reason:'comparison-unavailable'}};
  }finally{active=false;}
 }
 return {run};
}
