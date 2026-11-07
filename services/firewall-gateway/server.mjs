import http from 'node:http';
import {randomBytes} from 'node:crypto';
import {fileURLToPath} from 'node:url';
import {resolve,dirname,join} from 'node:path';
import {readFileSync} from 'node:fs';
import {createAuthenticator} from './auth.mjs';
import {createAccessVerifier} from './access.mjs';
import {createEgress} from './egress.mjs';
import {createActivityAcquisition,validateEventQuery,NEWS_SOURCE_IDS,TOKYO_EVENT_SOURCE_IDS} from './activitySources.mjs';
import {createGithubCanaryVerifier} from './githubCanary.mjs';
import {createAssistant,parseAssistantCommand,ASSISTANT_PATH,ASSISTANT_MAX_BODY,ASSISTANT_POLICY} from './assistant.mjs';
import {publicCatalog,publicClients,SIGNING_CONTRACT} from './policy.mjs';
import {renderConsole} from './ui.mjs';
import {independentApps,INDEPENDENT_ORIGINS,SERVING_HOSTS} from './origins.mjs';
import {publicAcquisitionLedger} from './acquisitionLedger.mjs';
import {storeFromEnv,createSharedGuards} from './store.mjs';

const SECURITY_HEADERS=Object.freeze({
 'Cache-Control':'no-store',
 'X-Content-Type-Options':'nosniff',
 'X-Frame-Options':'DENY',
 'Referrer-Policy':'no-referrer',
 'Permissions-Policy':'camera=(), microphone=(), geolocation=(), payment=()',
 'Cross-Origin-Resource-Policy':'same-origin',
 'Cross-Origin-Opener-Policy':'same-origin',
 'Strict-Transport-Security':'max-age=86400',
});
const safeCsp=nonce=>"default-src 'none'; base-uri 'none'; object-src 'none'; frame-ancestors 'none'; form-action 'none'; img-src 'none'; script-src 'none'; connect-src 'none'; style-src 'nonce-"+nonce+"'";
function reply(res,status,data,extra={}){
 const headers={...SECURITY_HEADERS,'Content-Type':'application/json; charset=utf-8',...extra};
 res.writeHead(status,headers);res.end(JSON.stringify(data));
}
function page(res,status,body,nonce){
 res.writeHead(status,{...SECURITY_HEADERS,'Content-Type':'text/html; charset=utf-8',
  'Content-Security-Policy':safeCsp(nonce)});
 res.end(body);
}
async function limitedBody(req,max=512){
 if(Number(req.headers['content-length'])>max)throw Error('request-too-large');
 const chunks=[];let size=0;
 for await(const part of req){
  size+=part.byteLength;
  if(size>max)throw Error('request-too-large');
  chunks.push(part);
 }
 return Buffer.concat(chunks,size).toString('utf8');
}
export const PARENT_ORIGIN='https://federation-runtime.com';
export const DISTRIBUTION_REPOSITORY='Satofumi-Goto/federation-runtime';
export const CANONICAL_REPOSITORY='Satofumi-Goto/federation-portal';
const SHA40=/^[a-f0-9]{40}$/;
// Served SHA comes only from the platform-provided RENDER_GIT_COMMIT (never a
// request value). The canonical commit is read from the distribution-only
// source-attestation.json when present; absent files leave it null.
function readCanonicalCommit(){
 try{
  const manifest=JSON.parse(readFileSync(join(dirname(fileURLToPath(import.meta.url)),'source-attestation.json'),'utf8'));
  return manifest?.canonicalRepository===CANONICAL_REPOSITORY&&SHA40.test(manifest?.canonicalCommit||'')?manifest.canonicalCommit:null;
 }catch{return null;}
}
export function gitHead(env=process.env,canonicalCommit=readCanonicalCommit()){
 const raw=String(env.RENDER_GIT_COMMIT||'').trim().toLowerCase();
 const sha=SHA40.test(raw)?raw:null;
 return {sha,repository:DISTRIBUTION_REPOSITORY,branch:sha&&env.RENDER_GIT_BRANCH==='main'?'main':null,
  sourceState:sha?'render-git-commit':'unverified-no-platform-sha',
  canonicalRepository:CANONICAL_REPOSITORY,canonicalCommit:canonicalCommit||null,
  canonicalVerification:canonicalCommit?'source-attestation-git-blob':'not-available'};
}
// Shared family contract: service is '<appId>-standalone' (appId 'firewall').
export const FAMILY_APP_ID='firewall';
export function parentStatus(origin){
 return {schema:'federation.runtime-child/1',service:FAMILY_APP_ID+'-standalone',
  parentOrigin:PARENT_ORIGIN,origin:origin||null,parentVerified:false,productionReady:false,authenticatedE2E:false,dnsVerified:false,gatewayService:'federation-firewall-gateway'};
}
// Only facts with evidence are true. Zero-dependency Node service with no
// Base44 SDK/backend: backendIndependent. No durable store, no app-UI signed
// E2E, no custom DNS: all false. productionReady stays false (shadow-hold).
export function readinessStatus({env=process.env,distributed=false}={}){
 const sharedLive=distributed&&['render-valkey','redis-rest'].includes(env.FIREWALL_STORE);
 const storageReason=sharedLive
  ?'shared replay and rate budgets are configured, but durability and immutable audit retention remain unverified; free Render Valkey loses state on restart'
  :'no verified durable shared store: signed replay, rate and audit require a configured distributed provider';

 // Shared family contract federation.independent-readiness/1; extra fields are additive.
 return {schema:'federation.independent-readiness/1',app:FAMILY_APP_ID,service:'federation-firewall-gateway',
  stage:'shadow-hold',productionReady:false,frontendHostIndependent:true,backendIndependent:true,storageIndependent:false,
  authenticatedE2E:false,dnsVerified:false,cutoverEnabled:false,verifiedCutovers:0,
  evidence:{frontendHostIndependent:'operations console and status pages are served by this Node process, not Base44',
   backendIndependent:'node-only server, no Base44 SDK or backend; served from its own Render origin'},
  pending:{storageIndependent:storageReason,
   authenticatedE2E:'no user-facing signed app-to-gateway E2E; GitHub OIDC and Activity HMAC canaries are diagnostic only',
   dnsVerified:'onrender.com subdomain only; no custom domain or DNS verification',
   productionReady:'shadow-hold; network WAF, durable audit and user-facing cutover not verified'}};
}
export function createGatewayServer({env=process.env,fetchImpl=fetch,clock=Date.now,auditSink=console.info}={}){
 const auth=createAuthenticator({env,clock});
 // Activity acquisition uses a dedicated secret; never rotate or overwrite
 // keys of the nine existing Gateway clients to connect this feature.
 const sourceKey=env.FIREWALL_ACTIVITY_ACQUISITION_KEY||'';
 const sourceAuth=createAuthenticator({env:{
   FIREWALL_CLIENT_KEYS_JSON:sourceKey?JSON.stringify({activity:sourceKey}):''
 },clock});
 // A separate news-only secret preserves all existing signed TV/event clients.
 const newsKey=env.FIREWALL_ACTIVITY_NEWS_KEY||'';
 const newsAuth=createAuthenticator({env:{
   FIREWALL_CLIENT_KEYS_JSON:newsKey?JSON.stringify({activity:newsKey}):''
 },clock});
 // Dedicated event-read key. Do not rotate or reuse TV/online/news HMAC grants.
 const eventKey=env.FIREWALL_ACTIVITY_EVENT_ACQUISITION_KEY||'';
 const eventAuth=createAuthenticator({env:{
   FIREWALL_CLIENT_KEYS_JSON:eventKey?JSON.stringify({activity:eventKey}):''
 },clock});
 // Additional key for the two fixed Tokyo public datasets ONLY. The existing
 // event key is retained unchanged for Kawasaki/other signed consumers.
 const tokyoKey=env.FIREWALL_ACTIVITY_TOKYO_SHADOW_KEY||'';
 const tokyoAuth=createAuthenticator({env:{
   FIREWALL_CLIENT_KEYS_JSON:tokyoKey?JSON.stringify({activity:tokyoKey}):''
 },clock});
 const access=createAccessVerifier({env,fetchImpl,clock});
 const egress=createEgress({env,fetchImpl,clock});
 const activityAcquisition=createActivityAcquisition({fetchImpl,clock});
 const activitySourcesEnabled=env.FIREWALL_ACTIVITY_SOURCES_ENABLED==='true';
 const activityEventsEnabled=env.FIREWALL_ACTIVITY_EVENTS_ENABLED==='true';
 const githubCanary=createGithubCanaryVerifier({env,fetchImpl,clock});
 // Strict opt-in: signed requests must claim a distributed nonce and budget
 // BEFORE any upstream or assistant invocation. Storage failure denies.
 const storeMode=env.FIREWALL_STORE||'memory';
 const requireShared=env.FIREWALL_REQUIRE_DISTRIBUTED_STORE==='true'||
  storeMode==='redis-rest'||storeMode==='render-valkey';
 const resolved=storeFromEnv(env,{fetchImpl,clock});
 const sharedStore=resolved.store?.distributed?resolved.store:null;
 const sharedGuards=sharedStore?createSharedGuards(sharedStore):null;
 async function enforceShared(client,nonce,kind){
  if(!requireShared)return {ok:true};
  if(!sharedGuards||!sharedStore)return {ok:false,status:503,reason:'security-store-unavailable'};
  const replay=await sharedGuards.replay(client,nonce);
  if(!replay.ok)return replay;
  const budget=await sharedGuards.budget(client,clock());
  if(!budget.ok)return budget;
  try{
   const audit=await sharedStore.appendAudit({
     type:'firewall.signed.accepted',at:new Date(clock()).toISOString(),
     client,kind
   });
   if(!audit.ok)return {ok:false,status:503,reason:'security-audit-unavailable'};
  }catch{return {ok:false,status:503,reason:'security-audit-unavailable'};}
  return {ok:true};
 }
 const assistant=createAssistant({env,fetchImpl,clock});
 const signedClients=new Set();
 const head=gitHead(env);
 const selfOrigin=INDEPENDENT_ORIGINS['firewall-gateway'];
 const apps=()=>independentApps(auth.configuredIds(),signedClients);
 const server=http.createServer({maxHeaderSize:8192},async(req,res)=>{
  const path=(req.url||'').split('?')[0];
  // Probe audit is metadata only. Never log request bodies, client secrets,
  // signatures, IP addresses, cookies or provider payloads.
  let probeClient=null,probeRoute=null;
  if(path==='/api/v1/shadow/probe'||path==='/api/v1/canary/github')res.once('finish',()=>{
    try{auditSink(JSON.stringify({
      type:'firewall.shadow.request',at:new Date(clock()).toISOString(),
      method:req.method,status:res.statusCode,client:probeClient,routeId:probeRoute,
    }));}catch{/* Observability must not interrupt responses. */}
  });
  // Assistant audit: never record question, persona, answer, signature or IP.
  let askClient=null,askCharacter=null,askHistory=null;
  if(path===ASSISTANT_PATH)res.once('finish',()=>{
    try{auditSink(JSON.stringify({
      type:'firewall.assistant.request',at:new Date(clock()).toISOString(),
      method:req.method,status:res.statusCode,client:askClient,characterId:askCharacter,
      historyCount:askHistory,
    }));}catch{/* Observability must not interrupt responses. */}
  });
  if(!req.url||req.url.length>1024)return reply(res,414,{ok:false,reason:'invalid-target'});
  try{
   if(req.method==='GET'&&path==='/healthz'){
    // Family monitor reads plain "ok" when it asks for text/plain; JSON stays the default.
    const accept=String(req.headers.accept||'');
    if(/text\/plain/i.test(accept)&&!/application\/json/i.test(accept)){
     res.writeHead(200,{...SECURITY_HEADERS,'Content-Type':'text/plain; charset=utf-8'});return res.end('ok');
    }
    return reply(res,200,{ok:true,service:'federation-firewall-gateway',stage:'shadow-hold',
      productionReady:false,cutoverEnabled:false,independentApps:apps()});
   }
   if(req.method==='GET'&&path==='/git-head.json')
    return reply(res,200,head);
   if(req.method==='GET'&&path==='/_status/parent')
    return reply(res,200,parentStatus(selfOrigin));
   if(req.method==='GET'&&path==='/_status/readiness')
    return reply(res,200,readinessStatus({env,distributed:!!sharedStore}));
   if(req.method==='GET'&&path==='/api/status')
    return reply(res,200,{service:'federation-firewall-gateway',stage:'shadow-hold',
      configuredClients:auth.configured,configuredClientIds:[...auth.configuredIds()].sort(),
      registeredApps:publicClients().appCount,canaryEgressEnabled:egress.liveEnabled,
      activityAcquisitionEnabled:activitySourcesEnabled,
      assistantEnabled:assistant.enabled,
      sharedSecurity:{mode:storeMode,required:requireShared,
       configured:!!sharedStore,distributed:!!sharedStore},
      productionReady:false,cutoverEnabled:false,legacyConnectionsPreserved:true,
      independentApps:apps()});
   if(req.method==='GET'&&path==='/api/catalog')
    return reply(res,200,{...publicCatalog(),independentApps:apps()});
   if(req.method==='GET'&&path==='/api/acquisition-routes'){
    // Read-only ledger for the independent apps' screens. No credentials, key values or egress.
    const origin=req.headers.origin;
    const allowed=new Set([...Object.values(INDEPENDENT_ORIGINS),...Object.values(SERVING_HOSTS)].filter(Boolean));
    const cors=typeof origin==='string'&&allowed.has(origin)?{'Access-Control-Allow-Origin':origin,Vary:'Origin'}:{Vary:'Origin'};
    return reply(res,200,publicAcquisitionLedger(env),cors);
   }
   if(req.method==='GET'&&path==='/api/clients')
    return reply(res,200,{...publicClients(auth.configuredIds()),signing:SIGNING_CONTRACT,
      assistant:{...ASSISTANT_POLICY,enabled:assistant.enabled}});
   if(req.method==='GET'&&(path==='/'||path==='/console')){
    const nonce=randomBytes(18).toString('base64url');
    return page(res,200,renderConsole({nonce,canaryEnabled:egress.liveEnabled,configuredIds:auth.configuredIds()}),nonce);
   }
   if(req.method==='GET'&&path==='/admin'){
    const assertion=req.headers['cf-access-jwt-assertion'];
    const verified=await access.verify(assertion);
    if(!verified.ok)return reply(res,verified.status,{ok:false,reason:verified.reason});
    const nonce=randomBytes(18).toString('base64url');
    return page(res,200,renderConsole({nonce,protectedView:true,canaryEnabled:egress.liveEnabled,configuredIds:auth.configuredIds()}),nonce);
   }
   if(path==='/api/v1/canary/github'){
    // Separate single-purpose identity boundary: OIDC token must be minted by
    // the pinned GitHub workflow, not by a browser or another service.
    if(req.headers.origin||req.headers.cookie||req.headers['x-fw-client']||
       req.headers['x-fw-signature'])
     return reply(res,403,{ok:false,reason:'server-to-server-only'});
    if(req.method!=='POST')return reply(res,405,{ok:false,reason:'method-not-allowed'});
    if(!/^application\/json(?:\s*;|$)/i.test(req.headers['content-type']||''))
     return reply(res,415,{ok:false,reason:'json-required'});
    const authorization=req.headers.authorization;
    if(typeof authorization!=='string'||!/^Bearer [A-Za-z0-9_.-]{100,12000}$/.test(authorization))
     return reply(res,401,{ok:false,reason:'github-identity-required'});
    let body;
    try{body=await limitedBody(req,96);}
    catch{return reply(res,413,{ok:false,reason:'request-too-large'},{Connection:'close'});}
    if(body!=='{"routeId":"japan-holidays"}')
     return reply(res,400,{ok:false,reason:'unsupported-command'});
    const identity=await githubCanary.verify(authorization.slice(7));
    if(!identity.ok)return reply(res,identity.status,{ok:false,reason:identity.reason});
    probeClient='github-actions';probeRoute='japan-holidays';
    const result=await egress.probe('federation','japan-holidays');
    return reply(res,result.status,result.result,
      result.result.retryAfterSeconds?{'Retry-After':String(result.result.retryAfterSeconds)}:{});
   }
   if(path===ASSISTANT_PATH){
    // Field names follow the assistant answer contract; transport is HMAC server-to-server only.
    const deny=(status,error,extra={},headers={})=>reply(res,status,{ok:false,
      status:status===503?'unavailable':'denied',error,requestId:null,...extra},headers);
    if(req.headers.origin||req.headers.cookie||req.headers.authorization)
     return deny(403,'origin_not_allowed',{reason:'server-to-server-only'});
    if(req.method!=='POST')return deny(405,'method_not_allowed');
    if(!/^application\/json(?:\s*;|$)/i.test(req.headers['content-type']||''))
     return deny(415,'invalid_question');
    let body;
    try{body=await limitedBody(req,ASSISTANT_MAX_BODY);}
    catch{return deny(413,'too_large',{},{Connection:'close'});}
    const identity=auth.verify(req,body,path);
    if(!identity.ok)return identity.status===503
      ?deny(503,'ai_unavailable',{reason:identity.reason})
      :deny(identity.status,'origin_not_allowed',{reason:identity.reason});
    const shared=await enforceShared(identity.client,req.headers['x-fw-nonce'],'assistant');
    if(!shared.ok)return deny(shared.status,'ai_unavailable',{reason:shared.reason});
    askClient=identity.client;signedClients.add(identity.client);
    const parsed=parseAssistantCommand(body);
    if(!parsed.ok)return deny(parsed.status||400,parsed.error,{requestId:parsed.requestId});
    askCharacter=parsed.command.character?.id||null;
    askHistory=parsed.command.history.length;
    const result=await assistant.ask(identity.client,parsed.command);
    return reply(res,result.status,result.result,
      result.result.retryAfterSeconds?{'Retry-After':String(result.result.retryAfterSeconds)}:{});
   }
   if(path==='/api/v1/activity/acquire'){
    // Browser requests and arbitrary lookups never pass this boundary.
    if(req.headers.origin||req.headers.cookie||req.headers.authorization)
      return reply(res,403,{ok:false,reason:'server-to-server-only'});
    if(req.method!=='POST')return reply(res,405,{ok:false,reason:'method-not-allowed'});
    if(!/^application\/json(?:\s*;|$)/i.test(req.headers['content-type']||''))
      return reply(res,415,{ok:false,reason:'json-required'});
    let body;
    try{body=await limitedBody(req,128);}
    catch{return reply(res,413,{ok:false,reason:'request-too-large'},{Connection:'close'});}
    let command;
    try{command=JSON.parse(body);}
    catch{return reply(res,400,{ok:false,reason:'invalid-json'});}
    const kawasakiSource=command?.source==='events';
    const eventSource=kawasakiSource||TOKYO_EVENT_SOURCE_IDS.includes(command?.source);
    const keys=command&&typeof command==='object'&&!Array.isArray(command)
      ?Object.keys(command).sort().join(','):'';
    const eventQuery=kawasakiSource&&keys==='from,page,source,to'
      ?validateEventQuery(command,clock()):null;
    if(!command||typeof command!=='object'||Array.isArray(command)||
      !['tv','online',...NEWS_SOURCE_IDS,'events','anilist',...TOKYO_EVENT_SOURCE_IDS].includes(command.source)||
      (kawasakiSource?!eventQuery:keys!=='source'))
      return reply(res,400,{ok:false,reason:'unsupported-command'});
    const newsSource=NEWS_SOURCE_IDS.includes(command.source);
    // The Tokyo-only staging key is an ADDITIONAL, isolated credential, never
    // a replacement or authorization for Kawasaki, TV, news or any user data.
    let identity=(eventSource?eventAuth:newsSource?newsAuth:sourceAuth).verify(req,body,path);
    const tokyoSource=eventSource&&!kawasakiSource;
    if(!identity.ok&&tokyoSource&&tokyoAuth.configured&&
       ['service-auth-unconfigured','signature-invalid'].includes(identity.reason))
      identity=tokyoAuth.verify(req,body,path);
    if(!identity.ok)return reply(res,identity.status,{ok:false,reason:identity.reason});
    if(identity.client!=='activity')return reply(res,403,{ok:false,reason:'activity-only'});
    if(!activitySourcesEnabled)return reply(res,503,{ok:false,reason:'activity-egress-disabled'});
    if(eventSource&&!activityEventsEnabled)
      return reply(res,503,{ok:false,reason:'event-egress-disabled'});
    const shared=await enforceShared(identity.client,req.headers['x-fw-nonce'],'activity-acquisition');
    if(!shared.ok)return reply(res,shared.status,{ok:false,reason:shared.reason},
      shared.retryAfterSeconds?{'Retry-After':String(shared.retryAfterSeconds)}:{});
    signedClients.add('activity');
    try{
      return reply(res,200,{ok:true,...await activityAcquisition.get(command.source,eventQuery)});
    }catch(error){
      // Public reason codes only; never expose upstream body, URL or credentials.
      // A GDELT 200 text throttle and subsequent cooldown are NOT valid news.
      const reason=error?.message==='gdelt-throttled'?'activity-provider-rate-limited'
        :error?.message==='upstream-cooldown'?'activity-provider-cooldown'
        :'activity-upstream-unavailable';
      return reply(res,503,{ok:false,reason});
    }
   }
   if(path==='/api/v1/shadow/probe'){
    // A server-to-server signature must never be accepted from a browser
    // carrying ambient cookies, bearer authorization or Origin metadata.
    if(req.headers.origin||req.headers.cookie||req.headers.authorization)
     return reply(res,403,{ok:false,reason:'server-to-server-only'});
    if(req.method!=='POST')return reply(res,405,{ok:false,reason:'method-not-allowed'});
    if(!/^application\/json(?:\s*;|$)/i.test(req.headers['content-type']||''))
     return reply(res,415,{ok:false,reason:'json-required'});
    let body;
    try{body=await limitedBody(req);}
    catch{return reply(res,413,{ok:false,reason:'request-too-large'},{Connection:'close'});}
    const identity=auth.verify(req,body,path);
    if(!identity.ok)return reply(res,identity.status,{ok:false,reason:identity.reason});
    const shared=await enforceShared(identity.client,req.headers['x-fw-nonce'],'shadow-probe');
    if(!shared.ok)return reply(res,shared.status,{ok:false,reason:shared.reason},
      shared.retryAfterSeconds?{'Retry-After':String(shared.retryAfterSeconds)}:{});
    probeClient=identity.client;signedClients.add(identity.client);
    let command;
    try{command=JSON.parse(body);}
    catch{return reply(res,400,{ok:false,reason:'invalid-json'});}
    if(!command||typeof command!=='object'||Array.isArray(command)
      ||Object.keys(command).length!==1||typeof command.routeId!=='string'
      ||!/^[a-z0-9-]{1,64}$/.test(command.routeId))
      return reply(res,400,{ok:false,reason:'unsupported-command'});
    probeRoute=command.routeId;
    const result=await egress.probe(identity.client,command.routeId);
    return reply(res,result.status,result.result,
      result.result.retryAfterSeconds?{'Retry-After':String(result.result.retryAfterSeconds)}:{});
   }
   return reply(res,404,{ok:false,reason:'not-found'});
  }catch{
   return reply(res,503,{ok:false,reason:'gateway-unavailable'});
  }
 });
 server.requestTimeout=10000;
 server.headersTimeout=12000;
 server.keepAliveTimeout=3500;
 server.on('clientError',(_error,socket)=>{if(socket.writable)socket.end('HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n');});
 return {server,auth,access,egress,githubCanary,assistant};
}
export function startServer(env=process.env){
 const port=Number(env.PORT||8789);
 if(!Number.isInteger(port)||port<1||port>65535)throw Error('invalid-port');
 const host=env.HOST||'0.0.0.0';
 const app=createGatewayServer({env});
 app.server.listen(port,host,()=>console.log(JSON.stringify({
  service:'federation-firewall-gateway',stage:'shadow-hold',port,
  canaryEgressEnabled:app.egress.liveEnabled,cutoverEnabled:false,
 })));
 return app;
}
if(process.argv[1]&&resolve(process.argv[1])===fileURLToPath(import.meta.url))startServer();
