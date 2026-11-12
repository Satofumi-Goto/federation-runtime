import http from 'node:http';
import {createTenAppChanges} from './tenAppChanges.mjs';
import {randomBytes} from 'node:crypto';
import {fileURLToPath} from 'node:url';
import {resolve,dirname,join} from 'node:path';
import {readFileSync} from 'node:fs';
import {createAuthenticator,keyringHealth} from './auth.mjs';
import {createAccessVerifier} from './access.mjs';
import {createEgress} from './egress.mjs';
import {createActivityAcquisition,validateEventQuery,NEWS_SOURCE_IDS,TOKYO_EVENT_SOURCE_IDS} from './activitySources.mjs';
import {createGithubCanaryVerifier} from './githubCanary.mjs';
import {createAssistant,parseAssistantCommand,ASSISTANT_PATH,ASSISTANT_MAX_BODY,ASSISTANT_POLICY} from './assistant.mjs';
import {createFreeAi,parseFreeAiCommand,FREE_AI_PATH,FREE_AI_MAX_BODY,FREE_AI_POLICY} from './freeAi.mjs';
import {createRegisteredAi,registeredProvider,parseRegisteredAiCommand,REGISTERED_AI_PROVIDERS} from './registeredAi.mjs';
import {publicCatalog,publicClients,SIGNING_CONTRACT} from './policy.mjs';
import {renderConsole} from './ui.mjs';
import {independentApps,INDEPENDENT_ORIGINS,SERVING_HOSTS} from './origins.mjs';
import {publicAcquisitionLedger} from './acquisitionLedger.mjs';
import {storeFromEnv,createSharedGuards} from './store.mjs';
import {precheckSignedHeaders,declaredTooLarge,findSecret} from './hardening.mjs';

const SECURITY_HEADERS=Object.freeze({
 'Cache-Control':'no-store',
 'X-Content-Type-Options':'nosniff',
 'X-Frame-Options':'DENY',
 'Referrer-Policy':'no-referrer',
 'Permissions-Policy':'camera=(), microphone=(), geolocation=(), payment=()',
 'Cross-Origin-Resource-Policy':'same-origin',
 'Cross-Origin-Opener-Policy':'same-origin',
 'Strict-Transport-Security':'max-age=31536000; includeSubDomains',
});
const safeCsp=nonce=>"default-src 'none'; base-uri 'none'; object-src 'none'; frame-ancestors 'none'; form-action 'none'; img-src 'none'; script-src 'none'; connect-src 'none'; style-src 'nonce-"+nonce+"'";
function reply(res,status,data,extra={}){
 const headers={...SECURITY_HEADERS,'Content-Type':'application/json; charset=utf-8',
  'Content-Security-Policy':"default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'",...extra};
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
export const AUDIT_EXPORT_MAX=300;
export function readinessStatus({env=process.env,distributed=false,observed={}}={}){
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
  // Measured in this process (additive; never promotes the boolean flags above).
  observed:{signedServerToServerClients:[...(observed.signedClients||[])].sort(),
   durableAuditExport:{lastExportAt:observed.lastAuditExportAt||null,exportsThisProcess:observed.auditExports||0,
    sink:'federation-api PostgreSQL append-only table (pulled with the federation HMAC key)'}},
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
 const tenAppChanges=createTenAppChanges({env,store:sharedStore,fetchImpl,clock,observe:record=>auditSink(JSON.stringify(record))});
 async function enforceShared(client,nonce,kind){
  if(!requireShared)return {ok:true};
  if(!sharedGuards||!sharedStore)return {ok:false,status:503,reason:'security-store-unavailable'};
  const replay=await sharedGuards.replay(client,nonce);
  if(!replay.ok)return replay;
  const budget=await sharedGuards.budget(client,clock(),['free-ai','audit-export'].includes(kind)?kind:null);
  if(!budget.ok)return budget;
  try{
   const audit=await sharedStore.appendAudit({
     type:'firewall.signed.accepted',at:new Date(clock()).toISOString(),
     client,kind
   });
   if(!audit.ok)return {ok:false,status:503,reason:'security-audit-unavailable'};
   if(audit.changePending)tenAppChanges.changed();
  }catch{return {ok:false,status:503,reason:'security-audit-unavailable'};}
  return {ok:true};
 }
 const assistant=createAssistant({env,fetchImpl,clock});
 const freeAi=createFreeAi({env,fetchImpl,clock});
 const registeredAi=createRegisteredAi({env,fetchImpl,clock});
 // Dedicated free-AI credential for the federation client only. It authorizes the
 // free-AI relay and the read-only audit export, nothing else, and leaves
 // FIREWALL_CLIENT_KEYS_JSON untouched.
 const freeAiKey=env.FIREWALL_FREE_AI_FEDERATION_KEY||'';
 const freeAiAuth=createAuthenticator({env:{
   FIREWALL_CLIENT_KEYS_JSON:freeAiKey?JSON.stringify({federation:freeAiKey}):''
 },clock});
 // Key hygiene across the main ring and every dedicated key (labels only, no key material).
 const keyHealth=keyringHealth(new Map([
  ...auth.keyring(),
  ...[['activity:acquisition',sourceAuth],['activity:news',newsAuth],['activity:event',eventAuth],
   ['activity:tokyo',tokyoAuth],['federation:free-ai',freeAiAuth]]
   .flatMap(([label,a])=>[...a.keyring().values()].map(list=>[label,list])),
 ]));
 const signedClients=new Set();
 const auditExport={lastAt:null,count:0};
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
  // Free AI audit: never record messages, answers, signature or IP.
  let freeClient=null,freeProvider=null,freeRole=null,freeAttempts=null;
  if(path===FREE_AI_PATH)res.once('finish',()=>{
    try{auditSink(JSON.stringify({
      type:'firewall.free-ai.request',at:new Date(clock()).toISOString(),
      method:req.method,status:res.statusCode,client:freeClient,provider:freeProvider,role:freeRole,
      attempts:freeAttempts,
    }));}catch{/* Observability must not interrupt responses. */}
  });
  // Activity acquisition / admin audit: fixed metadata only, never body or IP.
  let actClient=null,actSource=null;
  if(path==='/api/v1/activity/acquire')res.once('finish',()=>{
    try{auditSink(JSON.stringify({
      type:'firewall.activity.request',at:new Date(clock()).toISOString(),
      method:req.method,status:res.statusCode,client:actClient,source:actSource,
    }));}catch{/* Observability must not interrupt responses. */}
  });
  if(path==='/admin')res.once('finish',()=>{
    try{auditSink(JSON.stringify({
      type:'firewall.admin.request',at:new Date(clock()).toISOString(),
      method:req.method,status:res.statusCode,
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
    return reply(res,200,readinessStatus({env,distributed:!!sharedStore,
      observed:{signedClients,lastAuditExportAt:auditExport.lastAt,auditExports:auditExport.count}}));
   if(req.method==='GET'&&path==='/api/status')
    return reply(res,200,{service:'federation-firewall-gateway',stage:'shadow-hold',
      configuredClients:auth.configured,configuredClientIds:[...auth.configuredIds()].sort(),
      clientKeys:keyHealth,
      registeredApps:publicClients().appCount,canaryEgressEnabled:egress.liveEnabled,
      activityAcquisitionEnabled:activitySourcesEnabled,
      assistantEnabled:assistant.enabled,
      freeAiEnabled:freeAi.enabled,
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
      assistant:{...ASSISTANT_POLICY,enabled:assistant.enabled},
      freeAi:{...FREE_AI_POLICY,enabled:freeAi.enabled}});
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
    if(declaredTooLarge(req,ASSISTANT_MAX_BODY))return deny(413,'too_large',{},{Connection:'close'});
    const pre=precheckSignedHeaders(req,clock);
    if(!pre.ok)return deny(pre.status,'origin_not_allowed',{reason:pre.reason},{Connection:'close'});
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
    const c=parsed.command;
    const leaked=findSecret([c.question,c.context,c.page,...c.history.map(m=>m.content),
      ...Object.values(c.character||{}).flat().filter(v=>typeof v==='string')]);
    if(leaked)return deny(400,'invalid_question',{reason:'secret-detected',requestId:c.requestId||null});
    const result=await assistant.ask(identity.client,parsed.command);
    return reply(res,result.status,result.result,
      result.result.retryAfterSeconds?{'Retry-After':String(result.result.retryAfterSeconds)}:{});
   }
   if(req.method==='GET'&&path==='/api/free-ai')
    return reply(res,200,{...FREE_AI_POLICY,...freeAi.info()});
   if(req.method==='GET'&&path==='/api/registered-ai')
    return reply(res,200,registeredAi.info());
   if(path===FREE_AI_PATH){
    // Anonymous and explicitly enabled registered providers share the HMAC boundary.
    if(req.headers.origin||req.headers.cookie||req.headers.authorization)
     return reply(res,403,{ok:false,error:'server-to-server-only'});
    if(req.method!=='POST')return reply(res,405,{ok:false,error:'method-not-allowed'});
    if(!/^application\/json(?:\s*;|$)/i.test(req.headers['content-type']||''))
     return reply(res,415,{ok:false,error:'json-required'});
    if(declaredTooLarge(req,FREE_AI_MAX_BODY))
     return reply(res,413,{ok:false,error:'request-too-large'},{Connection:'close'});
    const pre=precheckSignedHeaders(req,clock);
    if(!pre.ok)return reply(res,pre.status,{ok:false,error:pre.reason},{Connection:'close'});
    let body;
    try{body=await limitedBody(req,FREE_AI_MAX_BODY);}
    catch{return reply(res,413,{ok:false,error:'request-too-large'},{Connection:'close'});}
    let identity=freeAiAuth.configured&&req.headers['x-fw-client']==='federation'
      ?freeAiAuth.verify(req,body,path):auth.verify(req,body,path);
    if(!identity.ok&&freeAiAuth.configured&&req.headers['x-fw-client']==='federation'
      &&['signature-invalid'].includes(identity.reason)&&auth.configured)
      identity=auth.verify(req,body,path);
    if(!identity.ok)return reply(res,identity.status,{ok:false,error:identity.reason});
    const shared=await enforceShared(identity.client,req.headers['x-fw-nonce'],'free-ai');
    if(!shared.ok)return reply(res,shared.status,{ok:false,error:shared.reason});
    freeClient=identity.client;signedClients.add(identity.client);
    const registered=registeredProvider(body);
    const parsed=registered?parseRegisteredAiCommand(body):parseFreeAiCommand(body);
    if(!parsed.ok)return reply(res,parsed.status,{ok:false,error:parsed.error});
    freeRole=parsed.command.role;
    // Prompts must not contain credentials, including for registered providers.
    if(findSecret(parsed.command.messages.map(m=>m.content)))
     return reply(res,422,{ok:false,error:'secret-detected'});
    const result=await (registered?registeredAi:freeAi).chat(identity.client,parsed.command);
    freeProvider=result.result.provider||null;
    // Provider id + fixed reason codes only (no prompt, answer, model text or key).
    freeAttempts=Array.isArray(result.result.attempts)?result.result.attempts.slice(0,20).map(a=>({
      provider:String(a.provider||'').slice(0,24),
      ...(a.ok?{ok:true}:{}),
      ...(a.skipped?{skipped:String(a.skipped).slice(0,40)}:{}),
      ...(a.failed?{failed:String(a.failed).slice(0,40)}:{}),
    })):null;
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
    const pre=precheckSignedHeaders(req,clock);
    if(!pre.ok)return reply(res,pre.status,{ok:false,reason:pre.reason},{Connection:'close'});
    let body;
    try{body=await limitedBody(req,128);}
    catch{return reply(res,413,{ok:false,reason:'request-too-large'},{Connection:'close'});}
    let command;
    try{command=JSON.parse(body);}
    catch{return reply(res,400,{ok:false,reason:'invalid-json'});}
    const kawasakiSource=command?.source==='events';
    const eventSource=kawasakiSource||TOKYO_EVENT_SOURCE_IDS.includes(command?.source)||command?.source==='japan_event_events';
    const keys=command&&typeof command==='object'&&!Array.isArray(command)
      ?Object.keys(command).sort().join(','):'';
    const eventQuery=kawasakiSource&&keys==='from,page,source,to'
      ?validateEventQuery(command,clock()):null;
    if(!command||typeof command!=='object'||Array.isArray(command)||
      !['tv','online',...NEWS_SOURCE_IDS,'events','anilist',...TOKYO_EVENT_SOURCE_IDS,'japan_event_events'].includes(command.source)||
      (kawasakiSource?!eventQuery:keys!=='source'))
      return reply(res,400,{ok:false,reason:'unsupported-command'});
    const newsSource=NEWS_SOURCE_IDS.includes(command.source);
    // The Tokyo-only staging key is an ADDITIONAL, isolated credential, never
    // a replacement or authorization for Kawasaki, TV, news or any user data.
    let identity=(eventSource?eventAuth:newsSource?newsAuth:sourceAuth).verify(req,body,path);
    const tokyoSource=TOKYO_EVENT_SOURCE_IDS.includes(command.source);
    if(!identity.ok&&tokyoSource&&tokyoAuth.configured&&
       ['service-auth-unconfigured','signature-invalid'].includes(identity.reason))
      identity=tokyoAuth.verify(req,body,path);
    if(!identity.ok)return reply(res,identity.status,{ok:false,reason:identity.reason});
    if(identity.client!=='activity')return reply(res,403,{ok:false,reason:'activity-only'});
    actClient=identity.client;actSource=command.source;
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
   // Durable audit: federation-api pulls the newest records (metadata only) and
   // stores them in an append-only PostgreSQL table. Federation only: its main key,
   // or its dedicated free-AI key (the key federation-api holds). Read-only, no egress.
   if(path==='/api/v1/audit/export'){
    if(req.headers.origin||req.headers.cookie||req.headers.authorization)
     return reply(res,403,{ok:false,reason:'server-to-server-only'});
    if(req.method!=='POST')return reply(res,405,{ok:false,reason:'method-not-allowed'});
    if(!/^application\/json(?:\s*;|$)/i.test(req.headers['content-type']||''))
     return reply(res,415,{ok:false,reason:'json-required'});
    if(declaredTooLarge(req,128))
     return reply(res,413,{ok:false,reason:'request-too-large'},{Connection:'close'});
    const pre=precheckSignedHeaders(req,clock);
    if(!pre.ok)return reply(res,pre.status,{ok:false,reason:pre.reason},{Connection:'close'});
    let body;
    try{body=await limitedBody(req,128);}
    catch{return reply(res,413,{ok:false,reason:'request-too-large'},{Connection:'close'});}
    if(req.headers['x-fw-client']!=='federation')return reply(res,403,{ok:false,reason:'federation-only'});
    let identity=auth.verify(req,body,path);
    if(!identity.ok&&identity.reason==='signature-invalid'&&freeAiAuth.configured)
     identity=freeAiAuth.verify(req,body,path);
    if(!identity.ok)return reply(res,identity.status,{ok:false,reason:identity.reason});
    let command;
    try{command=JSON.parse(body);}catch{return reply(res,400,{ok:false,reason:'invalid-json'});}
    if(!command||typeof command!=='object'||Array.isArray(command)||Object.keys(command).join()!=='limit'
      ||!Number.isInteger(command.limit)||command.limit<1||command.limit>AUDIT_EXPORT_MAX)
     return reply(res,400,{ok:false,reason:'unsupported-command'});
    if(!sharedStore||typeof sharedStore.readAudit!=='function')
     return reply(res,503,{ok:false,reason:'security-store-unavailable'});
    const shared=await enforceShared(identity.client,req.headers['x-fw-nonce'],'audit-export');
    if(!shared.ok)return reply(res,shared.status,{ok:false,reason:shared.reason},
      shared.retryAfterSeconds?{'Retry-After':String(shared.retryAfterSeconds)}:{});
    signedClients.add(identity.client);
    const read=await sharedStore.readAudit(command.limit);
    if(!read.ok)return reply(res,503,{ok:false,reason:'security-store-unavailable'});
    auditExport.lastAt=new Date(clock()).toISOString();auditExport.count++;
    return reply(res,200,{ok:true,schema:'federation.firewall-audit-export/1',order:'newest-first',
      count:read.lines.length,records:read.lines});
   }
   if(path==='/api/v1/shadow/probe'){
    // A server-to-server signature must never be accepted from a browser
    // carrying ambient cookies, bearer authorization or Origin metadata.
    if(req.headers.origin||req.headers.cookie||req.headers.authorization)
     return reply(res,403,{ok:false,reason:'server-to-server-only'});
    if(req.method!=='POST')return reply(res,405,{ok:false,reason:'method-not-allowed'});
    if(!/^application\/json(?:\s*;|$)/i.test(req.headers['content-type']||''))
     return reply(res,415,{ok:false,reason:'json-required'});
    if(declaredTooLarge(req,512))
     return reply(res,413,{ok:false,reason:'request-too-large'},{Connection:'close'});
    const pre=precheckSignedHeaders(req,clock);
    if(!pre.ok)return reply(res,pre.status,{ok:false,reason:pre.reason},{Connection:'close'});
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
 // Bound open sockets and requests per keep-alive socket (slow-loris / pipelining).
 server.maxConnections=Number.isInteger(Number(env.FIREWALL_MAX_CONNECTIONS))&&Number(env.FIREWALL_MAX_CONNECTIONS)>=8
  &&Number(env.FIREWALL_MAX_CONNECTIONS)<=1024?Number(env.FIREWALL_MAX_CONNECTIONS):128;
 server.maxRequestsPerSocket=100;
 server.on('clientError',(_error,socket)=>{if(socket.writable)socket.end('HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n');});
 server.once('listening',()=>tenAppChanges.start());server.once('close',()=>tenAppChanges.stop());
 return {server,auth,access,egress,githubCanary,assistant,freeAi,registeredAi};
}
// Owner-controlled, default-off, exactly one bounded public-text call per boot.
// No endpoint, schedule, retry, prompt/answer log, or new caller authorization.
export async function probeRegisteredAiOnce(ai,env=process.env,auditSink=console.info){
 const provider=env.FIREWALL_REGISTERED_AI_PROBE_ON_START;
 if(typeof provider!=='string'||!Object.hasOwn(REGISTERED_AI_PROVIDERS,provider))return null;
 let event;
 try{
  const r=await ai.chat('federation',{provider,role:'summarize',
   messages:[{role:'user',content:'Reply with the single word OK.'}],maxTokens:256});
  const upstream=ai.info().providers.find(p=>p.id===provider);
  event={type:'firewall.registered-ai.probe',provider,
   ok:r.status===200&&r.result?.ok===true&&typeof r.result.text==='string'&&!!r.result.text.trim(),
   httpStatus:r.status,upstreamHttpStatus:upstream?.lastHttpStatus??null};
 }catch{event={type:'firewall.registered-ai.probe',provider,ok:false,error:'probe-failed'};}
 try{auditSink(JSON.stringify(event));}catch{/* Diagnostics cannot fail startup. */}
 return event;
}
export function startServer(env=process.env){
 const port=Number(env.PORT||8789);
 if(!Number.isInteger(port)||port<1||port>65535)throw Error('invalid-port');
 const host=env.HOST||'0.0.0.0';
 const app=createGatewayServer({env});
 app.server.listen(port,host,()=>{
  console.log(JSON.stringify({service:'federation-firewall-gateway',stage:'shadow-hold',port,
   canaryEgressEnabled:app.egress.liveEnabled,cutoverEnabled:false}));
  void probeRegisteredAiOnce(app.registeredAi,env);
 });
 return app;
}
if(process.argv[1]&&resolve(process.argv[1])===fileURLToPath(import.meta.url))startServer();
