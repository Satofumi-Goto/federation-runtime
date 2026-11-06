import http from 'node:http';
import {randomBytes} from 'node:crypto';
import {fileURLToPath} from 'node:url';
import {resolve} from 'node:path';
import {createAuthenticator} from './auth.mjs';
import {createAccessVerifier} from './access.mjs';
import {createEgress} from './egress.mjs';
import {createGithubCanaryVerifier} from './githubCanary.mjs';
import {createAssistant,parseAssistantCommand,ASSISTANT_PATH,ASSISTANT_MAX_BODY,ASSISTANT_POLICY} from './assistant.mjs';
import {publicCatalog,publicClients,SIGNING_CONTRACT} from './policy.mjs';
import {renderConsole} from './ui.mjs';

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
export function createGatewayServer({env=process.env,fetchImpl=fetch,clock=Date.now,auditSink=console.info}={}){
 const auth=createAuthenticator({env,clock});
 const access=createAccessVerifier({env,fetchImpl,clock});
 const egress=createEgress({env,fetchImpl,clock});
 const githubCanary=createGithubCanaryVerifier({env,fetchImpl,clock});
 const assistant=createAssistant({env,fetchImpl,clock});
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
  let askClient=null,askCharacter=null;
  if(path===ASSISTANT_PATH)res.once('finish',()=>{
    try{auditSink(JSON.stringify({
      type:'firewall.assistant.request',at:new Date(clock()).toISOString(),
      method:req.method,status:res.statusCode,client:askClient,characterId:askCharacter,
    }));}catch{/* Observability must not interrupt responses. */}
  });
  if(!req.url||req.url.length>1024)return reply(res,414,{ok:false,reason:'invalid-target'});
  try{
   if(req.method==='GET'&&path==='/healthz')
    return reply(res,200,{service:'federation-firewall-gateway',stage:'shadow-hold',
      productionReady:false,cutoverEnabled:false});
   if(req.method==='GET'&&path==='/api/status')
    return reply(res,200,{service:'federation-firewall-gateway',stage:'shadow-hold',
      configuredClients:auth.configured,configuredClientIds:[...auth.configuredIds()].sort(),
      registeredApps:publicClients().appCount,canaryEgressEnabled:egress.liveEnabled,
      assistantEnabled:assistant.enabled,
      productionReady:false,cutoverEnabled:false,legacyConnectionsPreserved:true});
   if(req.method==='GET'&&path==='/api/catalog')
    return reply(res,200,publicCatalog());
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
    if(req.headers.origin||req.headers.cookie||req.headers.authorization)
     return reply(res,403,{ok:false,reason:'server-to-server-only'});
    if(req.method!=='POST')return reply(res,405,{ok:false,reason:'method-not-allowed'});
    if(!/^application\/json(?:\s*;|$)/i.test(req.headers['content-type']||''))
     return reply(res,415,{ok:false,reason:'json-required'});
    let body;
    try{body=await limitedBody(req,ASSISTANT_MAX_BODY);}
    catch{return reply(res,413,{ok:false,reason:'request-too-large'},{Connection:'close'});}
    const identity=auth.verify(req,body,path);
    if(!identity.ok)return reply(res,identity.status,{ok:false,reason:identity.reason});
    askClient=identity.client;
    const parsed=parseAssistantCommand(body);
    if(!parsed.ok)return reply(res,parsed.status,{ok:false,reason:parsed.reason});
    askCharacter=parsed.command.characterId;
    const result=await assistant.ask(identity.client,parsed.command);
    return reply(res,result.status,result.result,
      result.result.retryAfterSeconds?{'Retry-After':String(result.result.retryAfterSeconds)}:{});
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
    probeClient=identity.client;
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
