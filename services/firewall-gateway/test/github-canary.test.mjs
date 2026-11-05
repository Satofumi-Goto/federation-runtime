import test from 'node:test';
import assert from 'node:assert/strict';
import {generateKeyPairSync,sign as signRsa} from 'node:crypto';
import {createGithubCanaryVerifier,GITHUB_CANARY_AUDIENCE} from '../githubCanary.mjs';
import {createEgress} from '../egress.mjs';
import {createGatewayServer} from '../server.mjs';

const encode=v=>Buffer.from(JSON.stringify(v)).toString('base64url');
function fixture(){
 const {publicKey,privateKey}=generateKeyPairSync('rsa',{modulusLength:2048});
 const jwk=publicKey.export({format:'jwk'});jwk.kid='fixture-key';jwk.use='sig';
 const now=Date.now();
 const claims={
  iss:'https://token.actions.githubusercontent.com',
  aud:GITHUB_CANARY_AUDIENCE,
  sub:'repo:Satofumi-Goto/federation-runtime:ref:refs/heads/main',
  repository:'Satofumi-Goto/federation-runtime',repository_id:'1248370969',
  ref:'refs/heads/main',
  workflow_ref:'Satofumi-Goto/federation-runtime/.github/workflows/firewall-holidays-canary-once.yml@refs/heads/main',
  event_name:'push',actor_id:'281488838',sha:'a'.repeat(40),
  exp:Math.floor(now/1000)+240,iat:Math.floor(now/1000),
  jti:'fixture-unique-id-123456',
 };
 function token(overrides={}){
  const header=encode({alg:'RS256',kid:'fixture-key',typ:'JWT'});
  const payload=encode({...claims,...overrides});
  const data=header+'.'+payload;
  return data+'.'+signRsa('RSA-SHA256',Buffer.from(data),privateKey).toString('base64url');
 }
 const providerResponse=()=>Response.json({'2026-11-05':'文化的祝日'});
 let calls=0;
 async function fetchImpl(url){
  calls++;
  if(url==='https://token.actions.githubusercontent.com/.well-known/jwks')
   return Response.json({keys:[jwk]});
  if(url.startsWith('https://holidays-jp.github.io/'))return providerResponse();
  throw Error('unapproved-url');
 }
 return{token,fetchImpl,getCalls:()=>calls};
}
test('closed OIDC gate, strict repository claims and replay defense',async()=>{
 const f=fixture();
 const disabled=createGithubCanaryVerifier({env:{},fetchImpl:f.fetchImpl});
 assert.equal((await disabled.verify(f.token())).status,503);
 const verifier=createGithubCanaryVerifier({env:{FIREWALL_GITHUB_CANARY_OIDC:'true'},fetchImpl:f.fetchImpl});
 assert.equal((await verifier.verify(f.token({repository:'attacker/repo'}))).status,403);
 assert.equal((await verifier.verify(f.token({workflow_ref:'attacker-workflow'}))).status,403);
 assert.equal((await verifier.verify(f.token({aud:'wrong-audience'}))).status,403);
 assert.equal((await verifier.verify(f.token({event_name:'workflow_dispatch'}))).status,403);
 assert.equal((await verifier.verify(f.token())).ok,true);
 assert.equal((await verifier.verify(f.token())).status,409);
});
test('egress stays disabled unless BOTH global and holiday-only flags are exact',async()=>{
 const f=fixture();
 for(const env of [{FIREWALL_CANARY_EGRESS:'true'},
  {FIREWALL_CANARY_ROUTE_IDS:'japan-holidays'},{}]){
  const x=createEgress({env,fetchImpl:f.fetchImpl});
  assert.equal((await x.probe('federation','japan-holidays')).status,503);
 }
 const x=createEgress({env:{FIREWALL_CANARY_EGRESS:'true',FIREWALL_CANARY_ROUTE_IDS:'japan-holidays'},fetchImpl:f.fetchImpl});
 assert.equal((await x.probe('federation','open-meteo-tokyo')).status,403);
 assert.equal((await x.probe('federation','jma-earthquake-list')).status,403);
 assert.equal((await x.probe('federation','japan-holidays')).status,200);
});
test('only pinned workflow identity may call the holiday gateway endpoint',async()=>{
 const f=fixture();
 const app=createGatewayServer({
  env:{FIREWALL_GITHUB_CANARY_OIDC:'true',
   FIREWALL_CANARY_EGRESS:'true',FIREWALL_CANARY_ROUTE_IDS:'japan-holidays'},
  fetchImpl:f.fetchImpl,auditSink:()=>{},
 });
 await new Promise(done=>app.server.listen(0,'127.0.0.1',done));
 const url='http://127.0.0.1:'+app.server.address().port+'/api/v1/canary/github';
 const body='{"routeId":"japan-holidays"}';
 const post=(auth,headers={},payload=body)=>fetch(url,{method:'POST',
  headers:{'Content-Type':'application/json',Authorization:'Bearer '+auth,...headers},body:payload});
 try{
  assert.equal((await post(f.token(),{Origin:'https://bad.example'})).status,403);
  assert.equal((await post(f.token(),{},'{"routeId":"open-meteo-tokyo"}')).status,400);
  const ok=await post(f.token());
  assert.equal(ok.status,200);
  const packet=await ok.json();
  assert.equal(packet.routeId,'japan-holidays');
  assert.equal(packet.data['2026-11-05'],'文化的祝日');
  assert.equal(packet.mode,'shadow-only');
  assert.equal((await post(f.token())).status,409);
  const status=await fetch('http://127.0.0.1:'+app.server.address().port+'/api/status');
  assert.equal((await status.json()).cutoverEnabled,false);
 }finally{await new Promise(done=>app.server.close(done));}
});
