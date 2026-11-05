// One-shot, read-only, no secrets persisted. Used only by a pinned GH Actions workflow.
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
const WORKFLOW='Satofumi-Goto/federation-runtime/.github/workflows/firewall-holidays-canary-once.yml@refs/heads/main';
const ORIGIN='https://federation-firewall-gateway.onrender.com';
const LEGACY='https://holidays-jp.github.io/api/v1/date.json';
const AUD='federation-firewall-holidays-canary/1';
assert.equal(process.env.GITHUB_REPOSITORY,'Satofumi-Goto/federation-runtime');
assert.equal(process.env.GITHUB_REF,'refs/heads/main');
assert.equal(process.env.GITHUB_WORKFLOW_REF,WORKFLOW);
assert.equal(process.env.GITHUB_EVENT_NAME,'push');
assert.equal(process.env.GITHUB_ACTOR_ID,'281488838');
assert.equal(process.env.GITHUB_RUN_ATTEMPT,'1');
assert.equal(process.env.GITHUB_RUN_NUMBER,'1');
const tokenUrl=process.env.ACTIONS_ID_TOKEN_REQUEST_URL;
const tokenAuth=process.env.ACTIONS_ID_TOKEN_REQUEST_TOKEN;
assert.ok(tokenAuth&&tokenAuth.length>16,'GitHub OIDC unavailable');
assert.ok(typeof tokenUrl==='string','GitHub OIDC URL unavailable');
const endpoint=new URL(tokenUrl);
assert.equal(endpoint.protocol,'https:');
assert.ok(endpoint.hostname==='pipelines.actions.githubusercontent.com','Unexpected OIDC provider host');
endpoint.searchParams.set('audience',AUD);
const digest=value=>createHash('sha256').update(JSON.stringify(value)).digest('hex').slice(0,16);
async function getJson(resp,max){
 assert.ok(resp.ok,'HTTP status '+resp.status);
 assert.ok(![301,302,303,307,308].includes(resp.status),'No redirects');
 assert.match(resp.headers.get('content-type')||'',/application\/json/i);
 assert.ok(Number(resp.headers.get('content-length'))<=max,'Oversized response header');
 const reader=resp.body?.getReader();assert.ok(reader,'Unstreamable response');
 let size=0;const chunks=[];
 try{
  for(;;){
   const {done,value}=await reader.read();
   if(done)break;
   size+=value.byteLength;
   if(size>max){await reader.cancel().catch(()=>{});throw Error('Response size exceeded');}
   chunks.push(Buffer.from(value));
  }
 }finally{reader.releaseLock();}
 return JSON.parse(Buffer.concat(chunks,size).toString('utf8'));
}
function normalize(data){
 assert.ok(data&&typeof data==='object'&&!Array.isArray(data),'Holiday object required');
 const entries=Object.entries(data).sort(([a],[b])=>a.localeCompare(b));
 assert.ok(entries.length>=1&&entries.length<=500,'Invalid holiday count');
 for(const [date,name] of entries){
  assert.match(date,/^[0-9]{4}-[0-9]{2}-[0-9]{2}$/);
  assert.ok(typeof name==='string'&&name.trim().length>0&&name.length<=120);
 }
 return Object.fromEntries(entries);
}
// Warm the free hosting tier BEFORE minting a short-lived OIDC token.
const warm=await fetch(ORIGIN+'/healthz',{redirect:'manual',signal:AbortSignal.timeout(45000)});
const health=await getJson(warm,2048);
assert.equal(health.cutoverEnabled,false);
assert.equal(health.productionReady,false);
const grant=await fetch(endpoint,{
 method:'GET',headers:{Authorization:'Bearer '+tokenAuth,Accept:'application/json'},
 redirect:'manual',signal:AbortSignal.timeout(8000),
});
const secret=await getJson(grant,20000);
assert.ok(typeof secret.value==='string'&&secret.value.split('.').length===3,'JWT missing');
const packetResponse=await fetch(ORIGIN+'/api/v1/canary/github',{
 method:'POST',headers:{Authorization:'Bearer '+secret.value,
  'Content-Type':'application/json',Accept:'application/json'},
 redirect:'manual',signal:AbortSignal.timeout(25000),
 body:'{"routeId":"japan-holidays"}',
});
if(!packetResponse.ok)throw Error('Firewall canary unavailable: HTTP '+packetResponse.status);
const packet=await getJson(packetResponse,134000);
assert.equal(packet.ok,true);
assert.equal(packet.mode,'shadow-only');
assert.equal(packet.routeId,'japan-holidays');
assert.equal(packet.sourceUrl,LEGACY);
assert.equal(packet.provider,'holidays-jp');
assert.ok(Date.now()-Date.parse(packet.fetchedAt)>=-300000);
assert.ok(Date.now()-Date.parse(packet.fetchedAt)<=900000);
const gateway=normalize(packet.data);
const incumbentResponse=await fetch(LEGACY,{
 method:'GET',headers:{Accept:'application/json'},
 redirect:'manual',signal:AbortSignal.timeout(12000),
});
const incumbent=normalize(await getJson(incumbentResponse,131072));
assert.deepEqual(gateway,incumbent,'Gateway and incumbent differ');
console.log(JSON.stringify({stage:'github-oidc-holiday-canary-parity-passed',
 gatewayStatus:packetResponse.status,sourceStatus:incumbentResponse.status,
 gatewayCount:Object.keys(gateway).length,incumbentCount:Object.keys(incumbent).length,
 gatewayHash:digest(gateway),incumbentHash:digest(incumbent),
 sourceFetchedAt:packet.fetchedAt,legacyRetained:true,cutover:false,
 activitySignedE2e:false,networkWafVerified:false}));
