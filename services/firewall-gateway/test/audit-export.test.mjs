import test from 'node:test';
import assert from 'node:assert/strict';
import {randomBytes} from 'node:crypto';
import {createGatewayServer,readinessStatus,AUDIT_EXPORT_MAX} from '../server.mjs';
import {signHeaders} from '../auth.mjs';

const NOW=Date.parse('2026-11-11T06:30:00.000Z');
const PATH='/api/v1/audit/export';
const fed=randomBytes(32),sen=randomBytes(32),freeOnly=randomBytes(32);
function fakeRedis(){
 const data=new Map();
 const run=([cmd,...a])=>{
  if(cmd==='SET'){if(data.has(a[0]))return null;data.set(a[0],a[1]);return 'OK';}
  if(cmd==='INCR'){const v=(data.get(a[0])||0)+1;data.set(a[0],v);return v;}
  if(cmd==='PEXPIRE')return 1;
  if(cmd==='LPUSH'){const v=data.get(a[0])||[];v.unshift(a[1]);data.set(a[0],v);return v.length;}
  if(cmd==='LTRIM'){const v=data.get(a[0])||[];data.set(a[0],v.slice(Number(a[1]),Number(a[2])+1));return 'OK';}
  if(cmd==='LRANGE')return (data.get(a[0])||[]).slice(Number(a[1]),Number(a[2])+1);
  return {error:'unknown'};
 };
 return async(url,init)=>new Response(JSON.stringify(JSON.parse(init.body).map(c=>({result:run(c)}))),
  {status:200,headers:{'content-type':'application/json'}});
}
const distributedEnv={FIREWALL_CLIENT_KEYS_JSON:JSON.stringify({federation:fed.toString('base64url'),seneschal:sen.toString('base64url')}),
 FIREWALL_FREE_AI_FEDERATION_KEY:freeOnly.toString('base64url'),
 FIREWALL_STORE:'redis-rest',FIREWALL_STORE_REST_URL:'https://firewall-example.upstash.io',FIREWALL_STORE_REST_TOKEN:'a'.repeat(30),
 FIREWALL_REQUIRE_DISTRIBUTED_STORE:'true'};
async function withGateway(env,run){
 const app=createGatewayServer({env,fetchImpl:fakeRedis(),clock:()=>NOW,auditSink:()=>{}});
 await new Promise(r=>app.server.listen(0,'127.0.0.1',r));
 try{await run('http://127.0.0.1:'+app.server.address().port);}finally{await new Promise(r=>app.server.close(r));}
}
async function exportCall(origin,{client='federation',key=fed,body='{"limit":50}',extra={}}={}){
 const h=signHeaders({client,key,body,path:PATH,time:NOW});
 const r=await fetch(origin+PATH,{method:'POST',body,headers:{'content-type':'application/json',...h,...extra}});
 return {status:r.status,data:await r.json()};
}

test('federation main key exports newest-first audit metadata; the export itself is audited',async()=>{
 await withGateway(distributedEnv,async origin=>{
  const first=await exportCall(origin);
  assert.equal(first.status,200);
  assert.equal(first.data.schema,'federation.firewall-audit-export/1');
  assert.equal(first.data.order,'newest-first');
  const records=first.data.records.map(l=>JSON.parse(l));
  assert.equal(records[0].type,'firewall.signed.accepted');assert.equal(records[0].kind,'audit-export');
  const second=await exportCall(origin);
  assert.equal(second.data.count,2);
  const ready=await (await fetch(origin+'/_status/readiness')).json();
  assert.equal(ready.observed.durableAuditExport.exportsThisProcess,2);
  assert.equal(ready.observed.durableAuditExport.lastExportAt,new Date(NOW).toISOString());
  assert.deepEqual(ready.observed.signedServerToServerClients,['federation']);
  assert.equal(ready.authenticatedE2E,false);assert.equal(ready.productionReady,false);
 });
});

test('federation main key or its dedicated free-AI key may export; other clients are refused',async()=>{
 await withGateway(distributedEnv,async origin=>{
  assert.equal((await exportCall(origin,{client:'seneschal',key:sen})).data.reason,'federation-only');
  const dedicated=await exportCall(origin,{key:freeOnly});
  assert.equal(dedicated.status,200);assert.equal(dedicated.data.schema,'federation.firewall-audit-export/1');
  assert.equal((await exportCall(origin,{key:randomBytes(32)})).data.reason,'signature-invalid');
  const r=await fetch(origin+PATH,{method:'POST',body:'{"limit":5}',headers:{'content-type':'application/json'}});
  assert.equal(r.status,401);
  assert.equal((await exportCall(origin,{extra:{origin:'https://evil.example'}})).status,403);
 });
});

test('export command is strict and requires the distributed store',async()=>{
 await withGateway(distributedEnv,async origin=>{
  for(const body of ['{"limit":0}','{"limit":'+(AUDIT_EXPORT_MAX+1)+'}','{"limit":"5"}','{"limit":5,"x":1}','{}','[]'])
   assert.equal((await exportCall(origin,{body})).data.reason,'unsupported-command',body);
 });
 const {FIREWALL_STORE,FIREWALL_STORE_REST_URL,FIREWALL_STORE_REST_TOKEN,FIREWALL_REQUIRE_DISTRIBUTED_STORE,...memoryEnv}=distributedEnv;
 await withGateway(memoryEnv,async origin=>{
  assert.equal((await exportCall(origin)).data.reason,'security-store-unavailable');
 });
});

test('readiness observed evidence is additive and empty by default',()=>{
 const r=readinessStatus({env:{}});
 assert.deepEqual(r.observed.signedServerToServerClients,[]);
 assert.equal(r.observed.durableAuditExport.lastExportAt,null);
 assert.equal(r.storageIndependent,false);
});

test('identical events stay distinct: every exported line carries a unique id',async()=>{
 await withGateway(distributedEnv,async origin=>{
  await exportCall(origin);await exportCall(origin);
  const r=await exportCall(origin);
  const records=r.data.records.map(l=>JSON.parse(l));
  assert.equal(records.length,3);
  assert.equal(new Set(r.data.records).size,3);
  assert.equal(new Set(records.map(x=>x.id)).size,3);
  const {id,...rest}=records[0],{id:id2,...rest2}=records[1];
  assert.deepEqual(rest,rest2);
 });
});
