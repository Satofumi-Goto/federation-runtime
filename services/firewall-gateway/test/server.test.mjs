import test from 'node:test';
import assert from 'node:assert/strict';
import {createGatewayServer} from '../server.mjs';
test('independent app serves holding screen without changing application routes',async()=>{
 const app=createGatewayServer({env:{}});
 await new Promise(resolve=>app.server.listen(0,'127.0.0.1',resolve));
 const root='http://127.0.0.1:'+app.server.address().port;
 try{
  const health=await fetch(root+'/healthz');
  assert.equal(health.status,200);
  assert.equal((await health.json()).cutoverEnabled,false);
  const ui=await fetch(root+'/');
  assert.equal(ui.status,200);
  assert.match(await ui.text(),/SHADOW/);
  const admin=await fetch(root+'/admin');
  assert.equal(admin.status,503);
 }finally{await new Promise(resolve=>app.server.close(resolve));}
});
test('client registry endpoint reports key presence only, never key values',async()=>{
 const {randomBytes}=await import('node:crypto');
 const value=randomBytes(32).toString('base64url');
 const app=createGatewayServer({env:{FIREWALL_CLIENT_KEYS_JSON:JSON.stringify({seneschal:value})}});
 await new Promise(resolve=>app.server.listen(0,'127.0.0.1',resolve));
 const root='http://127.0.0.1:'+app.server.address().port;
 try{
  const response=await fetch(root+'/api/clients');
  assert.equal(response.status,200);
  assert.equal(response.headers.get('access-control-allow-origin'),null);
  const raw=await response.text(),data=JSON.parse(raw);
  assert.equal(data.appCount,10);
  assert.equal(data.clients.find(c=>c.id==='seneschal').keyConfigured,true);
  assert.equal(data.clients.find(c=>c.id==='activity').keyConfigured,false);
  assert.equal(data.signing.endpoint,'/api/v1/shadow/probe');
  assert.ok(!raw.includes(value));
  const status=await (await fetch(root+'/api/status')).json();
  assert.deepEqual(status.configuredClientIds,['seneschal']);
  assert.equal(status.registeredApps,10);
  const ui=await (await fetch(root+'/')).text();
  assert.match(ui,/App Client Registry/);
  assert.match(ui,/1 \/ 9 KEYS/);
  assert.ok(!ui.includes(value));
 }finally{await new Promise(resolve=>app.server.close(resolve));}
});
test('independent origin status endpoints report served SHA, parent and honest readiness',async()=>{
 const sha='0123456789abcdef0123456789abcdef01234567';
 const app=createGatewayServer({env:{RENDER_GIT_COMMIT:sha,RENDER_GIT_BRANCH:'main'}});
 await new Promise(resolve=>app.server.listen(0,'127.0.0.1',resolve));
 const root='http://127.0.0.1:'+app.server.address().port;
 try{
  const health=await fetch(root+'/healthz');
  assert.equal(health.status,200);
  const h=await health.json();
  assert.equal(h.ok,true);assert.equal(h.productionReady,false);assert.equal(h.cutoverEnabled,false);
  const headRes=await fetch(root+'/git-head.json');
  assert.equal(headRes.status,200);
  assert.equal(headRes.headers.get('cache-control'),'no-store');
  assert.equal(headRes.headers.get('access-control-allow-origin'),null);
  const head=await headRes.json();
  assert.equal(head.sha,sha);assert.equal(head.repository,'Satofumi-Goto/federation-runtime');
  assert.equal(head.sourceState,'render-git-commit');assert.equal(head.branch,'main');
  assert.equal(head.canonicalRepository,'Satofumi-Goto/federation-portal');
  const parent=await (await fetch(root+'/_status/parent')).json();
  assert.deepEqual(parent,{schema:'federation.runtime-child/1',service:'firewall-standalone',
   parentOrigin:'https://federation-runtime.com',origin:'https://federation-firewall-gateway.onrender.com',parentVerified:false,
   productionReady:false,authenticatedE2E:false,dnsVerified:false,gatewayService:'federation-firewall-gateway'});
  const ready=await (await fetch(root+'/_status/readiness')).json();
  // Shared family contract (#1007): fixed names and types; extra fields are additive.
  assert.equal(ready.schema,'federation.independent-readiness/1');assert.equal(ready.app,'firewall');
  for(const key of ['productionReady','frontendHostIndependent','backendIndependent','storageIndependent','authenticatedE2E','dnsVerified'])
   assert.equal(typeof ready[key],'boolean',key);
  assert.equal(ready.frontendHostIndependent,true);assert.ok(ready.evidence.frontendHostIndependent);
  assert.match(await (await fetch(root+'/')).text(),/Firewall Gateway/);
  assert.equal(ready.productionReady,false);assert.equal(ready.backendIndependent,true);
  assert.equal(ready.storageIndependent,false);assert.equal(ready.authenticatedE2E,false);
  assert.equal(ready.dnsVerified,false);assert.equal(ready.cutoverEnabled,false);assert.equal(ready.verifiedCutovers,0);
  for(const key of ['storageIndependent','authenticatedE2E','dnsVerified','productionReady'])assert.ok(ready.pending[key]);
  for(const p of ['/','/api/status','/api/catalog'])assert.equal((await fetch(root+p)).status,200);
  assert.equal((await fetch(root+'/git-head.json',{method:'POST'})).status,404);
 }finally{await new Promise(resolve=>app.server.close(resolve));}
});
test('git-head.json never invents a SHA when the platform value is missing or malformed',async()=>{
 const {gitHead}=await import('../server.mjs');
 for(const env of [{},{RENDER_GIT_COMMIT:'abc'},{RENDER_GIT_COMMIT:'Z'.repeat(40)},{RENDER_GIT_COMMIT:'<script>'}]){
  const head=gitHead(env,null);
  assert.equal(head.sha,null);assert.equal(head.branch,null);
  assert.equal(head.sourceState,'unverified-no-platform-sha');
  assert.equal(head.canonicalCommit,null);assert.equal(head.canonicalVerification,'not-available');
 }
 const pinned=gitHead({RENDER_GIT_COMMIT:'A'.repeat(40),RENDER_GIT_BRANCH:'feature'},'b'.repeat(40));
 assert.equal(pinned.sha,'a'.repeat(40));assert.equal(pinned.branch,null);
 assert.equal(pinned.canonicalCommit,'b'.repeat(40));
});
test('healthz answers plain ok for text/plain monitors and keeps JSON by default',async()=>{
 const app=createGatewayServer({env:{}});
 await new Promise(resolve=>app.server.listen(0,'127.0.0.1',resolve));
 const root='http://127.0.0.1:'+app.server.address().port;
 try{
  const plain=await fetch(root+'/healthz',{headers:{accept:'text/plain'}});
  assert.equal(plain.status,200);
  assert.match(plain.headers.get('content-type'),/^text\/plain/);
  assert.equal(plain.headers.get('cache-control'),'no-store');
  assert.equal(plain.headers.get('x-content-type-options'),'nosniff');
  assert.equal(await plain.text(),'ok');
  for(const accept of [undefined,'application/json','text/plain, application/json','*/*']){
   const r=await fetch(root+'/healthz',{headers:accept?{accept}:{}});
   assert.match(r.headers.get('content-type'),/^application\/json/,String(accept));
   const body=await r.json();
   assert.equal(body.ok,true);assert.equal(body.productionReady,false);assert.equal(body.cutoverEnabled,false);
  }
 }finally{await new Promise(resolve=>app.server.close(resolve));}
});
