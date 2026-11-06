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
