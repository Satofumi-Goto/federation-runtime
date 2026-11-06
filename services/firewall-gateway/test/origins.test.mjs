import test from 'node:test';
import assert from 'node:assert/strict';
import {randomBytes} from 'node:crypto';
import {createGatewayServer} from '../server.mjs';
import {signHeaders} from '../auth.mjs';
import {CLIENT_IDS,GATEWAY_APP_ID} from '../policy.mjs';
import {INDEPENDENT_ORIGINS,independentApps} from '../origins.mjs';

test('every registered app has an origin entry; unassigned stays null',()=>{
 assert.deepEqual(Object.keys(INDEPENDENT_ORIGINS).sort(),[...CLIENT_IDS,GATEWAY_APP_ID].sort());
 for(const v of Object.values(INDEPENDENT_ORIGINS))
  assert.ok(v===null||/^https:\/\/[a-z0-9.-]+$/.test(v));
 const d=independentApps();
 assert.equal(d.appCount,10);
 assert.equal(d.productionE2EVerified,0);
 assert.ok(d.apps.every(a=>a.productionE2EVerified===false&&a.connection!=='connected'));
});

test('healthz/status/catalog show 10 origins and honest connection state; egress stays off',async()=>{
 const key=randomBytes(32);
 const app=createGatewayServer({env:{FIREWALL_CLIENT_KEYS_JSON:JSON.stringify({federation:key.toString('base64url')}),
  FIREWALL_CANARY_EGRESS:'false'},auditSink:()=>{},fetchImpl:async()=>{throw Error('upstream must not be called');}});
 await new Promise(r=>app.server.listen(0,'127.0.0.1',r));
 const root='http://127.0.0.1:'+app.server.address().port;
 const state=(d,id)=>d.apps.find(a=>a.id===id).connection;
 try{
  const health=await (await fetch(root+'/healthz')).json();
  assert.equal(health.productionReady,false);
  assert.equal(health.independentApps.apps.length,10);
  assert.equal(state(health.independentApps,'activity'),'origin-unassigned');
  assert.equal(state(health.independentApps,'seneschal'),'not-connected');
  assert.equal(state(health.independentApps,'federation'),'key-configured-no-signed-request');
  assert.equal(state(health.independentApps,GATEWAY_APP_ID),'self');
  const body=JSON.stringify({routeId:'japan-holidays'});
  const probe=await fetch(root+'/api/v1/shadow/probe',{method:'POST',
   headers:{'content-type':'application/json',...signHeaders({client:'federation',key,body})},body});
  assert.equal(probe.status,503);
  assert.equal((await probe.json()).reason,'egress-disabled');
  const status=await (await fetch(root+'/api/status')).json();
  assert.equal(status.canaryEgressEnabled,false);
  assert.equal(state(status.independentApps,'federation'),'signed-request-verified-this-process');
  const catalog=await (await fetch(root+'/api/catalog')).json();
  assert.equal(catalog.policy.defaultEgressEnabled,false);
  assert.equal(catalog.independentApps.productionE2EVerified,0);
  assert.equal(catalog.independentApps.originsAssigned,3);
  assert.doesNotMatch(JSON.stringify([health,status,catalog]),new RegExp(key.toString('base64url')));
 }finally{await new Promise(r=>app.server.close(r));}
});
