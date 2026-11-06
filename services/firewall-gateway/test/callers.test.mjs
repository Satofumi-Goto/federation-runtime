import test from 'node:test';
import assert from 'node:assert/strict';
import {randomBytes} from 'node:crypto';
import {createGatewayServer} from '../server.mjs';
import {CLIENT_IDS} from '../policy.mjs';
import {callerUpstream,callerPlan,createActivityShadowCompare,INDEPENDENT_API_ORIGIN,CALLER_FLOWS} from '../callers.mjs';

test('caller upstream defaults to base44; only exact values select independent',()=>{
 assert.equal(callerUpstream('activity-shadow-compare',{}),'base44');
 assert.equal(callerUpstream('activity-shadow-compare',{FIREWALL_CALLER_UPSTREAM:'Independent'}),'base44');
 assert.equal(callerUpstream('activity-shadow-compare',{FIREWALL_CALLER_UPSTREAM:'independent'}),'independent');
 assert.equal(callerUpstream('fleet-assistant',{FIREWALL_CALLER_UPSTREAM:'independent',FIREWALL_CALLER_UPSTREAM_FLEET_ASSISTANT:'base44'}),'base44');
 assert.equal(callerUpstream('remote-monitoring-assistant',{FIREWALL_CALLER_UPSTREAM_REMOTE_MONITORING_ASSISTANT:'independent'}),'independent');
});

test('caller plan lists shadow compare plus one assistant entry per client, never claims round trip',()=>{
 assert.equal(CALLER_FLOWS.length,1+CLIENT_IDS.length);
 const plan=callerPlan({});
 assert.equal(plan.defaultUpstream,'base44');
 assert.equal(plan.independentSelected,0);
 assert.equal(plan.roundTripVerified,0);
 assert.ok(plan.flows.every(f=>f.upstream==='base44'&&f.callerHost.startsWith('base44:')&&!f.roundTripVerified&&!f.cutover&&f.legacyRetained));
 const on=callerPlan({FIREWALL_CALLER_UPSTREAM:'independent'});
 assert.equal(on.independentSelected,CALLER_FLOWS.length);
 assert.ok(on.flows.every(f=>f.callerHost.startsWith(INDEPENDENT_API_ORIGIN+'/api/')&&f.roundTripVerified===false));
 assert.equal(on.flows.find(f=>f.id==='activity-shadow-compare').callerHost,
  INDEPENDENT_API_ORIGIN+'/api/activity/functions/activityFirewallShadowCompare');
});

test('shadow compare refuses without owner, flag, key or valid route and never calls out',async()=>{
 const calls=[];const fetchImpl=async u=>{calls.push(u);throw Error('no network');};
 const key=randomBytes(32).toString('base64url');
 const mk=env=>createActivityShadowCompare({env,fetchImpl});
 assert.equal((await mk({}).run({routeId:'japan-holidays'})).body.reason,'owner-required');
 assert.equal((await mk({}).run({ownerAuthenticated:true,routeId:'jma-earthquake-list'})).body.reason,'unsupported-route');
 assert.equal((await mk({}).run({ownerAuthenticated:true,routeId:'japan-holidays'})).body.reason,'shadow-not-enabled');
 assert.equal((await mk({FIREWALL_ACTIVITY_SHADOW_ENABLED:'true'}).run({ownerAuthenticated:true,routeId:'japan-holidays'})).body.reason,'hmac-not-configured');
 assert.equal((await mk({FIREWALL_ACTIVITY_SHADOW_ENABLED:'true',FIREWALL_ACTIVITY_HMAC_KEY:key,FIREWALL_GATEWAY_ORIGIN:'http://evil.example'})
  .run({ownerAuthenticated:true,routeId:'japan-holidays'})).body.reason,'gateway-origin-invalid');
 assert.equal(calls.length,0);
});

test('shadow compare signs a real gateway request and compares with the legacy provider',async()=>{
 const key=randomBytes(32).toString('base64url');
 const holidays={'2026-01-01':'元日','2026-11-03':'文化の日'};
 const gw=createGatewayServer({env:{FIREWALL_CLIENT_KEYS_JSON:JSON.stringify({activity:key}),
  FIREWALL_CANARY_EGRESS:'false'},auditSink:()=>{},fetchImpl:async()=>{throw Error('gateway upstream must stay off');}});
 await new Promise(r=>gw.server.listen(0,'127.0.0.1',r));
 const origin='http://127.0.0.1:'+gw.server.address().port;
 const legacyCalls=[];
 const fetchImpl=async(url,init)=>{
  if(url.startsWith(origin))return fetch(url,init);
  legacyCalls.push(url);
  return new Response(JSON.stringify(holidays),{headers:{'Content-Type':'application/json'}});
 };
 try{
  const env={FIREWALL_ACTIVITY_SHADOW_ENABLED:'true',FIREWALL_ACTIVITY_HMAC_KEY:key,FIREWALL_GATEWAY_ORIGIN:origin};
  const compare=createActivityShadowCompare({env,fetchImpl});
  const r=await compare.run({ownerAuthenticated:true,routeId:'japan-holidays'});
  // Gateway egress is OFF, so the signed request is accepted but egress is refused (503).
  assert.equal(r.status,502);
  assert.equal(r.body.reason,'gateway-not-ready');
  assert.equal(r.body.gatewayStatus,503);
  assert.equal(legacyCalls.length,0);
  assert.equal((await compare.run({ownerAuthenticated:true,routeId:'japan-holidays'})).status,429);
 }finally{await new Promise(r=>gw.server.close(r));}
});

test('shadow compare reports parity with a trusted packet',async()=>{
 const key=randomBytes(32).toString('base64url');
 const holidays={'2026-01-01':'元日'};
 const now=Date.parse('2026-11-06T06:00:00.000Z');
 const fetchImpl=async url=>url.includes('/api/v1/shadow/probe')
  ?new Response(JSON.stringify({ok:true,mode:'shadow-only',routeId:'japan-holidays',provider:'holidays-jp',
   sourceUrl:'https://holidays-jp.github.io/api/v1/date.json',fetchedAt:new Date(now).toISOString(),cached:false,data:holidays}),
   {headers:{'Content-Type':'application/json'}})
  :new Response(JSON.stringify(holidays),{headers:{'Content-Type':'application/json'}});
 const r=await createActivityShadowCompare({env:{FIREWALL_ACTIVITY_SHADOW_ENABLED:'true',FIREWALL_ACTIVITY_HMAC_KEY:key},
  fetchImpl,clock:()=>now}).run({ownerAuthenticated:true,routeId:'japan-holidays'});
 assert.equal(r.status,200);
 assert.equal(r.body.matched,true);
 assert.equal(r.body.cutover,false);
 assert.equal(r.body.legacyRetained,true);
});
