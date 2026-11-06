// Live read-only / refusal verification of the isolated Phase-0 Firewall.
// No upstream provider calls, credentials, billing changes or cutover.
import assert from 'node:assert/strict';
import {resolve} from 'node:path';
import {fileURLToPath} from 'node:url';

export const ORIGIN='https://federation-firewall-gateway.onrender.com';
const ROUTES=['japan-holidays','jma-earthquake-list','open-meteo-tokyo'];
const CLIENTS=['activity','seneschal','fleet','urban','service','federation','simulator',
 'remote-monitoring','administration'];
const EXCEPTIONS=['google-maps-js','google-places','personal-calendar-auth',
 'fleet-dispatch-control','booking-payment','map-24h-forecast'];
async function request(fetchImpl,path,method='GET'){
  const response=await fetchImpl(ORIGIN+path,{
    method,redirect:'error',credentials:'omit',signal:AbortSignal.timeout(25000),
    headers:method==='POST'?{'Content-Type':'application/json',Accept:'application/json'}:{Accept:'application/json'},
    ...(method==='POST'?{body:JSON.stringify({routeId:'japan-holidays'})}:{})
  });
  const raw=await response.text();
  assert.ok(raw.length<200000,'unexpectedly large response');
  const ct=response.headers.get('content-type')||'';
  const json=/application\/json/i.test(ct);
  return{response,data:json?JSON.parse(raw):null,raw};
}
function securityHeaders(response,{html=false}={}){
  assert.equal(response.headers.get('cache-control'),'no-store');
  assert.equal(response.headers.get('x-content-type-options'),'nosniff');
  assert.equal(response.headers.get('x-frame-options'),'DENY');
  assert.equal(response.headers.get('referrer-policy'),'no-referrer');
  assert.match(response.headers.get('strict-transport-security')||'',/max-age=/);
  assert.equal(response.headers.get('access-control-allow-origin'),null,
    'Never expose this API via wildcard CORS');
  if(html){
    assert.match(response.headers.get('content-security-policy')||'',/default-src 'none'/);
    assert.match(response.headers.get('content-security-policy')||'',/frame-ancestors 'none'/);
  }
}
export async function verifyFirewallPhase0(fetchImpl=fetch){
  const status={origin:ORIGIN,checkedAt:new Date().toISOString(),checks:[]};
  const check=async(path,method='GET',expectedStatus=200,html=false)=>{
    const {response,data,raw}=await request(fetchImpl,path,method);
    assert.equal(response.status,expectedStatus,method+' '+path);
    securityHeaders(response,{html});
    status.checks.push({method,path,http:response.status});
    return {data,raw};
  };
  const health=(await check('/healthz')).data;
  assert.equal(health.service,'federation-firewall-gateway');
  assert.equal(health.stage,'shadow-hold');
  assert.equal(health.productionReady,false);
  assert.equal(health.cutoverEnabled,false);
  const state=(await check('/api/status')).data;
  for(const key of ['canaryEgressEnabled','productionReady','cutoverEnabled'])
    assert.equal(state[key],false,'must remain disabled '+key);
  assert.equal(typeof state.configuredClients,'boolean');
  assert.equal(state.legacyConnectionsPreserved,true);
  const catalog=(await check('/api/catalog')).data;
  assert.equal(catalog.policy.version,'federation-firewall-policy/1');
  assert.equal(catalog.policy.mode,'shadow-hold');
  assert.equal(catalog.policy.defaultCutoverEnabled,false);
  assert.equal(catalog.policy.defaultEgressEnabled,false);
  assert.equal(catalog.policy.paidProviderCallsAllowed,false);
  assert.deepEqual(catalog.routes.map(r=>r.id),ROUTES);
  assert.ok(catalog.routes.every(r=>r.phase==='shadow-hold'&&!r.switched&&!r.liveVerified));
  assert.deepEqual(catalog.directExceptions.map(r=>r.id),EXCEPTIONS);
  const page=await check('/', 'GET',200,true);
  for(const phrase of ['SHADOW','NO CUTOVER','Egress Canary','LOCKED','0 / 3'])
    assert.ok(page.raw.includes(phrase),'missing public UI state '+phrase);
  const admin=(await check('/admin','GET',503)).data;
  assert.equal(admin.reason,'admin-access-unconfigured');
  const wrongMethod=(await check('/api/v1/shadow/probe','GET',405)).data;
  assert.equal(wrongMethod.reason,'method-not-allowed');
  const unsignedStatus=state.configuredClients?401:503;
  const unsigned=(await check('/api/v1/shadow/probe','POST',unsignedStatus)).data;
  assert.equal(unsigned.reason,state.configuredClients?'signature-required':'service-auth-unconfigured');
  // Ten-app client registry (served after the manual Render deploy of the registry release).
  const registry=await request(fetchImpl,'/api/clients');
  if(registry.response.status===200){
    securityHeaders(registry.response);
    status.checks.push({method:'GET',path:'/api/clients',http:200});
    const r=registry.data;
    assert.equal(r.appCount,10);
    assert.deepEqual(r.clients.map(c=>c.id),CLIENTS);
    assert.ok(r.clients.every(c=>typeof c.keyConfigured==='boolean'&&c.gatewayEgressActive===false));
    assert.equal(r.signing.version,'federation-firewall-hmac/1');
    assert.doesNotMatch(registry.raw,/"[A-Za-z0-9_-]{43}"/,'key material must never be published');
    assert.deepEqual(state.configuredClientIds,r.clients.filter(c=>c.keyConfigured).map(c=>c.id).sort());
    status.clientRegistry='deployed';
    status.configuredClientIds=state.configuredClientIds;
  }else{
    assert.equal(registry.response.status,404,'unexpected /api/clients status');
    status.clientRegistry='pending-manual-render-deploy';
  }
  // Independent-origin status endpoints (served after the manual Render deploy of that release).
  const head=await request(fetchImpl,'/git-head.json');
  if(head.response.status===200){
    securityHeaders(head.response);
    for(const path of ['/_status/parent','/_status/readiness'])status.checks.push({method:'GET',path,http:200});
    status.checks.push({method:'GET',path:'/git-head.json',http:200});
    assert.ok(head.data.sha===null||/^[a-f0-9]{40}$/.test(head.data.sha),'invalid served sha');
    assert.equal(head.data.repository,'Satofumi-Goto/federation-runtime');
    const parent=(await request(fetchImpl,'/_status/parent'));
    assert.equal(parent.response.status,200);securityHeaders(parent.response);
    assert.equal(parent.data.schema,'federation.runtime-child/1');
    assert.equal(parent.data.parentOrigin,'https://federation-runtime.com');
    assert.equal(parent.data.origin,ORIGIN);
    const ready=(await request(fetchImpl,'/_status/readiness'));
    assert.equal(ready.response.status,200);securityHeaders(ready.response);
    for(const key of ['productionReady','storageIndependent','authenticatedE2E','dnsVerified','cutoverEnabled'])
      assert.equal(ready.data[key],false,'must not claim '+key);
    assert.equal(ready.data.verifiedCutovers,0);
    status.independentStatus='deployed';
    status.servedSha=head.data.sha;
  }else{
    assert.equal(head.response.status,404,'unexpected /git-head.json status');
    status.independentStatus='pending-manual-render-deploy';
  }
  status.ok=true;
  status.routes=ROUTES.length;
  status.directExceptions=EXCEPTIONS.length;
  status.upstreamRequests=0;
  return status;
}
if(process.argv[1]&&resolve(process.argv[1])===fileURLToPath(import.meta.url)){
  verifyFirewallPhase0()
    .then(result=>console.log(JSON.stringify(result)))
    .catch(e=>{console.error('Firewall live verification failed:',e.message);process.exitCode=1;});
}
