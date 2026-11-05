// Live read-only / refusal verification of the isolated Phase-0 Firewall.
// No upstream provider calls, credentials, billing changes or cutover.
import assert from 'node:assert/strict';
import {resolve} from 'node:path';
import {fileURLToPath} from 'node:url';

export const ORIGIN='https://federation-firewall-gateway.onrender.com';
const ROUTES=['japan-holidays','jma-earthquake-list','open-meteo-tokyo'];
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
  for(const key of ['configuredClients','canaryEgressEnabled','productionReady','cutoverEnabled'])
    assert.equal(state[key],false,'must remain disabled '+key);
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
  const unsigned=(await check('/api/v1/shadow/probe','POST',503)).data;
  assert.equal(unsigned.reason,'service-auth-unconfigured');
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
