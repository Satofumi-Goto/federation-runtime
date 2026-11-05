import test from 'node:test';
import assert from 'node:assert/strict';
import {verifyFirewallPhase0,ORIGIN} from '../verify-firewall-phase0-live.mjs';
const HEADERS={
 'Cache-Control':'no-store','X-Content-Type-Options':'nosniff',
 'X-Frame-Options':'DENY','Referrer-Policy':'no-referrer',
 'Strict-Transport-Security':'max-age=86400'
};
const routes=['japan-holidays','jma-earthquake-list','open-meteo-tokyo'];
const exceptions=['google-maps-js','google-places','personal-calendar-auth','fleet-dispatch-control','booking-payment','map-24h-forecast'];
const response=(data,status=200,html=false)=>new Response(html?data:JSON.stringify(data),{
 status,headers:{...HEADERS,'Content-Type':html?'text/html; charset=utf-8':'application/json; charset=utf-8',
  ...(html?{'Content-Security-Policy':"default-src 'none'; frame-ancestors 'none'"}:{})}
});
function mock({egress=false,adminStatus=503}={}){
 const calls=[];
 const fetchImpl=async(url,init)=>{
  assert.ok(url.startsWith(ORIGIN+'/'),'outbound source must be the Gateway only');
  assert.equal(init.redirect,'error');
  assert.equal(init.credentials,'omit');
  const path=new URL(url).pathname;
  calls.push(init.method+' '+path);
  if(path==='/healthz')return response({service:'federation-firewall-gateway',stage:'shadow-hold',productionReady:false,cutoverEnabled:false});
  if(path==='/api/status')return response({configuredClients:false,canaryEgressEnabled:egress,productionReady:false,cutoverEnabled:false,legacyConnectionsPreserved:true});
  if(path==='/api/catalog')return response({policy:{version:'federation-firewall-policy/1',mode:'shadow-hold',defaultCutoverEnabled:false,defaultEgressEnabled:false,paidProviderCallsAllowed:false},
   routes:routes.map(id=>({id,phase:'shadow-hold',switched:false,liveVerified:false})),
   directExceptions:exceptions.map(id=>({id}))});
  if(path==='/')return response('SHADOW NO CUTOVER Egress Canary LOCKED 0 / 3',200,true);
  if(path==='/admin')return response({ok:false,reason:'admin-access-unconfigured'},adminStatus);
  if(path==='/api/v1/shadow/probe'&&init.method==='GET')return response({ok:false,reason:'method-not-allowed'},405);
  if(path==='/api/v1/shadow/probe'&&init.method==='POST'){
   assert.equal(init.headers.Authorization,undefined);
   assert.deepEqual(JSON.parse(init.body),{routeId:'japan-holidays'});
   return response({ok:false,reason:'service-auth-unconfigured'},503);
  }
  throw Error('unapproved target '+path);
 };
 return{fetchImpl,calls};
}
test('Phase 0 verifies real safe interface without sending provider requests',async()=>{
 const {fetchImpl,calls}=mock();
 const r=await verifyFirewallPhase0(fetchImpl);
 assert.equal(r.ok,true);
 assert.equal(r.routes,3);assert.equal(r.directExceptions,6);
 assert.equal(r.upstreamRequests,0);
 assert.equal(calls.length,7);
 assert.deepEqual(calls.filter(x=>x.endsWith('/api/v1/shadow/probe')),[
  'GET /api/v1/shadow/probe','POST /api/v1/shadow/probe']);
});
test('Verifier fails closed if live egress or admin access unexpectedly enabled',async()=>{
 await assert.rejects(()=>verifyFirewallPhase0(mock({egress:true}).fetchImpl),/canaryEgressEnabled/);
 await assert.rejects(()=>verifyFirewallPhase0(mock({adminStatus:200}).fetchImpl),/GET \/admin/);
});
