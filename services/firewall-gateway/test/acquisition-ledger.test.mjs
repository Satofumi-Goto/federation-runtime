import test from 'node:test';
import assert from 'node:assert/strict';
import {ACQUISITION_LEDGER,publicAcquisitionLedger,validateLedger} from '../acquisitionLedger.mjs';
import {createGatewayServer} from '../server.mjs';

test('gateway owns the 80-route Seneschal acquisition ledger, one category per route',()=>{
 assert.equal(ACQUISITION_LEDGER.owner,'firewall-gateway');
 assert.equal(ACQUISITION_LEDGER.routes.length,80);
 const s=publicAcquisitionLedger({}).summary;
 assert.deepEqual([s.verified,s.unverified,s.unconnected],[30,18,32]);
 assert.throws(()=>validateLedger({...ACQUISITION_LEDGER,routes:[...ACQUISITION_LEDGER.routes,ACQUISITION_LEDGER.routes[0]]}),/duplicate/);
});

test('key state is presence only; service-scoped map key is unknown to the gateway',()=>{
 const secret='never-echo-'+'x'.repeat(24);
 const out=publicAcquisitionLedger({HOTPEPPER_API_KEY:secret,VITE_GOOGLE_MAPS_API_KEY:secret});
 assert.ok(!JSON.stringify(out).includes(secret));
 const keys=Object.fromEntries(out.routes.flatMap(r=>r.keys).map(k=>[k.name,k]));
 assert.equal(keys.HOTPEPPER_API_KEY.configured,true);
 assert.equal(keys.RAKUTEN_ACCESS_KEY.configured,false);
 assert.deepEqual(keys.VITE_GOOGLE_MAPS_API_KEY,{name:'VITE_GOOGLE_MAPS_API_KEY',scope:'service',service:'seneschal',configured:null});
 assert.equal(keys.GEOAPIFY_API_KEY.scope,'service');
 assert.equal(keys.GOOGLE_ENVIRONMENT_API_KEY.configured,null);
 assert.equal(keys.KEYVOX_API_KEY.scope,'service');
 assert.equal(keys.KEYVOX_API_SECRET.configured,null);
 assert.equal(keys.KEYVOX_PUBLIC_LOCKERS_JSON.configured,null);
 assert.equal(out.egressChanged,false);
});

test('GET /api/acquisition-routes allows registered app origins only',async()=>{
 const app=createGatewayServer({env:{}});
 await new Promise(r=>app.server.listen(0,'127.0.0.1',r));
 const root='http://127.0.0.1:'+app.server.address().port+'/api/acquisition-routes';
 try{
  const ok=await fetch(root,{headers:{origin:'https://activity-standalone-staging.onrender.com'}});
  assert.equal(ok.status,200);
  assert.equal(ok.headers.get('access-control-allow-origin'),'https://activity-standalone-staging.onrender.com');
  assert.equal((await ok.json()).routes.length,80);
  const other=await fetch(root,{headers:{origin:'https://evil.example'}});
  assert.equal(other.headers.get('access-control-allow-origin'),null);
 }finally{await new Promise(r=>app.server.close(r));}
});
