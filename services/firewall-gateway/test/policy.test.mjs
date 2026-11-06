import test from 'node:test';
import assert from 'node:assert/strict';
import {ROUTES,SECURITY_POLICY,publicCatalog} from '../policy.mjs';
test('shadow-only default preserves every incumbent',()=>{
 assert.equal(SECURITY_POLICY.defaultCutoverEnabled,false);
 assert.equal(SECURITY_POLICY.legacyRoutesStayEnabled,true);
 assert.equal(SECURITY_POLICY.anonymousProxyAllowed,false);
 assert.equal(SECURITY_POLICY.paidProviderCallsAllowed,false);
 assert.ok(Object.values(ROUTES).every(r=>r.phase==='shadow-hold'));
 assert.ok(publicCatalog().routes.every(r=>r.switched===false&&r.liveVerified===false));
});
test('ten-app registry: nine signed clients plus the gateway, routes only from ROUTES',async()=>{
 const {CLIENT_REGISTRY,CLIENT_IDS,publicClients,SIGNING_CONTRACT}=await import('../policy.mjs');
 const {loadKeys}=await import('../auth.mjs');
 assert.deepEqual([...CLIENT_IDS].sort(),['activity','administration','federation','fleet','remote-monitoring',
  'seneschal','service','simulator','urban']);
 assert.equal(publicClients().appCount,10);
 for(const c of CLIENT_REGISTRY){
  assert.match(c.clientSecretName,/^FIREWALL_[A-Z_]+_HMAC_KEY$/);
  assert.deepEqual(c.routes,Object.values(ROUTES).filter(r=>r.consumers.includes(c.id)).map(r=>r.id));
 }
 assert.ok(publicClients().clients.every(c=>c.keyConfigured===false&&c.gatewayEgressActive===false));
 const key='A'.repeat(43);
 assert.equal(loadKeys({FIREWALL_CLIENT_KEYS_JSON:JSON.stringify({administration:key})}).size,1);
 assert.throws(()=>loadKeys({FIREWALL_CLIENT_KEYS_JSON:JSON.stringify({'service-hub':key})}),/invalid-keys/);
 assert.equal(SIGNING_CONTRACT.version,'federation-firewall-hmac/1');
 assert.equal(SIGNING_CONTRACT.canonicalString.split('\n').length,7);
 assert.doesNotMatch(JSON.stringify(publicClients()),/[A-Za-z0-9_-]{43}/);
});
