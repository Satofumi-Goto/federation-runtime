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
