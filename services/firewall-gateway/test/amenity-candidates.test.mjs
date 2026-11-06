import test from 'node:test';
import assert from 'node:assert/strict';
import {ROUTES,SECURITY_POLICY,publicCatalog} from '../policy.mjs';
import {AMENITY_CANDIDATES} from '../amenityCandidates.mjs';

test('all Seneschal Map selectable facilities have inert Gateway candidates, not live routes',()=>{
 const c=publicCatalog();
 assert.equal(AMENITY_CANDIDATES.length,26);
 assert.equal(new Set(AMENITY_CANDIDATES.map(x=>x.mapLayerId)).size,26);
 assert.deepEqual(c.amenityCandidates,AMENITY_CANDIDATES);
 for(const x of AMENITY_CANDIDATES){
  assert.equal(x.sourceOwner,'activity');
  assert.equal(x.mode,'catalog-candidate-only');
  assert.equal(x.gatewayRouteId,null);
  assert.equal(x.gatewayConsumerActive,false);
  assert.equal(x.egressEnabled,false);
  assert.equal(x.liveVerified,false);
  assert.equal(x.cutoverApproved,false);
  assert.ok(!Object.hasOwn(ROUTES,x.mapLayerId));
 }
 assert.deepEqual(Object.keys(ROUTES).sort(),['japan-holidays','jma-earthquake-list','open-meteo-tokyo']);
 assert.equal(SECURITY_POLICY.anonymousProxyAllowed,false);
 assert.equal(SECURITY_POLICY.defaultCutoverEnabled,false);
 assert.equal(SECURITY_POLICY.legacyRoutesStayEnabled,true);
 assert.equal(AMENITY_CANDIDATES.filter(x=>x.sourceKind==='municipal-authorized-feed-pending').length,2);
 assert.equal(AMENITY_CANDIDATES.filter(x=>x.sourceKind==='operator-authorized-feed-pending').length,1);
});
