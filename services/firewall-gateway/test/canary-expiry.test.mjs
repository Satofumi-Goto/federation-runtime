import test from 'node:test';
import assert from 'node:assert/strict';
import {createEgress} from '../egress.mjs';

const BASE=Date.parse('2026-11-06T01:00:00.000Z');
const activeSettings=expire=>({
 FIREWALL_CANARY_EGRESS:'true',
 FIREWALL_CANARY_ROUTE_IDS:'japan-holidays',
 FIREWALL_CANARY_EXPIRES_AT:expire
});
const validResponse=()=>Response.json({'2026-11-23':'勤労感謝の日'});

test('a global ON without a bounded expiration fails closed',async()=>{
 for(const env of [
  activeSettings(''),activeSettings('2026-11-06'),activeSettings('not-a-time'),
  activeSettings(new Date(BASE-1).toISOString()),
  activeSettings(new Date(BASE+600001).toISOString()),
  {...activeSettings(new Date(BASE+40000).toISOString()),FIREWALL_CANARY_ROUTE_IDS:'jma-earthquake-list'},
  {...activeSettings(new Date(BASE+40000).toISOString()),FIREWALL_CANARY_EGRESS:'TRUE'}
 ]){
  let count=0;
  const gate=createEgress({env,clock:()=>BASE,fetchImpl:async()=>{count++;return validResponse();}});
  assert.equal(gate.liveEnabled,false);
  assert.equal((await gate.probe('activity','japan-holidays')).status,503);
  assert.equal(count,0);
 }
});
test('holiday probe is allowed only until expiration, including cached reads',async()=>{
 let now=BASE,count=0;
 const gate=createEgress({
  env:activeSettings(new Date(BASE+45000).toISOString()),
  clock:()=>now,
  fetchImpl:async()=>{count++;return validResponse();}
 });
 assert.equal(gate.liveEnabled,true);
 assert.equal((await gate.probe('activity','japan-holidays')).status,200);
 assert.equal(count,1);
 now+=25000;
 assert.equal((await gate.probe('activity','japan-holidays')).status,200);
 assert.equal(count,1,'cache should be within short window');
 now=BASE+45000;
 assert.equal(gate.liveEnabled,false);
 assert.equal((await gate.probe('activity','japan-holidays')).status,503);
 assert.equal(count,1,'expired gate must not return cached data or fetch provider');
});
test('even an in-flight provider response cannot be delivered after expiry',async()=>{
 let now=BASE,unblock;
 const responsePromise=new Promise(resolve=>unblock=resolve);
 const gate=createEgress({
  env:activeSettings(new Date(BASE+10000).toISOString()),clock:()=>now,
  fetchImpl:async()=>{await responsePromise;return validResponse();}
 });
 const pending=gate.probe('activity','japan-holidays');
 now=BASE+10000;
 unblock();
 const result=await pending;
 assert.equal(result.status,503);
 assert.equal(result.result.reason,'egress-expired');
 assert.equal(gate.liveEnabled,false);
});
