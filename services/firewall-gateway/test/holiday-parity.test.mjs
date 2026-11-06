import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {compareHolidays,holidayRouteDecision,REQUIRED_EVIDENCE,HOLIDAY_SOURCE} from '../holidayParity.mjs';

const migration=JSON.parse(readFileSync(new URL('../../../config/firewall-gateway-migration.json',import.meta.url),'utf8'));
const now=Date.parse('2026-11-06T00:00:00.000Z');
const legacy={'2026-11-23':'勤労感謝の日','2026-11-03':'文化の日'};
const packet=data=>({ok:true,mode:'shadow-only',routeId:'japan-holidays',provider:'holidays-jp',
 sourceUrl:HOLIDAY_SOURCE,fetchedAt:new Date(now-1000).toISOString(),cached:false,data});

test('parity: equal data in any key order matches; never cuts over',()=>{
 const r=compareHolidays({gatewayPacket:packet({'2026-11-03':'文化の日','2026-11-23':'勤労感謝の日'}),legacyData:legacy,now});
 assert.equal(r.matched,true);
 assert.deepEqual(r.records,{gateway:2,legacy:2});
 assert.equal(r.cutover,false);
 assert.equal(r.legacyRetained,true);
 assert.equal(r.rollbackTarget,'legacy-direct');
});

test('parity: missing, extra and renamed holidays are counted as mismatch',()=>{
 const r=compareHolidays({gatewayPacket:packet({'2026-11-03':'別名','2026-12-31':'x'}),legacyData:legacy,now});
 assert.equal(r.matched,false);
 assert.deepEqual(r.diff,{missing:1,extra:1,renamed:1});
 assert.equal(r.reason,'parity-mismatch-no-cutover');
});

test('parity: untrusted or stale packets and invalid legacy data never match',()=>{
 for(const bad of [{...packet(legacy),sourceUrl:'https://evil.example/'},{...packet(legacy),fetchedAt:'2020-01-01T00:00:00.000Z'},
   {...packet(legacy),mode:'live'},{...packet(legacy),ok:false},null])
  assert.equal(compareHolidays({gatewayPacket:bad,legacyData:legacy,now}).matched,false);
 assert.equal(compareHolidays({gatewayPacket:packet(legacy),legacyData:[],now}).reason,'legacy-data-invalid');
 assert.equal(compareHolidays({gatewayPacket:packet({'bad':'x'}),legacyData:legacy,now}).reason,'gateway-data-invalid');
});

test('decision: current config is HOLD with evidence missing; no cutover is ever returned without all evidence',()=>{
 const d=holidayRouteDecision(migration,{});
 assert.equal(d.action,'hold');
 assert.deepEqual(d.missing,[...REQUIRED_EVIDENCE]);
 const partial=Object.fromEntries(REQUIRED_EVIDENCE.slice(1).map(k=>[k,true]));
 assert.equal(holidayRouteDecision(migration,partial).action,'hold');
});

test('decision: gateway enabled without evidence or legacy disabled -> rollback to legacy direct',()=>{
 const flipped=structuredClone(migration);
 flipped.candidateRoutes.find(r=>r.id==='japan-holidays').gateway=true;
 const d=holidayRouteDecision(flipped,{dataParity:true});
 assert.equal(d.action,'rollback');
 assert.deepEqual(d.set,{legacy:true,gateway:false,state:'HOLD'});
 const noLegacy=structuredClone(migration);
 noLegacy.candidateRoutes.find(r=>r.id==='japan-holidays').legacy=false;
 assert.equal(holidayRouteDecision(noLegacy,{}).action,'rollback');
});

test('decision: with all evidence it only proposes a separate PR for this one route',()=>{
 const all=Object.fromEntries(REQUIRED_EVIDENCE.map(k=>[k,true]));
 const d=holidayRouteDecision(migration,all);
 assert.equal(d.action,'propose-cutover-pr');
 assert.equal(d.routeOnly,'japan-holidays');
 assert.equal(d.legacyRetained,true);
 // config itself stays HOLD
 assert.ok(migration.candidateRoutes.every(r=>r.state==='HOLD'&&r.gateway===false&&r.legacy===true));
});
