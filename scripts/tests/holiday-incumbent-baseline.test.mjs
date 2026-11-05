import test from 'node:test';
import assert from 'node:assert/strict';
import {compareHolidayIncumbent,normalizeHolidayForActivity} from '../verify-activity-holiday-incumbent.mjs';

const day=Date.parse('2026-11-05T02:00:00Z');
const provider={'2026-11-03':'文化の日','2026-11-23':'勤労感謝の日','2027-01-01':'元日','2027-01-11':'成人の日'};
const json=(data,status=200)=>Response.json(data,{status});
const activity=(data,status='ok')=>({version:'external-signals.v1',sources:{
 holidays:{status,data,fetchedAt:'2026-11-05T02:00:00.000Z'}
}});
function mock(response,{providerStatus=200,activityStatus=200}={}){
 const calls=[];
 const fetchImpl=async(url,init)=>{
  calls.push({url,method:init.method,credentials:init.credentials,redirect:init.redirect,body:init.body});
  if(url.includes('holidays-jp.github.io'))return json(provider,providerStatus);
  if(url.includes('life-ledger-link.base44.app'))return json(response,activityStatus);
  throw Error('unexpected-host');
 };
 return {calls,fetchImpl};
}

test('the Activity normalization matches a fixed provider date set',()=>{
 assert.deepEqual(normalizeHolidayForActivity(provider,day),{
  today:'2026-11-05',isHoliday:false,todayName:null,
  upcoming:[{date:'2026-11-23',name:'勤労感謝の日'},{date:'2027-01-01',name:'元日'},
    {date:'2027-01-11',name:'成人の日'}]});
});

test('single bounded Activity holidays-only request; parity never cuts over',async()=>{
 const correct=normalizeHolidayForActivity(provider,day);
 const {calls,fetchImpl}=mock(activity(correct));
 const result=await compareHolidayIncumbent({fetchImpl,now:()=>day});
 assert.equal(result.ok,true);
 assert.equal(result.comparison,'normalized-holiday-parity');
 assert.equal(result.gatewaySignedE2e,false);
 assert.equal(result.cutover,false);
 assert.equal(result.legacyRetained,true);
 assert.equal(calls.length,2);
 assert.deepEqual(calls.map(x=>x.method).sort(),['GET','POST']);
 for(const x of calls){assert.equal(x.credentials,'omit');assert.equal(x.redirect,'error');}
 assert.deepEqual(JSON.parse(calls.find(x=>x.method==='POST').body),{only:['holidays']});
});

test('mismatch, provider failure and Activity errors remain HOLD',async()=>{
 const altered=normalizeHolidayForActivity(provider,day);
 altered.upcoming[0].name='incorrect';
 for(const options of [
  {payload:activity(altered)},
  {payload:activity({},'error')},
  {payload:activity(normalizeHolidayForActivity(provider,day)),providerStatus:503},
  {payload:activity(normalizeHolidayForActivity(provider,day)),activityStatus:429}
 ]){
  const {fetchImpl}=mock(options.payload,options);
  const r=await compareHolidayIncumbent({fetchImpl,now:()=>day});
  assert.equal(r.ok,false);assert.equal(r.cutover,false);
  assert.equal(r.legacyRetained,true);
  assert.equal(r.gatewaySignedE2e,false);
 }
});
