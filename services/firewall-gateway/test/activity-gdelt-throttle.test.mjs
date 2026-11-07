import test from 'node:test';
import assert from 'node:assert/strict';
import {randomBytes} from 'node:crypto';
import {createActivityAcquisition} from '../activitySources.mjs';
import {createGatewayServer} from '../server.mjs';
import {signHeaders} from '../auth.mjs';

const HOUR=3_600_000,NOW=Date.parse('2026-11-07T03:00:00Z');
const NOTICE='Please limit requests to one every 5 seconds or contact the data provider.';
const throttled=()=>new Response(NOTICE,{status:200,headers:{'content-type':'text/plain'}});
const valid=()=>Response.json({articles:[]});
test('GDELT plain text HTTP 200 throttle is never promoted to news and imposes 1h then 2h cooldown',async()=>{
 let now=NOW,calls=0;
 const get=createActivityAcquisition({clock:()=>now,fetchImpl:async(url,options)=>{
   assert.equal(new URL(url).hostname,'api.gdeltproject.org');
   assert.equal(options.method,'GET');assert.equal(options.credentials,'omit');
   calls++;return calls<3?throttled():valid();
 }}).get;
 await assert.rejects(get('gdelt'),/gdelt-throttled/);assert.equal(calls,1);
 now+=HOUR-1000;
 await assert.rejects(get('gdelt'),/upstream-cooldown/);assert.equal(calls,1);
 now+=1000;
 await assert.rejects(get('gdelt'),/gdelt-throttled/);assert.equal(calls,2);
 now+=2*HOUR-1000;
 await assert.rejects(get('gdelt'),/upstream-cooldown/);assert.equal(calls,2);
 now+=1000;
 const response=await get('gdelt');
 assert.equal(response.schema,'gateway.activity-raw/1');
 assert.equal(JSON.parse(Buffer.from(response.data.body,'base64url').toString('utf8')).articles.length,0);
 assert.equal(calls,3);
 const cached=await get('gdelt');
 assert.equal(cached.cached,true);assert.equal(calls,3);
});
test('signed Activity gets only safe throttle and cooldown reason; never repeats provider request',async()=>{
 const KEY=randomBytes(32),clock=()=>NOW;
 let calls=0;
 const gateway=createGatewayServer({
   env:{FIREWALL_ACTIVITY_NEWS_KEY:KEY.toString('base64url'),
       FIREWALL_ACTIVITY_SOURCES_ENABLED:'true'},
   clock,fetchImpl:async(url,init)=>{
     assert.match(url,/^https:\/\/api\.gdeltproject\.org\/api\/v2\/doc\/doc/);
     assert.equal(init.method,'GET');calls++;return throttled();
   },auditSink:()=>{}
 });
 await new Promise(resolve=>gateway.server.listen(0,'127.0.0.1',resolve));
 const origin='http://127.0.0.1:'+gateway.server.address().port;
 const path='/api/v1/activity/acquire',body='{"source":"gdelt"}';
 const query=async()=>{
   const headers={'content-type':'application/json',...signHeaders({
     client:'activity',key:KEY,body,path,time:NOW,
   })};
   const r=await fetch(origin+path,{method:'POST',headers,body});
   return {status:r.status,data:await r.json()};
 };
 try{
   const first=await query(),second=await query();
   assert.equal(first.status,503);
   assert.equal(first.data.reason,'activity-provider-rate-limited');
   assert.equal(second.status,503);
   assert.equal(second.data.reason,'activity-provider-cooldown');
   assert.equal(calls,1);
 }finally{await new Promise(resolve=>gateway.server.close(resolve));}
});
