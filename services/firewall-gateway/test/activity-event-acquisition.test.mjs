import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {createActivityAcquisition} from '../activitySources.mjs';

const NOW=Date.parse('2026-11-07T03:00:00Z');
const event={title:'地域イベント',date_list:[{date:'2026-11-14',time_from:'10:00',time_to:'11:00'}],
  place_lat:35.6,place_lon:139.6};
const ok=(body)=>new Response(JSON.stringify(body),{status:200,headers:{'content-type':'application/json'}});
test('Gateway fetches a single bounded official Kawasaki page, not caller-controlled URLs',async()=>{
 const urls=[],fake=async(url,options)=>{
   urls.push(url);
   assert.equal(options.method,'GET');
   assert.equal(options.redirect,'manual');
   assert.equal(options.credentials,'omit');
   assert.equal(new URL(url).hostname,'eventapp.city.kawasaki.jp');
   return ok({event_data:[event],total_pages:2});
 };
 const source=createActivityAcquisition({fetchImpl:fake,clock:()=>NOW});
 const first=await source.get('events');
 assert.equal(first.schema,'gateway.activity-raw/1');
 assert.equal(first.source,'events');
 assert.equal(first.personalDataCollected,false);
 assert.equal(first.kawasaki.event_data[0].title,'地域イベント');
 assert.equal(first.providers[0].count,1);
 assert.equal(first.kawasaki.from,'2026-11-07');
 assert.equal(first.kawasaki.to,'2026-11-21');
 assert.equal(urls.length,1);
 assert.equal(new URL(urls[0]).searchParams.get('page'),'1');
 assert.equal(new URL(urls[0]).searchParams.get('from'),'2026-11-07');
 const second=await source.get('events');
 assert.equal(second.cached,true);
 assert.equal(urls.length,1);
});
test('Gateway fails closed on missing event_data; no synthetic recommendation',async()=>{
 const source=createActivityAcquisition({fetchImpl:async()=>ok({events:[event]}),clock:()=>NOW});
 await assert.rejects(()=>source.get('events'),/invalid-kawasaki-events/);
});
test('Gateway refuses >100 raw events to avoid unbounded processing',async()=>{
 const source=createActivityAcquisition({fetchImpl:async()=>ok({event_data:Array.from({length:101},()=>event)}),clock:()=>NOW});
 await assert.rejects(()=>source.get('events'),/invalid-kawasaki-events/);
});
test('Gateway event route is independently disabled by default and does not enable legacy cutover',()=>{
 const src=readFileSync(new URL('../server.mjs',import.meta.url),'utf8');
 assert.match(src,/FIREWALL_ACTIVITY_EVENTS_ENABLED==='true'/);
 assert.match(src,/event-egress-disabled/);
 assert.match(src,/\\['tv','online','gdelt','mlit','events'\\]/);
 assert.doesNotMatch(src,/autoCutover=true/);
});
