import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {createActivityAcquisition,validateEventQuery,projectKawasakiEvent} from '../activitySources.mjs';

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
 assert.match(src,/\['tv','online','gdelt','mlit','events','anilist'\]/);
 assert.doesNotMatch(src,/autoCutover=true/);
});

test('Gateway validates fixed bounded dates and page before any egress',()=>{
 const good={from:'2026-11-07',to:'2026-11-21',page:2};
 assert.deepEqual(validateEventQuery(good,NOW),good);
 for(const bad of [
  {...good,page:0},{...good,page:4},{...good,page:'2'},
  {...good,from:'2026-02-30'},{...good,to:'2026-12-31'},
  {...good,from:'2026-10-30'},{...good,from:'2026-11-22'},
  {...good,from:'2026-11-01',to:'2026-12-18'},
  {...good,from:'2026-11-07',to:'2026-11-21',url:'https://evil.invalid/anything'},
 ]) {
  if('url' in bad)continue; // The HTTP handler's exact-key check rejects extras.
  assert.equal(validateEventQuery(bad,NOW),null);
 }
 const server=readFileSync(new URL('../server.mjs',import.meta.url),'utf8');
 assert.match(server,/keys==='from,page,source,to'/);
 assert.match(server,/validateEventQuery\(command,clock\(\)\)/);
 assert.match(server,/limitedBody\(req,128\)/);
});
test('Gateway distinguishes pages and does not reuse page 1 cache for page 2',async()=>{
 const urls=[];
 const source=createActivityAcquisition({clock:()=>NOW,fetchImpl:async url=>{
  const page=Number(new URL(url).searchParams.get('page'));
  urls.push(String(url));
  return ok({total_pages:3,event_data:[{...event,title:'page-'+page}]});
 }});
 const first=await source.get('events',{from:'2026-11-07',to:'2026-11-21',page:1});
 const third=await source.get('events',{from:'2026-11-07',to:'2026-11-21',page:3});
 assert.equal(first.kawasaki.page,1);
 assert.equal(third.kawasaki.page,3);
 assert.equal(third.kawasaki.total_pages,3);
 assert.equal(first.kawasaki.event_data[0].title,'page-1');
 assert.equal(third.kawasaki.event_data[0].title,'page-3');
 assert.equal(urls.length,2);
 const again=await source.get('events',{from:'2026-11-07',to:'2026-11-21',page:3});
 assert.equal(again.cached,true);
 assert.equal(urls.length,2);
 await assert.rejects(()=>source.get('events',{from:'2026-11-07',to:'2026-11-21',page:4}),/invalid-event-query/);
 assert.equal(urls.length,2);
});
test('Gateway refuses reported provider pagination >3 rather than claiming completeness',async()=>{
 const source=createActivityAcquisition({clock:()=>NOW,fetchImpl:async()=>ok({event_data:[event],total_pages:5})});
 await assert.rejects(()=>source.get('events'),/invalid-kawasaki-events/);
});

test('oversized official JSON prose is accepted only for Kawasaki and excluded from Activity packet',async()=>{
 const notes='公開イベントの詳細'.repeat(26000);
 const raw={...event,content:notes,internal_contact:'test@example.org',
   place:'施設A',place_adr:'川崎市',open_url:'https://www.city.kawasaki.jp/',
   date_list:[{date:'2026-11-14',time_from:'10:00',time_to:'11:00'}]};
 const payload=JSON.stringify({total_pages:1,event_data:[raw]});
 assert(Buffer.byteLength(payload,'utf8')>350000);
 assert(Buffer.byteLength(payload,'utf8')<900000);
 let requests=0;
 const source=createActivityAcquisition({clock:()=>NOW,fetchImpl:async(_,init)=>{
   requests++;
   assert.equal(init.method,'GET');
   return ok({total_pages:1,event_data:[raw]});
 }});
 const result=await source.get('events');
 assert.equal(requests,1);
 assert.equal(result.kawasaki.event_data[0].place,'施設A');
 assert.equal(result.kawasaki.event_data[0].content,undefined);
 assert.equal(result.kawasaki.event_data[0].internal_contact,undefined);
 assert.equal(result.kawasaki.event_data[0].open_url,'https://www.city.kawasaki.jp/');
 assert(Buffer.byteLength(JSON.stringify(result),'utf8')<340000);
});
test('bounded public field transport preserves only normalizer inputs and no personal data',()=>{
 const projected=projectKawasakiEvent({...event,
  content:'private prose',email:'private@example.org',
  date_list:[{date:'2026-11-14',time_from:'10:00',time_to:'11:00'}],
  event_location:[{latitude:35.6,longitude:139.6,place:'Hall',venue_address:'Street',contact:'hidden'}]});
 assert.equal(projected.content,undefined);
 assert.equal(projected.email,undefined);
 assert.equal(projected.date_list[0].date,'2026-11-14');
 assert.equal(projected.event_location[0].place,'Hall');
 assert.equal(projected.event_location[0].contact,undefined);
});
test('Kawasaki payload above fixed 900KB is rejected without page fallback or synthetic output',async()=>{
 const tooLarge={...event,content:'文'.repeat(310000)};
 const body=JSON.stringify({total_pages:1,event_data:[tooLarge]});
 assert(Buffer.byteLength(body,'utf8')>900000);
 let calls=0;
 const source=createActivityAcquisition({clock:()=>NOW,fetchImpl:async()=>{
  calls++;
  return new Response(body,{status:200,headers:{'content-type':'application/json'}});
 }});
 await assert.rejects(()=>source.get('events'),/upstream-too-large/);
 assert.equal(calls,1);
});
