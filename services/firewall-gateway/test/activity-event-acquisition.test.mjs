import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {createActivityAcquisition,validateEventQuery,projectKawasakiEvent,projectTokyoEventHit,NEWS_SOURCE_IDS,TOKYO_EVENT_SOURCE_IDS} from '../activitySources.mjs';

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
 assert.match(src,/\['tv','online',\.\.\.NEWS_SOURCE_IDS,'events','anilist',\.\.\.TOKYO_EVENT_SOURCE_IDS\]/);
 assert.match(src,/const eventSource=kawasakiSource\|\|TOKYO_EVENT_SOURCE_IDS\.includes\(command\?\.source\)/);
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

test('Tokyo Koto and Sumida only reach pinned official POST datasets and public-field transport',async()=>{
 const fetched=[];
 const fake=async(url,init)=>{
   fetched.push(url);
   assert.equal(init.method,'POST');
   assert.equal(init.body,'{}');
   assert.equal(init.redirect,'manual');
   assert.equal(init.credentials,'omit');
   assert.equal(new URL(url).hostname,'service.api.metro.tokyo.lg.jp');
   assert.equal(new URL(url).searchParams.get('limit'),'250');
   return ok({hits:[{_source:{'イベント名':'地区の公開行事','開始日':'2026/11/17',
       '緯度':'35.65','経度':'139.80','開催場所':'区民会館',
       'URL':'https://www.city.koto.lg.jp/',contact_person:'not-public'}}]});
 };
 const source=createActivityAcquisition({fetchImpl:fake,clock:()=>NOW});
 const koto=await source.get('tokyo_koto_events');
 const sumida=await source.get('tokyo_sumida_events');
 assert.equal(koto.schema,'gateway.activity-raw/1');
 assert.equal(koto.source,'tokyo_koto_events');
 assert.equal(koto.personalDataCollected,false);
 assert.equal(koto.tokyo.datasetId,'tokyo_koto');
 assert.equal(koto.tokyo.hits[0]._source['イベント名'],'地区の公開行事');
 assert.equal(koto.tokyo.hits[0]._source.contact_person,undefined);
 assert.equal(sumida.tokyo.datasetId,'tokyo_sumida');
 assert.equal(fetched.length,2);
 const cached=await source.get('tokyo_koto_events');
 assert.equal(cached.cached,true);
 assert.equal(fetched.length,2);
});
test('Tokyo source cannot receive arbitrary URLs or expose opaque operator fields',async()=>{
 assert.deepEqual(projectTokyoEventHit({_source:{'名称':'文化行事',phone:'secret'}}),
   {_source:{'名称':'文化行事'}});
 let calls=0;
 const source=createActivityAcquisition({fetchImpl:async()=>{calls++;return ok({hits:[]});},clock:()=>NOW});
 await assert.rejects(()=>source.get('tokyo_custom_events'),/invalid-source/);
 assert.equal(calls,0);
});
test('Tokyo oversized or malformed official result fails closed without partial publication',async()=>{
 const source=createActivityAcquisition({clock:()=>NOW,fetchImpl:async()=>ok({hits:Array(251).fill({_source:{'名称':'X'}})})});
 await assert.rejects(()=>source.get('tokyo_koto_events'),/invalid-tokyo-events/);
});

// Fixed new RSS sources: pinned and signed; no caller supplied URL.
const FIXED = {
  yahoo_domestic:'https://news.yahoo.co.jp/rss/topics/domestic.xml',
  yahoo_entertainment:'https://news.yahoo.co.jp/rss/topics/entertainment.xml',
  yahoo_sports:'https://news.yahoo.co.jp/rss/topics/sports.xml',
  google_japan:'https://news.google.com/rss?hl=ja&gl=JP&ceid=JP:ja',
  google_entertainment:'https://news.google.com/rss/headlines/section/topic/ENTERTAINMENT?hl=ja&gl=JP&ceid=JP:ja',
  google_business:'https://news.google.com/rss/headlines/section/topic/BUSINESS?hl=ja&gl=JP&ceid=JP:ja',
};

test('RSS news sources are fixed, public and have no caller-defined query or key',()=>{
  for(const source of Object.keys(FIXED)) assert(NEWS_SOURCE_IDS.includes(source));
  const denied=['yahoo_private','google_search','shopping_paid','arbitrary_news'];
  for(const source of denied) assert(!NEWS_SOURCE_IDS.includes(source));
});

test('fixed RSS goes through bounded, read-only gateway and preserves bytes',async()=>{
  const calls=[];
  const rss='<?xml version="1.0" encoding="UTF-8"?><rss><channel><item><title>イベント</title><link>https://example.org/event</link></item></channel></rss>';
  const collector=createActivityAcquisition({
    fetchImpl:async(url,opts)=>{
      calls.push({url,opts});
      assert.equal(opts.method,'GET');
      assert.equal(opts.redirect,'manual');
      assert.equal(opts.credentials,'omit');
      assert.match(opts.headers.Accept,/rss\+xml/);
      assert(!('Authorization' in opts.headers));
      return new Response(rss,{headers:{'content-type':'application/rss+xml'}});
    },
    clock:()=>Date.parse('2026-11-08T00:00:00Z')
  });
  for(const source of Object.keys(FIXED)){
    const packet=await collector.get(source);
    assert.equal(packet.schema,'gateway.activity-raw/1');
    assert.equal(packet.source,source);
    assert.equal(packet.personalDataCollected,false);
    assert.equal(Buffer.from(packet.data.body,'base64url').toString('utf8'),rss);
    assert.equal(calls.at(-1).url,FIXED[source]);
  }
  assert.equal(calls.length,Object.keys(FIXED).length);
  await assert.rejects(()=>collector.get('arbitrary_news'),/invalid-source/);
});

test('Tokyo: five wards and Big Sight are fixed POST-only CC BY datasets',async()=>{
 const expected={
   tokyo_koto_events:'t131083d0000000017-252a3033bb76c746c8ee30c24a3a2b5a-0',
   tokyo_sumida_events:'t131075d0000000136-d97c9fdbf7d4a3ad38c0cac25c78beb3-0',
   tokyo_itabashi_events:'t131199d0000000141-800c4c5f071f4be278136b4d19b2bcf8-0',
   tokyo_bunkyo_events:'t131059d0000000001-630186c15946c72991dddc3808cd46dc-0',
   tokyo_chuo_events:'t131024d0000000041-e5e6d00248bbe97738bfb80d0d3d3e00-0',
   tokyo_bigsight_events:'t001001d0000000001-1db9fd22025886d3d5c9607d5c24fdf0-0'
 };
 assert.deepEqual([...TOKYO_EVENT_SOURCE_IDS].sort(),Object.keys(expected).sort());
 const calls=[];
 const src=createActivityAcquisition({clock:()=>NOW,fetchImpl:async(url,opts)=>{
   const u=new URL(url);calls.push(u);
   assert.equal(u.hostname,'service.api.metro.tokyo.lg.jp');
   assert.match(u.pathname,/\/api\/t[0-9a-f-]+\/json$/);
   assert.equal(opts.method,'POST');
   assert.equal(opts.redirect,'manual');
   assert.equal(opts.credentials,'omit');
   assert.equal(opts.body,'{}');
   assert.equal(opts.headers['Content-Type'],'application/json');
   return ok({hits:[{_source:{'イベント名':'東京都の公開講座','開始日':'2026/11/14',
     '場所名称':'東京ホール','緯度':'35.7','経度':'139.7',
     'URL':'https://www.metro.tokyo.lg.jp/evt'}}]});
 }});
 for(const id of TOKYO_EVENT_SOURCE_IDS){
   const packet=await src.get(id);
   assert.equal(packet.source,id);
   assert.equal(packet.tokyo.datasetId,id.slice(0,-7));
   assert.equal(packet.tokyo.hits.length,1);
   assert.equal(packet.personalDataCollected,false);
   const matched=calls.at(-1);
   assert(matched.pathname.includes(expected[id]),'fixed dataset ID '+id);
   assert.equal(matched.searchParams.get('limit'),'250');
 }
 await assert.rejects(()=>src.get('tokyo_yokohama_events'),/invalid-source/);
 assert.equal(calls.length,6);
});


test('Tokyo Big Sight official 2026 nested row events retain only public title/period/link fields',async()=>{
 const dataset='tokyo_bigsight_events';
 const host='https://service.api.metro.tokyo.lg.jp/api/t001001d0000000001-1db9fd22025886d3d5c9607d5c24fdf0-0/json?limit=250';
 let calls=0;
 const source=createActivityAcquisition({clock:()=>NOW,fetchImpl:async(url,opts)=>{
   calls++;assert.equal(url,host);assert.equal(opts.method,'POST');
   return ok({hits:[{row:{
     '展示会名':'東京の展示会2026','会期(開始)':'2026/11/15','会期(終了)':'2026/11/17',
     '利用施設':'南1-4','開催時間':'10:00-17:00','来場対象者':'一般',
     '入場料について':'無料','内容':'展示会',
     URL:'https://www.example.org/tokyo-event',
     TEL:'03-1234-5678',連絡先:'secret@example.org',
   }}]});
 }});
 const packet=await source.get(dataset);
 assert.equal(packet.tokyo.datasetId,'tokyo_bigsight');
 assert.equal(packet.tokyo.hits.length,1);
 const row=packet.tokyo.hits[0]._source;
 assert.equal(row['展示会名'],'東京の展示会2026');
 assert.equal(row['会期(開始)'],'2026/11/15');
 assert.equal(row.URL,'https://www.example.org/tokyo-event');
 assert.equal(row.TEL,undefined);
 assert.equal(row['連絡先'],undefined);
 assert.equal(calls,1);
});
