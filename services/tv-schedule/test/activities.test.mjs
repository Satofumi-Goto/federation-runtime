import test from 'node:test';
import assert from 'node:assert/strict';
import {normalizeSwissEvents,normalizeFellowshipEvents,normalizeRedLookEvents,createOnlineActivitiesCollector} from '../activities.mjs';
import {createTvScheduleService} from '../server.mjs';
const now=Date.parse('2026-11-06T01:00:00Z');
const swiss={events:[{
  id:'webinar-1',title:'AI Agents live webinar',online:true,allDay:false,
  start:'2026-11-10T18:30:00+01:00',end:'2026-11-10T20:00:00+01:00',
  url:'https://swissdataevents.ch/events/ai-agents-live/',organiser:'Open Data',cost:'Free'
},{id:'all-day',title:'Conference',online:false,allDay:true,
  start:'2026-11-10',end:'2026-11-11',url:'https://swissdataevents.ch/events/conference/'}]};
const fellowship={events:[{id:'fellow-1',title:'Global AI livestream',format:'virtual',
  startTime:'2026-11-09T22:00:00.000Z',url:'https://theaifellowship.ca/events/fellow-1',
  description:'Public livestream'},{id:'local',title:'In-person',format:'in-person',
  startTime:'2026-11-10T00:00:00Z',url:'https://theaifellowship.ca/events/local'}]};
const redlook='<h2>次はいつ会える？ 直近の日程</h2><div>オンライン 11/11（水）20:30〜（日本時間）</div>';
const ok=(v,html=false)=>new Response(html?v:JSON.stringify(v),{status:200,headers:{'Content-Type':html?'text/html':'application/json'}});
test('Swiss source includes only truly online, timed, future webinars',()=>{
 const events=normalizeSwissEvents(swiss,now);
 assert.equal(events.length,1);
 assert.equal(events[0].endBasis,'published');
 assert.equal(events[0].endsAt,'2026-11-10T19:00:00.000Z');
 assert.equal(events[0].category,'webinar');
 assert.equal(normalizeSwissEvents({...swiss,events:[{...swiss.events[0],url:'https://evil.invalid'}]},now).length,0);
});
test('Fellowship start-only virtual event is discovery only, not invented 60-minute calendar reservation',()=>{
 const events=normalizeFellowshipEvents(fellowship,now);
 assert.equal(events.length,1);
 assert.equal(events[0].startsAt,'2026-11-09T22:00:00.000Z');
 assert.equal(events[0].endsAt,undefined);
});
test('Red Look parses actual official announced online date, never assumes weekly repetition',()=>{
 const ev=normalizeRedLookEvents(redlook,now);
 assert.equal(ev.length,1);
 assert.equal(ev[0].category,'english-exchange');
 assert.equal(ev[0].startsAt,'2026-11-11T11:30:00.000Z');
 assert.equal(ev[0].endBasis,'estimated-duration');
 assert.equal(normalizeRedLookEvents('<h2>次回の開催</h2><p>近日発表</p>',now).length,0);
});
test('only fixed publicly documented provider URLs are fetched, response cached and fail-open per source',async()=>{
 const calls=[];
 const provider=async(url)=>{
   calls.push(url);
   if(url==='https://swissdataevents.ch/events.json')return ok(swiss);
   if(url.startsWith('https://rmxirzudhsautnsrdvib.supabase.co/'))return ok(fellowship);
   if(url==='https://red-look.com/ja/online.html')return ok(redlook,true);
   throw Error('Unexpected URL: '+url);
 };
 const app=createTvScheduleService({fetchImpl:provider,clock:()=>now,
   env:{INDEPENDENT_SENESCHAL_ORIGIN:'https://seneschal-standalone-staging.onrender.com'}});
 await new Promise(ok=>app.server.listen(0,'127.0.0.1',ok));
 const root='http://127.0.0.1:'+app.server.address().port;
 try{
  const r=await fetch(root+'/api/v1/activities/upcoming',{headers:{Origin:'https://seneschal-standalone-staging.onrender.com'}});
  assert.equal(r.status,200);
  assert.equal(r.headers.get('access-control-allow-origin'),'https://seneschal-standalone-staging.onrender.com');
  const data=await r.json();
  assert.equal(data.schema,'federation.online-activities/1');
  assert.equal(data.count,3);
  assert.equal(data.personalDataCollected,false);
  assert.equal(data.items.filter(e=>e.endsAt).length,2);
  assert.deepEqual(calls.sort(),['https://swissdataevents.ch/events.json',
   'https://rmxirzudhsautnsrdvib.supabase.co/functions/v1/public-events?format=json',
   'https://red-look.com/ja/online.html'].sort());
  await fetch(root+'/api/v1/activities/upcoming'); assert.equal(calls.length,3);
  assert.equal((await fetch(root+'/api/v1/activities/upcoming?url=https://evil.invalid')).status,400);
  assert.equal((await fetch(root+'/api/v1/activities/upcoming',{method:'POST'})).status,405);
  const denied=await fetch(root+'/api/v1/activities/upcoming',{headers:{Origin:'https://unknown.example'}});
  assert.equal(denied.headers.get('access-control-allow-origin'),null);
  assert.equal(calls.length,3);
 }finally{await new Promise(ok=>app.server.close(ok));}
});
test('partial provider failures do not erase verified event results',async()=>{
 const f=async url=>{
   if(url.includes('swissdataevents.ch'))return new Response('fail',{status:503});
   if(url.includes('supabase.co'))return ok(fellowship);
   return ok('',true);
 };
 const c=createOnlineActivitiesCollector(f,()=>now);
 const r=await c.get();
 assert.equal(r.count,1);
 assert.equal(r.providers.find(x=>x.id==='swiss-data-events').state,'unavailable');
 assert.equal(r.providers.find(x=>x.id==='ai-fellowship').state,'ok');
});
