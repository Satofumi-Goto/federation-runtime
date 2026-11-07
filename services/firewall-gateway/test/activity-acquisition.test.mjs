import test from 'node:test';
import assert from 'node:assert/strict';
import {randomBytes} from 'node:crypto';
import {createGatewayServer} from '../server.mjs';
import {signHeaders} from '../auth.mjs';
const NOW=Date.parse('2026-11-07T00:00:00.000Z'),PATH='/api/v1/activity/acquire';
const KEY=randomBytes(32);
const config=(flags={})=>({FIREWALL_CLIENT_KEYS_JSON:JSON.stringify({activity:KEY.toString('base64url')}),
 FIREWALL_ACTIVITY_ACQUISITION_KEY:KEY.toString('base64url'),...flags});
async function serve(env,fetchImpl,fn){
 const app=createGatewayServer({env,clock:()=>NOW,fetchImpl,auditSink:()=>{}});
 await new Promise(resolve=>app.server.listen(0,'127.0.0.1',resolve));
 try{await fn('http://127.0.0.1:'+app.server.address().port);}
 finally{await new Promise(resolve=>app.server.close(resolve));}
}
async function request(base,source='online',extra={}){
 const body=JSON.stringify({source});
 const headers={'content-type':'application/json',...signHeaders({client:'activity',key:KEY,body,path:PATH,time:NOW}),...extra};
 const r=await fetch(base+PATH,{method:'POST',headers,body});
 return {status:r.status,data:await r.json()};
}
test('off by default; signed activity receives 503 and NO outbound traffic',async()=>{
 let calls=0;
 await serve(config(),async()=>{calls++;throw Error('should not fetch');},async url=>{
  assert.equal((await request(url)).status,503);
  assert.equal(calls,0);
 });
});
test('the general client key alone never authorizes Activity source egress',async()=>{
 let calls=0;
 const fake=async()=>{calls++;throw Error('not allowed');};
 await serve({FIREWALL_CLIENT_KEYS_JSON:JSON.stringify({activity:KEY.toString('base64url')}),
   FIREWALL_ACTIVITY_SOURCES_ENABLED:'true'},fake,async url=>{
   const result=await request(url,'online');
   assert.equal(result.status,503);
   assert.equal(result.data.reason,'service-auth-unconfigured');
 });
 assert.equal(calls,0);
});
test('the signed endpoint rejects browsers, wrong clients, arbitrary queries and replay',async()=>{
 const provider=async url=>{
  if(url.includes('swissdataevents.ch'))return new Response(JSON.stringify({events:[]}),{headers:{'content-type':'application/json'}});
  if(url.includes('supabase.co'))return new Response(JSON.stringify({events:[]}),{headers:{'content-type':'application/json'}});
  return new Response('<p>Next event TBA</p>',{headers:{'content-type':'text/html'}});
 };
 await serve(config({FIREWALL_ACTIVITY_SOURCES_ENABLED:'true'}),provider,async url=>{
  const denied=await request(url,'online',{origin:'https://seneschal-standalone-staging.onrender.com'});
  assert.equal(denied.status,403);
  const first=await request(url,'online');
  assert.equal(first.status,200);assert.equal(first.data.schema,'gateway.activity-raw/1');
  assert.equal(first.data.personalDataCollected,false);
  const b='{"source":"online"}',headers=signHeaders({client:'activity',key:KEY,body:b,path:PATH,time:NOW});
  const r1=await fetch(url+PATH,{method:'POST',headers:{'content-type':'application/json',...headers},body:b});
  const r2=await fetch(url+PATH,{method:'POST',headers:{'content-type':'application/json',...headers},body:b});
  assert.equal(r1.status,200);assert.equal(r2.status,409);
  const weird=await request(url,'https://attacker.invalid');
  assert.equal(weird.status,400);
 });
});
test('TV raw credits and fixed online providers are gateway-only, bounded and cached',async()=>{
 const calls=[],start='2026-11-07T04:00:00Z';
 const provider=async url=>{
  calls.push(url);
  const data=url.includes('/schedule?')?[{id:10,airstamp:start,runtime:30,show:{id:22,name:'Trial Show'},url:'https://www.tvmaze.com/episodes/10/one'}]:
    url.endsWith('/episodes/10/guestcast')?[{person:{name:'Guest A'}}]:
    url.endsWith('/shows/22/cast')?[{person:{name:'Regular B'}}]:
    url.includes('swissdataevents.ch')?{events:[{online:true,start,end:start,title:'Conference'}]}:
    url.includes('supabase.co')?{events:[{format:'virtual',title:'Livestream',startTime:start}]}:
    '<h2>Next date pending</h2>';
  return new Response(typeof data==='string'?data:JSON.stringify(data),
    {headers:{'content-type':typeof data==='string'?'text/html':'application/json'}});
 };
 await serve(config({FIREWALL_ACTIVITY_SOURCES_ENABLED:'true'}),provider,async url=>{
  const tv=await request(url,'tv');
  assert.equal(tv.status,200);assert.equal(tv.data.episodes.length,1);
  assert.deepEqual(tv.data.episodes[0].guestCast,['Guest A']);
  assert.deepEqual(tv.data.episodes[0].showCast,['Regular B']);
  const online=await request(url,'online');
  assert.equal(online.status,200);assert.equal(online.data.swiss.length,1);
  assert.equal(online.data.fellowship.length,1);
  assert.match(online.data.redlook,/pending/);
  const total=calls.length;
  assert(total<=7);
  await request(url,'tv');await request(url,'online');
  assert.equal(calls.length,total,'cached results must not repeat provider fetch');
  assert(calls.every(x=>x.startsWith('https://api.tvmaze.com/')||
    ['https://swissdataevents.ch/events.json','https://rmxirzudhsautnsrdvib.supabase.co/functions/v1/public-events?format=json','https://red-look.com/ja/online.html'].includes(x)));
 });
});

test('news providers are fixed gateway-owned URLs, signed Activity-only, bytes bounded and cached',async()=>{
 const calls=[];
 const provider=async(url,options)=>{
  calls.push(url);
  assert.equal(options.method,'GET');
  assert.equal(options.redirect,'manual');
  assert.equal(options.credentials,'omit');
  if(url.includes('gdeltproject.org'))return new Response(JSON.stringify({articles:[{title:'News',url:'https://example.org/news'}]}),{headers:{'content-type':'application/json'}});
  if(url==='https://www.mlit.go.jp/pressrelease.rdf')return new Response(new Uint8Array([60,114,100,102,58,82,68,70,62]),{headers:{'content-type':'application/rdf+xml'}});
  throw Error('unexpected-egress');
 };
 await serve(config({FIREWALL_ACTIVITY_SOURCES_ENABLED:'true'}),provider,async url=>{
  const global=await request(url,'gdelt');
  const ministry=await request(url,'mlit');
  assert.equal(global.status,200);
  assert.equal(ministry.status,200);
  for(const packet of [global.data,ministry.data]){
   assert.equal(packet.schema,'gateway.activity-raw/1');
   assert.equal(packet.personalDataCollected,false);
   assert.equal(packet.data.encoding,'base64url');
   assert.match(packet.data.body,/^[A-Za-z0-9_-]+$/);
  }
  assert.deepEqual(JSON.parse(Buffer.from(global.data.data.body,'base64url').toString('utf8')).articles[0].title,'News');
  assert.equal(Buffer.from(ministry.data.data.body,'base64url').toString('utf8'),'<rdf:RDF>');
  const count=calls.length;
  await request(url,'gdelt');await request(url,'mlit');
  assert.equal(calls.length,count,'source-level cache prevents repeated outbound requests');
  assert.equal(count,2);
  assert.equal((await request(url,'arbitrary-url')).status,400);
  assert(calls.every(x=>x.startsWith('https://api.gdeltproject.org/api/v2/doc/doc?query=')||x==='https://www.mlit.go.jp/pressrelease.rdf'));
 });
});
test('news gateway denies unconfigured egress and never fetches provider directly',async()=>{
 let calls=0;
 await serve(config(),async()=>{calls++;throw Error('no egress');},async url=>{
   assert.equal((await request(url,'mlit')).status,503);
   assert.equal((await request(url,'gdelt')).status,503);
   assert.equal(calls,0);
 });
});
