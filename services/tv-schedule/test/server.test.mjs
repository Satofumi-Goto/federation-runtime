import test from 'node:test';
import assert from 'node:assert/strict';
import {createTvScheduleService,allowedOrigins} from '../server.mjs';
import {readFileSync} from 'node:fs';

const now=Date.parse('2026-11-06T01:00:00Z');
const start='2026-11-06T03:00:00Z';
const episode={id:101,airstamp:start,runtime:45,name:'Guest broadcast',
  url:'https://www.tvmaze.com/episodes/101/example',
  show:{id:11,name:'推しの出演番組',network:{name:'東京サンプル局'}}};
const response=value=>new Response(JSON.stringify(value),{status:200,headers:{'Content-Type':'application/json'}});
function fakeProvider({failSchedule=false}={}){
  const called=[];
  const fetchImpl=async url=>{
    called.push(url);
    if(url.includes('/schedule?')){
      if(failSchedule) return new Response('failed',{status:429});
      return response(url.endsWith('2026-11-06')?[episode,episode,{...episode,id:102,airstamp:'2026-11-06T00:59:00Z'}]:[]);
    }
    if(url.endsWith('/episodes/101/guestcast'))return response([{person:{name:'推しのAさん'}}]);
    if(url.endsWith('/shows/11/cast'))return response([{person:{name:'推しのBさん'}}]);
    return response([]);
  };
  return {fetchImpl,called};
}
async function startTestServer(options){
  const app=createTvScheduleService({env:{INDEPENDENT_SENESCHAL_ORIGIN:'https://seneschal-standalone-staging.onrender.com,https://seneschal-runtime.com'},...options,clock:()=>now});
  await new Promise(ok=>app.server.listen(0,'127.0.0.1',ok));
  const url='http://127.0.0.1:'+app.server.address().port;
  return {url,close:()=>new Promise(ok=>app.server.close(ok))};
}
test('GET returns real-provider-shaped evidence and estimated times without personal favorites',async()=>{
  const provider=fakeProvider();const s=await startTestServer({fetchImpl:provider.fetchImpl});
  try{
    const r=await fetch(s.url+'/api/v1/tv/schedule',{headers:{Origin:'https://seneschal-standalone-staging.onrender.com'}});
    assert.equal(r.status,200);
    assert.equal(r.headers.get('access-control-allow-origin'),'https://seneschal-standalone-staging.onrender.com');
    const j=await r.json();
    assert.equal(j.schema,'federation.tv-schedule/1');
    assert.equal(j.count,1);
    assert.equal(j.items[0].title,'推しの出演番組');
    assert.deepEqual(j.items[0].guestCast,['推しのAさん']);
    assert.deepEqual(j.items[0].showCast,['推しのBさん']);
    assert.equal(j.items[0].endsAt,'2026-11-06T03:45:00.000Z');
    assert.equal(j.items[0].endsAtBasis,'episode_runtime_estimate');
    assert.equal(j.personalFavorites,undefined);
    assert(provider.called.every(x=>x.startsWith('https://api.tvmaze.com/')));
    assert(provider.called.length<=4);
    await fetch(s.url+'/api/v1/tv/schedule');
    assert.equal(provider.called.length,4,'30-minute cache prevents repeat upstream access');
  }finally{await s.close();}
});
test('reject arbitrary queries, writes and untrusted browser origins',async()=>{
  const p=fakeProvider();const s=await startTestServer({fetchImpl:p.fetchImpl});
  try{
    assert.equal((await fetch(s.url+'/api/v1/tv/schedule?url=https://attacker.test')).status,400);
    assert.equal((await fetch(s.url+'/api/v1/tv/schedule',{method:'POST'})).status,405);
    assert.equal((await fetch(s.url+'/healthz')).status,200);
    const r=await fetch(s.url+'/api/v1/tv/schedule',{headers:{Origin:'https://untrusted.example'}});
    assert.equal(r.status,200);
    assert.equal(r.headers.get('access-control-allow-origin'),null);
    assert.equal(p.called.some(url=>url.includes('attacker.test')),false);
  }finally{await s.close();}
});
test('provider failure returns 503 rather than fabricated credits or stale availability',async()=>{
  const p=fakeProvider({failSchedule:true}),s=await startTestServer({fetchImpl:p.fetchImpl});
  try{
    const r=await fetch(s.url+'/api/v1/tv/schedule');
    assert.equal(r.status,503);
    assert.equal((await r.json()).reason,'upstream-unavailable');
  }finally{await s.close();}
});
test('concurrent requests coalesce to one bounded provider batch',async()=>{
  const p=fakeProvider(),s=await startTestServer({fetchImpl:p.fetchImpl});
  try{
    const [a,b,c]=await Promise.all([0,1,2].map(()=>fetch(s.url+'/api/v1/tv/schedule').then(x=>x.json())));
    assert.deepEqual([a.count,b.count,c.count],[1,1,1]);
    assert.equal(p.called.length,4);
  }finally{await s.close();}
});


test('throttles anonymous traffic without storing identifiers or blocking health',async()=>{
  const p=fakeProvider(),s=await startTestServer({fetchImpl:p.fetchImpl});
  try{
    for(let i=0;i<30;i++){
      const r=await fetch(s.url+'/api/v1/tv/schedule');
      assert.equal(r.status,200,'allowed request '+i);
    }
    const limited=await fetch(s.url+'/api/v1/tv/schedule');
    assert.equal(limited.status,429);
    assert.equal((await limited.json()).reason,'rate-limited');
    assert.equal((await fetch(s.url+'/healthz')).status,200);
    assert.equal(p.called.length,4,'request cap must not cause additional provider traffic');
  }finally{await s.close();}
});

test('browser origins come only from INDEPENDENT_SENESCHAL_ORIGIN; unset allows none and base44.app is refused',async()=>{
  const source=readFileSync(new URL('../server.mjs',import.meta.url),'utf8');
  assert.equal(/['"]https:\/\/[^'"]*base44\.app/i.test(source),false,'no base44.app origin literal in the server');
  assert.equal(allowedOrigins({}).size,0);
  assert.deepEqual([...allowedOrigins({INDEPENDENT_SENESCHAL_ORIGIN:' https://seneschal-runtime.com '})],['https://seneschal-runtime.com']);
  for(const bad of ['https://seneschal.base44.app','http://seneschal-runtime.com','https://seneschal-runtime.com/','not a url','https://a.example,https://x.base44.app'])
    assert.throws(()=>allowedOrigins({INDEPENDENT_SENESCHAL_ORIGIN:bad}),/invalid-independent-seneschal-origin/,bad);
  const p=fakeProvider();
  const app=createTvScheduleService({env:{},fetchImpl:p.fetchImpl,clock:()=>now});
  await new Promise(ok=>app.server.listen(0,'127.0.0.1',ok));
  const url='http://127.0.0.1:'+app.server.address().port;
  try{
    for(const origin of ['https://seneschal-runtime.com','https://seneschal.base44.app']){
      const r=await fetch(url+'/api/v1/tv/schedule',{headers:{Origin:origin}});
      assert.equal(r.headers.get('access-control-allow-origin'),null,origin);
    }
  }finally{await new Promise(ok=>app.server.close(ok));}
  const s=await startTestServer({fetchImpl:fakeProvider().fetchImpl});
  try{
    const r=await fetch(s.url+'/api/v1/tv/schedule',{headers:{Origin:'https://seneschal.base44.app'}});
    assert.equal(r.headers.get('access-control-allow-origin'),null);
    const ok=await fetch(s.url+'/api/v1/tv/schedule',{headers:{Origin:'https://seneschal-runtime.com'}});
    assert.equal(ok.headers.get('access-control-allow-origin'),'https://seneschal-runtime.com');
  }finally{await s.close();}
});
