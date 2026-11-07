import test from 'node:test';
import assert from 'node:assert/strict';
import {randomBytes} from 'node:crypto';
import {createGatewayServer} from '../server.mjs';
import {signHeaders} from '../auth.mjs';

const NOW=Date.parse('2026-11-07T01:00:00.000Z');
const PATH='/api/v1/activity/acquire',KEY=randomBytes(32);
const config={FIREWALL_ACTIVITY_ACQUISITION_KEY:KEY.toString('base64url'),FIREWALL_ACTIVITY_SOURCES_ENABLED:'true'};
async function serverWith(fetchImpl,fn){
 const service=createGatewayServer({env:config,fetchImpl,clock:()=>NOW,auditSink:()=>{}});
 await new Promise(resolve=>service.server.listen(0,'127.0.0.1',resolve));
 try{await fn('http://127.0.0.1:'+service.server.address().port);}
 finally{await new Promise(resolve=>service.server.close(resolve));}
}
async function acquire(base,body=JSON.stringify({source:'anilist'})){
 const h=signHeaders({client:'activity',key:KEY,body,path:PATH,time:NOW});
 const r=await fetch(base+PATH,{method:'POST',headers:{'Content-Type':'application/json',...h},body});
 return {status:r.status,body:await r.json()};
}
test('signed fixed AniList source uses exactly one bounded JSON POST with no credentials or caller query',async()=>{
 const egress=[];
 const sample={data:{Page:{media:[{id:10,title:{native:'作品'},siteUrl:'https://anilist.co/anime/10'}]}}};
 const provider=async(url,init)=>{
  egress.push({url,init});
  assert.equal(url,'https://graphql.anilist.co/');
  assert.equal(init.method,'POST');assert.equal(init.redirect,'manual');assert.equal(init.credentials,'omit');
  assert.equal(init.headers['Content-Type'],'application/json');
  assert.equal(new URL(url).search,'');
  assert.match(JSON.parse(init.body).query,/media\(type:ANIME/);
  assert.match(JSON.parse(init.body).query,/isAdult:false/);
  assert.equal(Object.keys(JSON.parse(init.body)).length,1);
  assert.equal(init.headers.Authorization,undefined);
  assert.equal(init.headers.Cookie,undefined);
  return Response.json(sample);
 };
 await serverWith(provider,async base=>{
  const a=await acquire(base);
  assert.equal(a.status,200);
  assert.equal(a.body.ok,true);
  assert.equal(a.body.schema,'gateway.activity-raw/1');
  assert.equal(a.body.source,'anilist');
  assert.equal(a.body.personalDataCollected,false);
  assert.equal(a.body.data.encoding,'base64url');
  assert.deepEqual(JSON.parse(Buffer.from(a.body.data.body,'base64url').toString('utf8')),sample);
  const b=await acquire(base);
  assert.equal(b.status,200);assert.equal(b.body.cached,true);
  assert.equal(egress.length,1,'shared cache prevents repeated provider egress');
  const bad=await acquire(base,JSON.stringify({source:'anilist',query:'{ viewer { id } }'}));
  assert.equal(bad.status,400);
  assert.equal(egress.length,1,'unexpected caller fields are never forwarded');
 });
});
test('AniList 429 enters minimum 1h cooldown; Gateway does not burst retry on rate limit',async()=>{
 let calls=0;
 const provider=async()=>{calls++;return new Response('{}',{status:429,headers:{'Retry-After':'90'}})};
 await serverWith(provider,async base=>{
  const a=await acquire(base);assert.equal(a.status,503);
  const b=await acquire(base);assert.equal(b.status,503);
  assert.equal(calls,1);
 });
});
test('no acquisition flag denies signed AniList and does not contact provider',async()=>{
 let calls=0;
 const server=createGatewayServer({env:{FIREWALL_ACTIVITY_ACQUISITION_KEY:KEY.toString('base64url')},clock:()=>NOW,
   fetchImpl:async()=>{calls++;throw Error('no call');},auditSink:()=>{}});
 await new Promise(resolve=>server.server.listen(0,'127.0.0.1',resolve));
 try{
  const url='http://127.0.0.1:'+server.server.address().port;
  const response=await acquire(url);
  assert.equal(response.status,503);assert.equal(calls,0);
 }finally{await new Promise(resolve=>server.server.close(resolve));}
});
