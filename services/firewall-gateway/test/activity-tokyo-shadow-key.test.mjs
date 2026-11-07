import test from 'node:test';
import assert from 'node:assert/strict';
import {randomBytes} from 'node:crypto';
import {createGatewayServer} from '../server.mjs';
import {signHeaders} from '../auth.mjs';

const NOW=Date.parse('2026-11-07T07:00:00Z'),PATH='/api/v1/activity/acquire';
const STAGING_KEY=randomBytes(32),EXISTING_EVENT_KEY=randomBytes(32);
const baseEnv={
 FIREWALL_ACTIVITY_TOKYO_SHADOW_KEY:STAGING_KEY.toString('base64url'),
 FIREWALL_ACTIVITY_SOURCES_ENABLED:'true',
 FIREWALL_ACTIVITY_EVENTS_ENABLED:'true'
};
async function withGateway(env,fn){
 let requests=0;
 const fetchImpl=async(url,init)=>{
   requests++;
   assert.match(url,/^https:\/\/service\.api\.metro\.tokyo\.lg\.jp\/api\//);
   assert.equal(init.method,'POST');
   assert.equal(init.body,'{}');
   assert.equal(init.credentials,'omit');
   assert.equal(init.redirect,'manual');
   return Response.json({hits:[{_source:{'イベント名':'区民公開イベント','開始日':'2026/11/15',
     '緯度':'35.6','経度':'139.7','開催場所':'公民館','URL':'https://www.city.koto.lg.jp/'}}]});
 };
 const service=createGatewayServer({env,clock:()=>NOW,fetchImpl,auditSink:()=>{}});
 await new Promise(resolve=>service.server.listen(0,'127.0.0.1',resolve));
 try{await fn('http://127.0.0.1:'+service.server.address().port,()=>requests);}
 finally{await new Promise(resolve=>service.server.close(resolve));}
}
async function signed(root,key,source){
 const body=JSON.stringify(source==='events'
   ?{source,from:'2026-11-07',to:'2026-11-14',page:1}:{source});
 const h=signHeaders({client:'activity',key,body,path:PATH,time:NOW});
 const response=await fetch(root+PATH,{method:'POST',headers:{'Content-Type':'application/json',...h},body});
 return {status:response.status,data:await response.json()};
}
test('Tokyo staging key accesses only two fixed public datasets, with no provider credentials',async()=>{
 await withGateway(baseEnv,async(root,count)=>{
  for(const [source,id] of [['tokyo_koto_events','tokyo_koto'],['tokyo_sumida_events','tokyo_sumida']]){
    const res=await signed(root,STAGING_KEY,source);
    assert.equal(res.status,200);
    assert.equal(res.data.ok,true);
    assert.equal(res.data.source,source);
    assert.equal(res.data.personalDataCollected,false);
    assert.equal(res.data.tokyo.datasetId,id);
    assert.equal(res.data.tokyo.hits.length,1);
  }
  assert.equal(count(),2);
  const repeat=await signed(root,STAGING_KEY,'tokyo_koto_events');
  assert.equal(repeat.status,200);
  assert.equal(repeat.data.cached,true);
  assert.equal(count(),2);
  const kawasaki=await signed(root,STAGING_KEY,'events');
  assert.equal(kawasaki.status,503);
  assert.equal(kawasaki.data.reason,'service-auth-unconfigured');
  for(const source of ['tv','gdelt','mlit','anilist']){
    const denied=await signed(root,STAGING_KEY,source);
    assert.equal(denied.status,503,source);
    assert.equal(denied.data.reason,'service-auth-unconfigured');
  }
  assert.equal(count(),2,'Tokyo-only staging key must not fetch any other provider');
 });
});
test('existing event key still works for Kawasaki and Tokyo; added key does not rotate it',async()=>{
 const env={...baseEnv,FIREWALL_ACTIVITY_EVENT_ACQUISITION_KEY:EXISTING_EVENT_KEY.toString('base64url')};
 await withGateway(env,async(root,count)=>{
  const tokyoExisting=await signed(root,EXISTING_EVENT_KEY,'tokyo_koto_events');
  const tokyoStaging=await signed(root,STAGING_KEY,'tokyo_koto_events');
  assert.equal(tokyoExisting.status,200);
  assert.equal(tokyoStaging.status,200);
  assert.equal(count(),1,'caching is shared across both authorized keys');
  const kawasakiWithStaging=await signed(root,STAGING_KEY,'events');
  assert.equal(kawasakiWithStaging.status,401);
  assert.equal(kawasakiWithStaging.data.reason,'signature-invalid');
 });
});
test('staging key absent by default rejects signing and performs no egress',async()=>{
 await withGateway({FIREWALL_ACTIVITY_SOURCES_ENABLED:'true',FIREWALL_ACTIVITY_EVENTS_ENABLED:'true'},async(root,count)=>{
  const res=await signed(root,STAGING_KEY,'tokyo_koto_events');
  assert.equal(res.status,503);
  assert.equal(res.data.reason,'service-auth-unconfigured');
  assert.equal(count(),0);
 });
});
