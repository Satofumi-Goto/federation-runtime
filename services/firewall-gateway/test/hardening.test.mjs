import test from 'node:test';
import assert from 'node:assert/strict';
import {randomBytes} from 'node:crypto';
import http from 'node:http';
import {createGatewayServer} from '../server.mjs';
import {signHeaders} from '../auth.mjs';
import {FREE_AI_PATH} from '../freeAi.mjs';
import {ASSISTANT_PATH} from '../assistant.mjs';
import {findSecret,precheckSignedHeaders,SECRET_PATTERNS} from '../hardening.mjs';

const NOW=Date.parse('2026-11-10T09:00:00.000Z');
const key=randomBytes(32).toString('base64url');
const raw=Buffer.from(key,'base64url');
const env=(over={})=>({FIREWALL_CLIENT_KEYS_JSON:JSON.stringify({federation:key,seneschal:key,activity:key}),
 FIREWALL_FREE_AI_ENABLED:'true',...over});
// Built from parts so this file never contains a credential-shaped literal.
const SAMPLES={
 'private-key':'-----BEGIN '+'RSA PRIVATE KEY-----\nMIIB',
 'github-token':'gh'+'p_'+'a'.repeat(36),
 'aws-access-key':'AK'+'IA'+'ABCDEFGHIJKLMNOP',
 'google-api-key':'AI'+'za'+'b'.repeat(35),
 'openai-or-anthropic-key':'sk'+'-proj-'+'c'.repeat(40),
 'stripe-secret':'sk'+'_live_'+'d'.repeat(24),
 'slack-token':'xo'+'xb-'+'1234567890-abc',
 'render-api-key':'rn'+'d_'+'e'.repeat(28),
 'jwt':'ey'+'J'+'f'.repeat(12)+'.ey'+'J'+'g'.repeat(12)+'.'+'h'.repeat(20),
 'url-credentials':'redis'+'://default:'+'p'.repeat(12)+'@red-host:6379',
};

async function withGateway(options,run){
 const audit=[];
 const app=createGatewayServer({clock:()=>NOW,auditSink:line=>audit.push(JSON.parse(line)),...options});
 await new Promise(resolve=>app.server.listen(0,'127.0.0.1',resolve));
 const origin='http://127.0.0.1:'+app.server.address().port;
 try{await run(origin,app,audit);}finally{await new Promise(resolve=>app.server.close(resolve));}
}
async function signedPost(origin,path,body,client='federation'){
 const headers=signHeaders({client,key:raw,body,path,time:NOW});
 const response=await fetch(origin+path,{method:'POST',body,headers:{'content-type':'application/json',...headers}});
 return {status:response.status,data:await response.json()};
}

test('every secret category is detected and ordinary text passes',()=>{
 assert.deepEqual(Object.keys(SAMPLES).sort(),SECRET_PATTERNS.map(([id])=>id).sort());
 for(const [id,sample] of Object.entries(SAMPLES))
  assert.equal(findSecret(['前置き '+sample+' 後ろ']),id,id);
 for(const ok of ['const key=process.env.FIREWALL_ASSISTANT_GEMINI_KEY;','https://example.com/path?x=1',
  '地図の予約はどこ？','sk-short','eyJhbGciOi','postgres://host:5432/db','uuid 2d3c1c8e-1b2a-4c3d-8e9f-0a1b2c3d4e5f'])
  assert.equal(findSecret([ok]),null,ok);
});

test('signed-header precheck refuses malformed or stale headers',()=>{
 const good=signHeaders({client:'federation',key:raw,body:'{}',time:NOW});
 assert.equal(precheckSignedHeaders({headers:good},()=>NOW).ok,true);
 assert.equal(precheckSignedHeaders({headers:{}},()=>NOW).status,401);
 assert.equal(precheckSignedHeaders({headers:good},()=>NOW+61000).status,401);
 assert.equal(precheckSignedHeaders({headers:{...good,'x-fw-nonce':'not-a-uuid'}},()=>NOW).status,401);
 assert.equal(precheckSignedHeaders({headers:{...good,'x-fw-client':'../x'}},()=>NOW).status,401);
});

test('free AI relay refuses credential-shaped prompts before any provider call',async()=>{
 let calls=0;
 const fetchImpl=async()=>{calls++;return new Response('{}',{status:500});};
 await withGateway({env:env(),fetchImpl},async(origin,_app,audit)=>{
  for(const sample of Object.values(SAMPLES)){
   const body=JSON.stringify({role:'reply-advice',messages:[{role:'user',content:'見て: '+sample}]});
   const r=await signedPost(origin,FREE_AI_PATH,body);
   assert.equal(r.status,422);assert.deepEqual(r.data,{ok:false,error:'secret-detected'});
   assert.doesNotMatch(JSON.stringify(r.data),new RegExp(sample.slice(0,8).replace(/[.*+?^${}()|[\]\\]/g,'\\$&')));
  }
  assert.equal(calls,0);
  assert.ok(audit.every(a=>!JSON.stringify(a).includes(SAMPLES['github-token'])));
 });
});

test('assistant refuses credential-shaped questions, history and context',async()=>{
 await withGateway({env:env()},async origin=>{
  const base={appId:'seneschal',question:'q',language:'ja',requestId:'r-1'};
  for(const extra of [{question:'key '+SAMPLES['google-api-key']},{context:SAMPLES['private-key']},
   {history:[{role:'user',content:SAMPLES['jwt']}]},{character:{id:'matsuko',personality:SAMPLES['render-api-key']}}]){
   const body=JSON.stringify({...base,...extra});
   const r=await signedPost(origin,ASSISTANT_PATH,body,'seneschal');
   assert.equal(r.status,400);assert.equal(r.data.error,'invalid_question');
   assert.equal(r.data.reason,'secret-detected');assert.equal(r.data.requestId,'r-1');
  }
 });
});

test('unsigned requests are refused without reading the body',async()=>{
 await withGateway({env:env()},async origin=>{
  const {port}=new URL(origin);
  for(const path of [FREE_AI_PATH,ASSISTANT_PATH,'/api/v1/shadow/probe','/api/v1/activity/acquire']){
   // Chunked upload with no signature: the gateway must answer 401 immediately.
   const status=await new Promise((resolve,reject)=>{
    const req=http.request({host:'127.0.0.1',port,path,method:'POST',
     headers:{'content-type':'application/json','transfer-encoding':'chunked'}},res=>{res.resume();resolve(res.statusCode);});
    req.on('error',reject);req.write('{"partial":');// body intentionally never completed
   });
   assert.equal(status,401,path);
  }
 });
});

test('security headers, socket caps and audit of activity/admin requests',async()=>{
 await withGateway({env:env()},async(origin,app,audit)=>{
  const r=await fetch(origin+'/healthz');
  assert.equal(r.headers.get('strict-transport-security'),'max-age=31536000; includeSubDomains');
  assert.equal(app.server.maxConnections,128);assert.equal(app.server.maxRequestsPerSocket,100);
  await fetch(origin+'/admin');
  await fetch(origin+'/api/v1/activity/acquire',{method:'POST',body:'{}',headers:{'content-type':'application/json'}});
  await new Promise(resolve=>setTimeout(resolve,20));
  const admin=audit.find(a=>a.type==='firewall.admin.request');
  assert.deepEqual(Object.keys(admin).sort(),['at','method','status','type']);
  assert.equal(admin.status,503);
  const act=audit.find(a=>a.type==='firewall.activity.request');
  assert.deepEqual(Object.keys(act).sort(),['at','client','method','source','status','type']);
  assert.equal(act.status,401);assert.equal(act.client,null);
 });
 await withGateway({env:env({FIREWALL_MAX_CONNECTIONS:'9999'})},async(_o,app)=>assert.equal(app.server.maxConnections,128));
 await withGateway({env:env({FIREWALL_MAX_CONNECTIONS:'32'})},async(_o,app)=>assert.equal(app.server.maxConnections,32));
});
