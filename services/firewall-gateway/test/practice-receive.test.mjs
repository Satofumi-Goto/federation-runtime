// 10アプリ同時同期：federation-api からの運行実務の受付番号の知らせ（/api/v1/practice/receive）。
import test from 'node:test';
import assert from 'node:assert/strict';
import {request} from 'node:http';
import {randomBytes} from 'node:crypto';
import {createGatewayServer,validPracticeReceipt,PRACTICE_RECEIPT_SCHEMA} from '../server.mjs';
import {CHANGE_SCHEMA,CHANGE_URL} from '../tenAppChangeContract.mjs';
import {signHeaders} from '../auth.mjs';

const NOW=Date.parse('2026-11-13T02:00:00.000Z'),PATH='/api/v1/practice/receive';
const fed=randomBytes(32),sen=randomBytes(32);
const env={FIREWALL_CLIENT_KEYS_JSON:JSON.stringify({federation:fed.toString('base64url'),seneschal:sen.toString('base64url')})};
const audits=[];
async function withGateway(run,options={}){
 const app=createGatewayServer({env,clock:()=>NOW,auditSink:line=>audits.push(line),...options});
 await new Promise(r=>app.server.listen(0,'127.0.0.1',r));
 try{await run('http://127.0.0.1:'+app.server.address().port);}finally{await new Promise(r=>app.server.close(r));}
}
const cmd=(cursor,extra={})=>JSON.stringify({schema:PRACTICE_RECEIPT_SCHEMA,cursor,incidents:1,decisions:[{area:'北区',decision:'suspend'}],...extra});
async function call(origin,{client='federation',key=fed,body=cmd(5),headers={}}={}){
 const h=signHeaders({client,key,body,path:PATH,time:NOW});
 const r=await fetch(origin+PATH,{method:'POST',body,headers:{'content-type':'application/json',...h,...headers}});
 return {status:r.status,data:await r.json()};
}

test('Federation の署名だけを受け付け、受付番号を返す（逆戻りしない）',async()=>{
 await withGateway(async origin=>{
  let r=await call(origin);assert.equal(r.status,200);assert.equal(r.data.cursor,5);assert.equal(r.data.schema,PRACTICE_RECEIPT_SCHEMA);
  r=await call(origin,{body:cmd(3)});assert.equal(r.status,200);assert.equal(r.data.cursor,5,'古い番号では戻らない');
  r=await call(origin,{body:cmd(9)});assert.equal(r.data.cursor,9);
  assert.equal((await call(origin,{client:'seneschal',key:sen})).status,403);
  assert.equal((await call(origin,{key:randomBytes(32)})).status,401);
  assert.equal((await call(origin,{headers:{origin:'https://evil.example'}})).status,403);
  assert.equal((await call(origin,{body:cmd(1,{note:'x'})})).status,400);
  const ready=await (await fetch(origin+'/_status/readiness')).json();
  assert.equal(ready.observed.practiceRelay.cursor,9);
 });
});

test('受け取る形の検査：本文・個人情報の欄は受け取らない',()=>{
 assert.ok(validPracticeReceipt(JSON.parse(cmd(1))));
 assert.equal(validPracticeReceipt({schema:PRACTICE_RECEIPT_SCHEMA,cursor:-1,incidents:0,decisions:[]}),false);
 assert.equal(validPracticeReceipt({schema:PRACTICE_RECEIPT_SCHEMA,cursor:1,incidents:0,decisions:[{area:'a',decision:'other'}]}),false);
 assert.equal(validPracticeReceipt({schema:PRACTICE_RECEIPT_SCHEMA,cursor:1,incidents:0,decisions:Array.from({length:21},()=>({area:'a',decision:'go'}))}),false);
});


test('volatile receipt is explicit; stale resend cannot refresh evidence and same cursor cannot change content',async()=>{
 let now=NOW;
 await withGateway(async origin=>{
  const first=await call(origin);
  assert.equal(first.data.durable,false);assert.equal(first.data.storage,'memory');
  assert.equal(first.data.memoryReceived,true);assert.equal(first.data.status,'received');
  now+=1000;
  const stale=await call(origin,{body:cmd(3)});
  assert.equal(stale.data.status,'stale');assert.equal(stale.data.memoryReceived,false);
  assert.equal(stale.data.requestCursor,3);assert.equal(stale.data.cursor,5);
  assert.equal(stale.data.receivedAt,first.data.receivedAt);
  const conflict=await call(origin,{body:cmd(5,{incidents:2})});
  assert.equal(conflict.status,409);assert.equal(conflict.data.reason,'cursor-content-conflict');
  const duplicate=await call(origin);assert.equal(duplicate.data.status,'duplicate');
  const ready=await (await fetch(origin+'/_status/readiness')).json();
  assert.equal(ready.observed.practiceRelay.durable,false);
  assert.equal(ready.authenticatedE2E,false);assert.equal(ready.productionReady,false);
 },{clock:()=>now});
 // A new process has no receipt, even after a successful volatile acknowledgement.
 await withGateway(async origin=>{
  const ready=await (await fetch(origin+'/_status/readiness')).json();
  assert.equal(ready.observed.practiceRelay.receivedAt,null);
  assert.equal(ready.observed.practiceRelay.cursor,0);
 });
});

test('rejects browser credentials, unsigned/tampered/stale signatures and repeated signed requests',async()=>{
 await withGateway(async origin=>{
  for(const headers of [{origin:'https://example.test'},{cookie:'session=x'},{authorization:'Bearer x'},{'sec-fetch-site':'same-origin'}]){
   assert.equal((await call(origin,{headers})).data.reason,'server-to-server-only');
  }
  const body=cmd(5),signed=signHeaders({client:'federation',key:fed,body,path:PATH,time:NOW});
  const send=async(b=body,h=signed)=>fetch(origin+PATH,{method:'POST',body:b,headers:{'content-type':'application/json',...h}});
  assert.equal((await send(body,{})).status,401);
  assert.equal((await send(cmd(6))).status,401);
  assert.equal((await send(body,signHeaders({client:'federation',key:fed,body,path:PATH,time:NOW-60001}))).status,401);
  assert.equal((await send()).status,200);
  const replay=await send();assert.equal(replay.status,409);assert.equal((await replay.json()).reason,'replay-refused');
 });
});

test('area rejects contact data, controls and credential shapes without echoing them',async()=>{
 await withGateway(async origin=>{
  for(const area of ['a@example.test','090-1234-5678','０９０－１２３４－５６７８','北区\n氏名','sk-'+ 'a'.repeat(35)]){
   const result=await call(origin,{body:cmd(1,{decisions:[{area,decision:'go'}]})});
   assert.equal(result.status,400,area);assert.equal(result.data.reason,'unsupported-command');
   assert.equal(JSON.stringify(result.data).includes(area),false);
  }
  assert.equal((await call(origin,{body:cmd(1,{decisions:[{area:'東京都 北区（北部）',decision:'go'}]})})).status,200);
 });
});

test('declared and chunked bodies above 2KB fail before receipt',async()=>{
 await withGateway(async origin=>{
  const body=' '.repeat(2049);
  assert.equal((await call(origin,{body})).status,413);
  const headers={'content-type':'application/json',...signHeaders({client:'federation',key:fed,body,path:PATH,time:NOW})};
  const result=await new Promise((resolve,reject)=>{
   const req=request(origin+PATH,{method:'POST',headers},res=>{
    let text='';res.on('data',part=>text+=part);res.on('end',()=>resolve({status:res.statusCode,text}));
   });req.on('error',reject);req.write(body.slice(0,1024));req.end(body.slice(1024));
  });
  assert.equal(result.status,413);
  const ready=await (await fetch(origin+'/_status/readiness')).json();
  assert.equal(ready.observed.practiceRelay.receivedAt,null);
 });
});

test('distributed-store requirement fails closed and free-AI key cannot authorize the new receipt route',async()=>{
 const dedicated=randomBytes(32);
 await withGateway(async origin=>{
  assert.equal((await call(origin,{key:dedicated})).status,401);
  assert.equal((await call(origin)).status,200);
  assert.equal((await call(origin,{client:'seneschal',key:dedicated})).status,403);
 },{env:{...env,FIREWALL_FREE_AI_FEDERATION_KEY:dedicated.toString('base64url')}});
 await withGateway(async origin=>{
  const result=await call(origin);assert.equal(result.status,503);
  assert.equal(result.data.reason,'security-store-unavailable');
  const ready=await (await fetch(origin+'/_status/readiness')).json();
  assert.equal(ready.observed.practiceRelay.receivedAt,null);
 },{env:{...env,FIREWALL_REQUIRE_DISTRIBUTED_STORE:'true'}});
 await withGateway(async origin=>{
  const result=await call(origin);assert.equal(result.status,503);
  assert.equal(result.data.reason,'replay-store-unavailable');
  const ready=await (await fetch(origin+'/_status/readiness')).json();
  assert.equal(ready.observed.practiceRelay.receivedAt,null);
 },{env:{...env,FIREWALL_STORE:'redis-rest',FIREWALL_STORE_REST_URL:'https://firewall-example.upstash.io',FIREWALL_STORE_REST_TOKEN:'a'.repeat(30)},fetchImpl:async()=>{throw Error('offline');}});
});

test('receipt claims a shared nonce across gateway instances without creating audit/export loops',async()=>{
 const nonces=new Set(),commands=[];
 const fetchImpl=async(_url,init)=>new Response(JSON.stringify(JSON.parse(init.body).map(([command,key])=>{
  commands.push(command);
  assert.equal(command,'SET','receipt must only claim a nonce, not append audit or consume egress budget');
  if(nonces.has(key))return {result:null};
  nonces.add(key);return {result:'OK'};
 })),{headers:{'content-type':'application/json'}});
 const options={env:{...env,FIREWALL_STORE:'redis-rest',FIREWALL_STORE_REST_URL:'https://firewall-example.upstash.io',FIREWALL_STORE_REST_TOKEN:'a'.repeat(30)},fetchImpl};
 await withGateway(async first=>{
  await withGateway(async second=>{
   const body=cmd(5),headers=signHeaders({client:'federation',key:fed,body,path:PATH,time:NOW});
   assert.equal((await call(first,{body,headers})).status,200);
   const replay=await call(second,{body,headers});
   assert.equal(replay.status,409);assert.equal(replay.data.reason,'replay-refused');
   const ready=await (await fetch(second+'/_status/readiness')).json();
   assert.equal(ready.observed.practiceRelay.receivedAt,null);
   assert.equal(commands.length,2);
  },options);
 },options);
});

test('receipt epoch is valid and stable per server, distinct across overlapping servers even when notifications are disabled',async()=>{
 await withGateway(async first=>{const a=await call(first),b=await call(first);assert.match(a.data.bootEpoch,/^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/);assert.equal(a.data.bootEpoch,b.data.bootEpoch);await withGateway(async second=>{const c=await call(second);assert.notEqual(a.data.bootEpoch,c.data.bootEpoch);});});
});
test('startup callback event ID and post-ACK receipt share the same server epoch',async()=>{
 const calls=[];const fetchImpl=async(url,init)=>{if(url===CHANGE_URL){const command=JSON.parse(init.body);calls.push(command);return Response.json({ok:true,schema:CHANGE_SCHEMA,eventId:command.eventId,accepted:true});}return Response.json(JSON.parse(init.body).map(([command])=>{assert.ok(['GET','SET'].includes(command));return {result:command==='GET'?null:'OK'};}));};
 await withGateway(async origin=>{for(let n=0;n<100&&calls.length===0;n++)await new Promise(r=>setTimeout(r,5));assert.equal(calls.length,1);assert.equal(calls[0].kind,'gateway-started');const a=await call(origin),b=await call(origin);assert.equal(a.data.bootEpoch,calls[0].eventId);assert.equal(b.data.bootEpoch,calls[0].eventId);},{env:{...env,FIREWALL_STORE:'redis-rest',FIREWALL_STORE_REST_URL:'https://firewall-example.upstash.io',FIREWALL_STORE_REST_TOKEN:'a'.repeat(30),FIREWALL_FREE_AI_FEDERATION_KEY:fed.toString('base64url'),FIREWALL_TEN_APP_CHANGE_NOTIFY_ENABLED:'true'},fetchImpl});
});
