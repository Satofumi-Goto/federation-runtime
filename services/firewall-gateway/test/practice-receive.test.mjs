// 10アプリ同時同期：federation-api からの運行実務の受付番号の知らせ（/api/v1/practice/receive）。
import test from 'node:test';
import assert from 'node:assert/strict';
import {randomBytes} from 'node:crypto';
import {createGatewayServer,validPracticeReceipt,PRACTICE_RECEIPT_SCHEMA} from '../server.mjs';
import {signHeaders} from '../auth.mjs';

const NOW=Date.parse('2026-11-13T02:00:00.000Z'),PATH='/api/v1/practice/receive';
const fed=randomBytes(32),sen=randomBytes(32);
const env={FIREWALL_CLIENT_KEYS_JSON:JSON.stringify({federation:fed.toString('base64url'),seneschal:sen.toString('base64url')})};
const audits=[];
async function withGateway(run){
 const app=createGatewayServer({env,clock:()=>NOW,auditSink:line=>audits.push(line)});
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
