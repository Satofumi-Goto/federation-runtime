import test from 'node:test';
import assert from 'node:assert/strict';
import {randomBytes} from 'node:crypto';
import {createGatewayServer} from '../server.mjs';
import {signHeaders} from '../auth.mjs';

test('signed gateway calls create redacted bounded audit; browser-origin calls reject',async()=>{
 const key=randomBytes(32);
 const logs=[];
 let upstreamCalls=0;
 const app=createGatewayServer({
  env:{FIREWALL_CLIENT_KEYS_JSON:JSON.stringify({activity:key.toString('base64url')}),FIREWALL_CANARY_EGRESS:'false'},
  auditSink:line=>logs.push(line),
  fetchImpl:async()=>{upstreamCalls++;throw Error('must not call upstream');}
 });
 await new Promise(resolve=>app.server.listen(0,'127.0.0.1',resolve));
 const origin='http://127.0.0.1:'+app.server.address().port, path='/api/v1/shadow/probe';
 const payload=JSON.stringify({routeId:'japan-holidays'});
 const signature=signHeaders({client:'activity',key,body:payload});
 const post=async headers=>{
  const response=await fetch(origin+path,{method:'POST',headers:{'content-type':'application/json',...signature,...headers},body:payload});
  return {status:response.status,data:await response.json()};
 };
 try{
  const browser=await post({origin:'https://evil.example'});
  assert.equal(browser.status,403);
  assert.equal(browser.data.reason,'server-to-server-only');
  const bearer=await post({authorization:'Bearer unwanted-token'});
  assert.equal(bearer.status,403);
  const valid=await post({});
  assert.equal(valid.status,503);
  assert.equal(valid.data.reason,'egress-disabled');
  assert.equal(upstreamCalls,0);
  assert.equal(logs.length,3);
  for(const raw of logs){
   const record=JSON.parse(raw);
   assert.deepEqual(Object.keys(record).sort(),['at','client','method','routeId','status','type']);
   assert.equal(record.type,'firewall.shadow.request');
   assert.equal(record.method,'POST');
   assert.ok([403,503].includes(record.status));
   assert.doesNotMatch(raw,/Bearer|unwanted-token|x-fw-signature|secret|198\.51\.100\./i);
  }
  assert.equal(JSON.parse(logs[0]).client,null);
  assert.equal(JSON.parse(logs[1]).routeId,null);
  assert.deepEqual({...JSON.parse(logs[2]),at:'redacted'},{
   type:'firewall.shadow.request',at:'redacted',method:'POST',status:503,client:'activity',routeId:'japan-holidays'});
 }finally{await new Promise(resolve=>app.server.close(resolve));}
});
test('audit callback failure cannot change an otherwise safe denial',async()=>{
 const app=createGatewayServer({env:{},auditSink:()=>{throw Error('log downstream unavailable');}});
 await new Promise(resolve=>app.server.listen(0,'127.0.0.1',resolve));
 try{
  const response=await fetch('http://127.0.0.1:'+app.server.address().port+'/api/v1/shadow/probe');
  assert.equal(response.status,405);
  assert.equal((await response.json()).reason,'method-not-allowed');
 }finally{await new Promise(resolve=>app.server.close(resolve));}
});
