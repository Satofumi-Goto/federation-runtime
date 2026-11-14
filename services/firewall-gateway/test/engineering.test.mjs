import test from 'node:test';
import assert from 'node:assert/strict';
import {randomBytes} from 'node:crypto';
import {createGatewayServer} from '../server.mjs';
import {signHeaders,createAuthenticator} from '../auth.mjs';
import {ENGINEERING_PATH,ENGINEERING_CATALOG,ENGINEERING_UPSTREAM,ENGINEERING_UPSTREAM_PATH,parseEngineeringCommand,createEngineeringRelay} from '../engineering.mjs';
const key=randomBytes(32),other=randomBytes(32);
const packet={service:'simulation',request:ENGINEERING_CATALOG.find(x=>x.id==='unit-conversion').example};
async function app({env={},fetchImpl=async()=>{throw Error('unexpected egress');}}={},run){
 const logs=[];const a=createGatewayServer({env:{FIREWALL_CLIENT_KEYS_JSON:JSON.stringify({federation:key.toString('base64url'),activity:other.toString('base64url')}),...env},fetchImpl,auditSink:x=>logs.push(JSON.parse(x))});
 await new Promise(resolve=>a.server.listen(0,'127.0.0.1',resolve));
 const root='http://127.0.0.1:'+a.server.address().port;
 const signed=(value=packet,extra={},client='federation')=>{
  const body=JSON.stringify(value);
  return fetch(root+ENGINEERING_PATH,{method:'POST',headers:{'content-type':'application/json',...signHeaders({client,key:client==='federation'?key:other,path:ENGINEERING_PATH,body}),...extra},body});
 };
 try{await run({root,signed,logs});}finally{await new Promise(resolve=>a.server.close(resolve));}
}
test('13 fixed free engineering operations have executable example packets; no runtime readiness claim',async()=>{
 assert.equal(ENGINEERING_CATALOG.length,13);
 for(const x of ENGINEERING_CATALOG)assert.deepEqual(parseEngineeringCommand(JSON.stringify({service:x.service,request:x.example})),{service:x.service,request:x.example});
 await app({},async({root})=>{
  const catalog=await(await fetch(root+'/api/engineering')).json();
  assert.equal(catalog.operations.length,13);assert.equal(catalog.gatewayRoundTripVerified,false);
  assert.equal(catalog.keyConfigured,true);assert.equal(catalog.arbitraryDestinationAllowed,false);
  assert.equal((await(await fetch(root+'/api/catalog')).json()).engineering.operations.length,13);
 });
});
test('signed request is re-signed only to fixed engineering backend; response artifact preserved, no cookie or auth forwarded',async()=>{
 let calls=0;
 await app({fetchImpl:async(url,init)=>{
  calls++;assert.equal(url,ENGINEERING_UPSTREAM+ENGINEERING_UPSTREAM_PATH);assert.equal(init.redirect,'manual');
  assert.equal(init.headers.cookie,undefined);assert.equal(init.headers.authorization,undefined);
  assert.equal(createAuthenticator({env:{FIREWALL_CLIENT_KEYS_JSON:JSON.stringify({federation:key.toString('base64url')})}}).verify({headers:init.headers,method:'POST'},init.body,ENGINEERING_UPSTREAM_PATH).ok,true);
  return Response.json({schema:'federation.simulation-comparison/1',comparisonOnly:true,result:{convertedValue:3600000}});
 }},async({signed,logs})=>{
  const response=await signed();assert.equal(response.status,200);assert.equal((await response.json()).result.convertedValue,3600000);
  assert.equal(calls,1);const event=logs.find(x=>x.type==='firewall.engineering.request');
  assert.equal(event.service,'simulation');assert.ok(!JSON.stringify(logs).includes('requestId'));assert.ok(!JSON.stringify(logs).includes(key.toString('base64url')));
 });
});
test('browser, unsigned, different-client, query, replay, owner/code/url and unsupported operation denied without egress',async()=>{
 let calls=0;
 await app({fetchImpl:async()=>{calls++;return Response.json({schema:'federation.simulation-comparison/1'});}},async({root,signed})=>{
  for(const extra of [{origin:'https://federation-runtime.com'},{cookie:'a=b'},{authorization:'Bearer forbidden'}])assert.equal((await signed(packet,extra)).status,403);
  assert.equal((await fetch(root+ENGINEERING_PATH,{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify(packet)})).status,401);
  assert.equal((await signed(packet,{},'activity')).status,403);
  for(const value of [{...packet,url:'https://example.com'},{...packet,ownerId:'other'},{service:'shell',request:{}},{service:'simulation',request:{...packet.request,kind:'exec'}},{service:'simulation',request:{...packet.request,input:{...packet.request.input,value:'https://example.com'}}}])assert.equal((await signed(value)).status,400);
  const body=JSON.stringify(packet),headers={'content-type':'application/json',...signHeaders({client:'federation',key,path:ENGINEERING_PATH,body})};
  assert.equal((await fetch(root+ENGINEERING_PATH+'?url=x',{method:'POST',headers,body})).status,400);
  assert.equal((await fetch(root+ENGINEERING_PATH,{method:'POST',headers,body})).status,200);
  assert.equal((await fetch(root+ENGINEERING_PATH,{method:'POST',headers,body})).status,409);
  assert.equal(calls,1);
 });
});
test('required distributed security store failure denies engineering before backend call',async()=>{
 await app({env:{FIREWALL_REQUIRE_DISTRIBUTED_STORE:'true'}},async({signed})=>assert.equal((await signed()).status,503));
});
test('upstream redirect, malformed JSON/schema, size violation and backend errors fail closed without leaking upstream body',async()=>{
 for(const make of [()=>new Response('redirect-secret',{status:302,headers:{location:'https://evil.example'}}),()=>new Response('secret',{headers:{'content-type':'application/json'}}),()=>Response.json({schema:'wrong'}),()=>new Response('{}',{headers:{'content-type':'application/json','content-length':String(11*1024*1024)}}),()=>Response.json({error:'sensitive-path-and-diagnostics'},{status:500})]){
  const relay=createEngineeringRelay({key,fetchImpl:async()=>make()});
  await assert.rejects(()=>relay.run(packet),e=>e.status===502&&!e.message.includes('secret')&&!e.message.includes('sensitive'));
 }
});
test('local engineering budget always applies, even when shared store is not required',async()=>{
 const relay=createEngineeringRelay({key,fetchImpl:async()=>Response.json({schema:'federation.simulation-comparison/1'})});
 for(let i=0;i<6;i++)await relay.run(packet);
 await assert.rejects(()=>relay.run(packet),e=>e.status===429);
});
test('existing dedicated API/Gateway key pair works when the main federation key is different',async()=>{
 const dedicated=randomBytes(32);
 const backend=createAuthenticator({env:{FIREWALL_CLIENT_KEYS_JSON:JSON.stringify({federation:dedicated.toString('base64url')})}});
 let calls=0;
 await app({env:{FIREWALL_FREE_AI_FEDERATION_KEY:dedicated.toString('base64url')},fetchImpl:async(url,init)=>{
  calls++;assert.equal(backend.verify({method:'POST',headers:init.headers},init.body,ENGINEERING_UPSTREAM_PATH).ok,true);
  return Response.json({schema:'federation.simulation-comparison/1',result:{convertedValue:3600000}});
 }},async({root,signed})=>{
  assert.equal((await signed()).status,401); // The distinct main key must not authorize this dedicated lane.
  const body=JSON.stringify(packet);
  const response=await fetch(root+ENGINEERING_PATH,{method:'POST',headers:{'Content-Type':'application/json',...signHeaders({client:'federation',key:dedicated,path:ENGINEERING_PATH,body})},body});
  assert.equal(response.status,200);assert.equal(calls,1);
 });
});
