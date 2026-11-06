import test from 'node:test';
import assert from 'node:assert/strict';
import {randomBytes} from 'node:crypto';
import {createGatewayServer} from '../server.mjs';
import {signHeaders} from '../auth.mjs';
import {parseAssistantCommand,buildInstruction,ASSISTANT_PATH} from '../assistant.mjs';

const PROVIDER_KEY='test-provider-key-not-real-000000';
async function start(env,fetchImpl,logs=[]){
 const app=createGatewayServer({env,fetchImpl,auditSink:line=>logs.push(line)});
 await new Promise(resolve=>app.server.listen(0,'127.0.0.1',resolve));
 return {app,origin:'http://127.0.0.1:'+app.server.address().port,logs};
}
const stop=app=>new Promise(resolve=>app.server.close(resolve));
const post=(origin,body,headers)=>fetch(origin+ASSISTANT_PATH,{method:'POST',
 headers:{'content-type':'application/json',...headers},body});

test('assistant route is OFF by default even with a valid signature',async()=>{
 const key=randomBytes(32);let calls=0;
 const {app,origin}=await start({FIREWALL_CLIENT_KEYS_JSON:JSON.stringify({seneschal:key.toString('base64url')})},
  async()=>{calls++;throw Error('must not call provider');});
 try{
  const body=JSON.stringify({characterId:'matsuko',question:'今日の予定は？'});
  const r=await post(origin,body,signHeaders({client:'seneschal',key,body,path:ASSISTANT_PATH}));
  assert.equal(r.status,503);
  assert.equal((await r.json()).reason,'assistant-disabled');
  const status=await (await fetch(origin+'/api/status')).json();
  assert.equal(status.assistantEnabled,false);
  assert.equal(calls,0);
 }finally{await stop(app);}
});

test('enabled flag without a provider key stays OFF',async()=>{
 const key=randomBytes(32);
 const {app,origin}=await start({FIREWALL_CLIENT_KEYS_JSON:JSON.stringify({activity:key.toString('base64url')}),
  FIREWALL_ASSISTANT_ENABLED:'true'},async()=>{throw Error('no');});
 try{
  const body=JSON.stringify({characterId:'sage',question:'q'});
  const r=await post(origin,body,signHeaders({client:'activity',key,body,path:ASSISTANT_PATH}));
  assert.equal(r.status,503);
 }finally{await stop(app);}
});

test('signed request is answered with the requested character, provider key stays server-side',async()=>{
 const key=randomBytes(32);const seen=[];
 const fetchImpl=async(url,init)=>{
  seen.push({url,init});
  return Response.json({candidates:[{content:{parts:[{text:'要点から話すわ。'}]}}]});
 };
 const logs=[];
 const {app,origin}=await start({FIREWALL_CLIENT_KEYS_JSON:JSON.stringify({fleet:key.toString('base64url')}),
  FIREWALL_ASSISTANT_ENABLED:'true',FIREWALL_ASSISTANT_GEMINI_KEY:PROVIDER_KEY},fetchImpl,logs);
 try{
  const body=JSON.stringify({characterId:'matsuko',question:'車両の状態は？',locale:'ja',
   persona:'率直で温かい。核心を一つ示す。',screen:'fleet/overview'});
  const r=await post(origin,body,signHeaders({client:'fleet',key,body,path:ASSISTANT_PATH}));
  assert.equal(r.status,200);
  const data=await r.json();
  assert.equal(data.ok,true);assert.equal(data.characterId,'matsuko');assert.equal(data.client,'fleet');
  assert.equal(data.answer,'要点から話すわ。');
  assert.doesNotMatch(JSON.stringify(data),new RegExp(PROVIDER_KEY));
  assert.equal(seen.length,1);
  assert.match(seen[0].url,/^https:\/\/generativelanguage\.googleapis\.com\/v1beta\/models\//);
  assert.equal(seen[0].init.headers['x-goog-api-key'],PROVIDER_KEY);
  assert.equal(seen[0].init.redirect,'manual');
  const sent=JSON.parse(seen[0].init.body);
  assert.match(sent.systemInstruction.parts[0].text,/matsuko/);
  assert.match(sent.systemInstruction.parts[0].text,/率直で温かい/);
  assert.equal(sent.contents[0].parts[0].text,'車両の状態は？');
  const record=JSON.parse(logs.at(-1));
  assert.deepEqual(Object.keys(record).sort(),['at','characterId','client','method','status','type']);
  assert.equal(record.status,200);
  assert.doesNotMatch(logs.join('\n'),/車両の状態|要点から|率直|x-fw-signature|test-provider-key/);
 }finally{await stop(app);}
});

test('assistant route keeps deny-by-default boundaries',async()=>{
 const key=randomBytes(32);let calls=0;
 const fetchImpl=async()=>{calls++;return Response.json({candidates:[{content:{parts:[{text:'x'}]}}]});};
 const {app,origin}=await start({FIREWALL_CLIENT_KEYS_JSON:JSON.stringify({urban:key.toString('base64url')}),
  FIREWALL_ASSISTANT_ENABLED:'true',FIREWALL_ASSISTANT_GEMINI_KEY:PROVIDER_KEY},fetchImpl);
 try{
  const body=JSON.stringify({characterId:'sage',question:'q'});
  const sign=(b=body,extra={})=>signHeaders({client:'urban',key,body:b,path:ASSISTANT_PATH,...extra});
  assert.equal((await post(origin,body,{})).status,401);
  assert.equal((await post(origin,body,{...sign(),origin:'https://evil.example'})).status,403);
  assert.equal((await post(origin,body,{...sign(),cookie:'a=b'})).status,403);
  // A signature for the probe path cannot be replayed on the assistant path.
  assert.equal((await post(origin,body,signHeaders({client:'urban',key,body}))).status,401);
  const once=sign();
  assert.equal((await post(origin,body,once)).status,200);
  assert.equal((await post(origin,body,once)).status,409);
  const extraKey=JSON.stringify({characterId:'sage',question:'q',url:'https://x'});
  assert.equal((await post(origin,extraKey,sign(extraKey))).status,400);
  const big=JSON.stringify({characterId:'sage',question:'あ'.repeat(1201)});
  assert.equal((await post(origin,big,sign(big))).status,400);
  const huge='x'.repeat(5000);
  assert.equal((await post(origin,huge,sign(huge))).status,413);
  assert.equal((await fetch(origin+ASSISTANT_PATH)).status,405);
  assert.equal(calls,1);
 }finally{await stop(app);}
});

test('per-client budget and provider failure are explicit errors',async()=>{
 const key=randomBytes(32);let fail=false;
 const fetchImpl=async()=>fail?new Response('no',{status:500}):
  Response.json({candidates:[{content:{parts:[{text:'ok'}]}}]});
 const {app,origin}=await start({FIREWALL_CLIENT_KEYS_JSON:JSON.stringify({simulator:key.toString('base64url')}),
  FIREWALL_ASSISTANT_ENABLED:'true',FIREWALL_ASSISTANT_GEMINI_KEY:PROVIDER_KEY},fetchImpl);
 try{
  const body=JSON.stringify({characterId:'strategist',question:'q'});
  const ask=()=>post(origin,body,signHeaders({client:'simulator',key,body,path:ASSISTANT_PATH}));
  fail=true;
  const broken=await ask();
  assert.equal(broken.status,502);
  assert.equal((await broken.json()).reason,'assistant-provider-unavailable');
  fail=false;
  for(let i=0;i<5;i++)assert.equal((await ask()).status,200);
  const limited=await ask();
  assert.equal(limited.status,429);
  assert.equal(limited.headers.get('retry-after'),'60');
 }finally{await stop(app);}
});

test('command parser and instruction keep the character identity',()=>{
 assert.equal(parseAssistantCommand('{').reason,'invalid-json');
 assert.equal(parseAssistantCommand('[]').ok,false);
 assert.equal(parseAssistantCommand(JSON.stringify({characterId:'Bad_ID',question:'q'})).ok,false);
 assert.equal(parseAssistantCommand(JSON.stringify({characterId:'sage',question:'q',locale:'fr'})).ok,false);
 const ok=parseAssistantCommand(JSON.stringify({characterId:'store-conan',question:' 手がかりは？ ',locale:'en'}));
 assert.equal(ok.ok,true);assert.equal(ok.command.question,'手がかりは？');
 const text=buildInstruction({client:'service',...ok.command});
 assert.match(text,/store-conan/);assert.match(text,/English/);assert.match(text,/Never invent numbers/);
});

test('client registry advertises the assistant contract without secrets',async()=>{
 const {app,origin}=await start({},async()=>{throw Error('no');});
 try{
  const data=await (await fetch(origin+'/api/clients')).json();
  assert.equal(data.assistant.path,ASSISTANT_PATH);
  assert.equal(data.assistant.enabled,false);
  assert.equal(data.assistant.providerKeyInBrowser,false);
  assert.ok(data.clients.some(c=>c.id==='administration'));
 }finally{await stop(app);}
});
