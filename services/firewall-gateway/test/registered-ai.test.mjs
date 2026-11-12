import test from 'node:test';
import assert from 'node:assert/strict';
import {randomBytes} from 'node:crypto';
import {createRegisteredAi,parseRegisteredAiCommand,REGISTERED_AI_PROVIDERS} from '../registeredAi.mjs';
import {createGatewayServer,probeRegisteredAiOnce} from '../server.mjs';
import {signHeaders} from '../auth.mjs';

const key='test-provider-credential-not-a-real-key';
const setup=(id,extra={})=>({FIREWALL_REGISTERED_AI_ENABLED:'true',
 ['FIREWALL_REGISTERED_AI_'+id.toUpperCase()+'_ENABLED']:'true',
 ['FIREWALL_REGISTERED_AI_'+id.toUpperCase()+'_FREE_TIER_CONFIRMED']:'true',
 [REGISTERED_AI_PROVIDERS[id].key]:key,...extra});
const command=(provider='groq',role='summarize')=>({provider,role,messages:[{role:'user',content:'Reply OK'}],maxTokens:1024});
const response=text=>new Response(JSON.stringify({choices:[{message:{content:text}}]}),{headers:{'content-type':'application/json'}});

test('keys alone cannot enable registered providers; unverified tiers do not send a request',async()=>{
 let calls=0;
 for(const env of [{GROQ_API_KEY:key},setup('groq',{FIREWALL_REGISTERED_AI_GROQ_FREE_TIER_CONFIRMED:'false'})]){
  const ai=createRegisteredAi({env,fetchImpl:async()=>{calls++;return response('OK');}});
  assert.equal((await ai.chat('federation',command())).result.error,'registered-ai-disabled');
 }
 assert.equal(calls,0);
});
test('all seven fixed hosts receive only their own credential; no keys in status or answers',async()=>{
 for(const id of Object.keys(REGISTERED_AI_PROVIDERS)){
  const ai=createRegisteredAi({env:setup(id,{CLOUDFLARE_ACCOUNT_ID:'a'.repeat(32)}),fetchImpl:async(url,init)=>{
   assert.equal(init.redirect,'manual');assert.equal(init.credentials,'omit');
   if(id==='gemini'){
    assert.equal(init.headers['x-goog-api-key'],key);
    assert.equal(init.headers.Authorization,undefined);
    assert.ok(url.endsWith('/models/gemini-2.5-flash:generateContent'));
   }else assert.equal(init.headers.Authorization,'Bearer '+key);
   assert.equal(url.includes(key),false);
   const body=JSON.parse(init.body);
   if(id==='openrouter'){
    assert.ok(body.model.endsWith(':free'));assert.deepEqual(body.provider.max_price,{prompt:0,completion:0});
   }
   return id==='gemini'?Response.json({candidates:[{content:{parts:[{text:'OK '+key}]}}]})
    :id==='cloudflare'?Response.json({result:{response:'OK '+key}}):response('OK '+key);
  }});
  const result=await ai.chat('federation',command(id));
  assert.equal(result.status,200,id);assert.equal(result.result.text.includes(key),false);
  assert.equal(JSON.stringify(ai.info()).includes(key),false);
 }
});
test('Gemini native request maps roles, excludes thinking text and reports only numeric upstream status',async()=>{
 const ai=createRegisteredAi({env:setup('gemini'),fetchImpl:async(url,init)=>{
  const body=JSON.parse(init.body);
  assert.deepEqual(body.systemInstruction,{parts:[{text:'Be concise'}]});
  assert.deepEqual(body.contents.map(m=>m.role),['user','model','user']);
  assert.deepEqual(body.generationConfig,{maxOutputTokens:1024,thinkingConfig:{thinkingBudget:0}});
  return Response.json({candidates:[{content:{parts:[{thought:true,text:'hidden thought'},{text:'OK'}]}}]});
 }});
 const c=command('gemini');c.messages=[{role:'system',content:'Be concise'},{role:'user',content:'Hi'},
  {role:'assistant',content:'Hello'},{role:'user',content:'Reply OK'}];
 const r=await ai.chat('federation',c);
 assert.equal(r.result.text,'OK');assert.equal(ai.info().providers.find(p=>p.id==='gemini').lastHttpStatus,200);
 const failed=createRegisteredAi({env:setup('gemini'),fetchImpl:async()=>Response.json({error:{message:key,status:'UNAUTHENTICATED'}},{status:401})});
 const denial=await failed.chat('federation',command('gemini'));
 assert.equal(denial.result.error,'provider-auth-or-budget-refused');
 assert.equal(failed.info().providers.find(p=>p.id==='gemini').lastHttpStatus,401);
 assert.equal(failed.info().providers.find(p=>p.id==='gemini').lastErrorStatus,'UNAUTHENTICATED');
 assert.equal(JSON.stringify([denial,failed.info()]).includes(key),false);
});
test('startup probe defaults off and performs only one fixed bounded call when opted in',async()=>{
 let calls=0;const logs=[];
 const ai={chat:async(client,c)=>{
  calls++;assert.equal(client,'federation');assert.equal(c.provider,'gemini');
  assert.equal(c.role,'summarize');assert.equal(c.maxTokens,256);
  assert.deepEqual(c.messages,[{role:'user',content:'Reply with the single word OK.'}]);
  return {status:200,result:{ok:true,text:key}};
 },info:()=>({providers:[{id:'gemini',lastHttpStatus:200}]})};
 assert.equal(await probeRegisteredAiOnce(ai,{},s=>logs.push(s)),null);
 assert.equal(await probeRegisteredAiOnce(ai,{FIREWALL_REGISTERED_AI_PROBE_ON_START:'https://evil.example'},s=>logs.push(s)),null);
 assert.equal(calls,0);
 const r=await probeRegisteredAiOnce(ai,{FIREWALL_REGISTERED_AI_PROBE_ON_START:'gemini'},s=>logs.push(s));
 assert.equal(r.ok,true);assert.equal(r.upstreamHttpStatus,200);assert.equal(calls,1);
 assert.equal(JSON.stringify(logs).includes(key),false);
 const failure=await probeRegisteredAiOnce({chat:async()=>{throw Error(key);}},
  {FIREWALL_REGISTERED_AI_PROBE_ON_START:'gemini'},()=>{throw Error('sink-down');});
 assert.equal(failure.error,'probe-failed');assert.equal(JSON.stringify(failure).includes(key),false);
});
test('privacy defaults block code and contact data; Gemini/Mistral cannot override training restriction',async()=>{
 let calls=0;
 for(const id of Object.keys(REGISTERED_AI_PROVIDERS)){
  const ai=createRegisteredAi({env:setup(id,{CLOUDFLARE_ACCOUNT_ID:'a'.repeat(32)}),fetchImpl:async()=>{calls++;return response('OK');}});
  assert.equal((await ai.chat('federation',command(id,'implement'))).status,400);
  const personal=command(id);personal.messages[0].content='Contact person@example.com';
  assert.equal((await ai.chat('federation',personal)).status,400);
 }
 for(const id of ['gemini','mistral']){
  const ai=createRegisteredAi({env:setup(id,{['FIREWALL_REGISTERED_AI_'+id.toUpperCase()+'_PRIVATE_PROCESSING_CONFIRMED']:'true'})});
  assert.equal((await ai.chat('federation',command(id,'review'))).status,400);
 }
 assert.equal(calls,0);
});
test('provider/model injection rejected and existing parser limits retained',()=>{
 assert.equal(parseRegisteredAiCommand(JSON.stringify({...command(),model:'paid/model'})).ok,false);
 assert.equal(parseRegisteredAiCommand(JSON.stringify({...command(),url:'https://evil.example'})).ok,false);
 assert.equal(parseRegisteredAiCommand(JSON.stringify(command('__proto__'))).ok,false);
 assert.equal(parseRegisteredAiCommand(JSON.stringify(command(['groq']))).ok,false);
 const large=command();large.messages[0].content='x'.repeat(24001);
 assert.equal(parseRegisteredAiCommand(JSON.stringify(large)).ok,false);
});
test('auth/budget failure stops calls and positive reported cost stops the lane',async()=>{
 for(const make of [()=>new Response('{}',{status:402}),()=>Response.json({usage:{cost:1}})]){
  let calls=0;
  const ai=createRegisteredAi({env:setup('groq'),fetchImpl:async()=>{calls++;return make();}});
  assert.equal((await ai.chat('federation',command())).status,503);
  assert.equal((await ai.chat('federation',command())).result.error,'provider-stopped');
  assert.equal(calls,1);
 }
});
test('minute/day ceilings and concurrency prevent excess provider calls',async()=>{
 let now=0,calls=0;
 const ai=createRegisteredAi({env:setup('groq'),clock:()=>now,fetchImpl:async()=>{calls++;return response('OK');}});
 for(let n=0;n<25;n++){now=n*61000;assert.equal((await ai.chat('federation',command())).status,200);}
 now+=61000;assert.equal((await ai.chat('federation',command())).status,429);assert.equal(calls,25);
 let release;
 const busy=createRegisteredAi({env:setup('groq'),fetchImpl:()=>new Promise(resolve=>{release=resolve;})});
 const first=busy.chat('federation',command());
 assert.equal((await busy.chat('federation',command())).status,429);
 release(response('OK'));assert.equal((await first).status,200);
});
test('registered calls use the existing signed gateway boundary',async()=>{
 const signing=randomBytes(32),now=Date.now();let calls=0;
 const app=createGatewayServer({clock:()=>now,auditSink:()=>{},env:{...setup('groq'),
  FIREWALL_FREE_AI_FEDERATION_KEY:signing.toString('base64url')},fetchImpl:async()=>{calls++;return response('OK');}});
 await new Promise(resolve=>app.server.listen(0,'127.0.0.1',resolve));
 const origin='http://127.0.0.1:'+app.server.address().port,path='/api/v1/free-ai/chat',body=JSON.stringify(command());
 try{
  const headers={'content-type':'application/json'};
  assert.equal((await fetch(origin+path,{method:'POST',headers,body})).status,401);
  const signed=signHeaders({client:'federation',key:signing,body,path,time:now});
  assert.equal((await fetch(origin+path,{method:'POST',headers:{...headers,...signed,origin:'https://evil.example'},body})).status,403);
  const result=await fetch(origin+path,{method:'POST',headers:{...headers,...signed},body});
  assert.equal(result.status,200);assert.equal((await result.json()).provider,'groq');assert.equal(calls,1);
 }finally{await new Promise(resolve=>app.server.close(resolve));}
});

test('Groq uses the free-plan-listed fixed model and bounded reasoning request',async()=>{
 let sent;
 const ai=createRegisteredAi({env:setup('groq'),fetchImpl:async(url,init)=>{sent=JSON.parse(init.body);assert.equal(url,'https://api.groq.com/openai/v1/chat/completions');return response('OK');}});
 const r=await ai.chat('federation',{...command('groq'),maxTokens:256});
 assert.equal(r.status,200);assert.equal(r.result.model,'openai/gpt-oss-20b');
 assert.equal(sent.model,'openai/gpt-oss-20b');assert.equal(sent.max_completion_tokens,256);assert.equal(sent.max_tokens,undefined);assert.equal(sent.reasoning_effort,'low');
 assert.equal(ai.info().providers.find(p=>p.id==='groq').requestsToday,1);
});


test('OpenRouter pins a current free model and rejects paid endpoint fallback',async()=>{
 let sent;
 const ai=createRegisteredAi({env:setup('openrouter'),fetchImpl:async(_url,options)=>{sent=JSON.parse(options.body);return Response.json({choices:[{message:{content:'OK'}}],usage:{cost:0}});}});
 const result=await ai.chat('federation',{provider:'openrouter',role:'summarize',messages:[{role:'user',content:'Reply OK.'}],maxTokens:256});
 assert.equal(result.status,200);
 assert.equal(sent.model,'liquid/lfm-2.5-2.6b:free');
 assert.equal(sent.max_tokens,256);
 assert.deepEqual(sent.provider,{max_price:{prompt:0,completion:0},allow_fallbacks:false});
 assert.deepEqual(sent.reasoning,{enabled:false});
});


test('NVIDIA pins the current NVIDIA-hosted model and bounds output',async()=>{
 let sent;
 const ai=createRegisteredAi({env:setup('nvidia'),fetchImpl:async(url,options)=>{assert.equal(url,'https://integrate.api.nvidia.com/v1/chat/completions');sent=JSON.parse(options.body);return response('OK');}});
 const result=await ai.chat('federation',{...command('nvidia'),maxTokens:256});
 assert.equal(result.status,200);
 assert.equal(sent.model,'nvidia/nemotron-3.5-lightning-30b-a3b');
 assert.equal(sent.max_tokens,256);
 assert.equal(result.result.model,sent.model);
});
