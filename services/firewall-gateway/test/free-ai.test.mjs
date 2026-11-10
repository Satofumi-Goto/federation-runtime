import test from 'node:test';
import assert from 'node:assert/strict';
import {randomBytes} from 'node:crypto';
import {createGatewayServer} from '../server.mjs';
import {signHeaders} from '../auth.mjs';
import {FREE_AI_PATH,FREE_AI_PROVIDERS,FREE_AI_POLICY,loadFreeAiConfig,parseFreeAiCommand,createFreeAi,HORDE_ANONYMOUS_KEY} from '../freeAi.mjs';

const NOW=Date.parse('2026-11-10T08:30:00.000Z');
const key=randomBytes(32).toString('base64url');
const env=(over={})=>({FIREWALL_CLIENT_KEYS_JSON:JSON.stringify({federation:key,seneschal:key}),
 FIREWALL_FREE_AI_ENABLED:'true',...over});
const ask=(role='reply-advice',extra={})=>JSON.stringify({role,messages:[{role:'user',content:'Reply OK'}],...extra});
const ok=text=>new Response(JSON.stringify({choices:[{message:{role:'assistant',content:text}}]}),
 {status:200,headers:{'content-type':'application/json'}});

async function withGateway(options,run){
 const app=createGatewayServer({clock:()=>NOW,auditSink:()=>{},...options});
 await new Promise(resolve=>app.server.listen(0,'127.0.0.1',resolve));
 const origin='http://127.0.0.1:'+app.server.address().port;
 try{await run(origin,app);}finally{await new Promise(resolve=>app.server.close(resolve));}
}
async function post(origin,body,{client='federation',headers={}}={}){
 const signed=signHeaders({client,key:Buffer.from(key,'base64url'),body,path:FREE_AI_PATH,time:NOW});
 const response=await fetch(origin+FREE_AI_PATH,{method:'POST',body,
  headers:{'content-type':'application/json',...signed,...headers}});
 return {status:response.status,data:await response.json()};
}
const recorder=handler=>{
 const calls=[];
 const fetchImpl=async(url,init)=>{
  if(!String(url).startsWith('https://'))return fetch(url,init);
  calls.push({url:String(url),headers:init.headers,body:JSON.parse(init.body)});
  return handler(String(url),calls.length);
 };
 return {calls,fetchImpl};
};

test('only keyless providers are listed and none of them takes a key',()=>{
 assert.deepEqual(Object.keys(FREE_AI_PROVIDERS).sort(),['blockrun','horde','kilo','llm7','mlvoca','ovh','pollinations']);
 assert.equal(FREE_AI_POLICY.keyless,true);
 assert.equal(FREE_AI_POLICY.credentialsStoredOrForwarded,false);
 assert.equal(FREE_AI_POLICY.defaultEnabled,false);
 for(const p of FREE_AI_POLICY.providers)assert.equal(p.codeRolesAllowed,!p.publicPrompts);
});

test('relay stays OFF unless explicitly enabled; models and clients are validated',()=>{
 assert.equal(loadFreeAiConfig({}).enabled,false);
 assert.equal(loadFreeAiConfig(env()).enabled,true);
 assert.deepEqual([...loadFreeAiConfig(env()).clients],['federation']);
 assert.equal(loadFreeAiConfig(env({FIREWALL_FREE_AI_CLIENT_IDS:'unknown'})).reason,'clients-invalid');
 assert.equal(loadFreeAiConfig(env({FIREWALL_FREE_AI_PROVIDERS:'ovh,openai'})).reason,'providers-invalid');
 assert.equal(loadFreeAiConfig(env({FIREWALL_FREE_AI_KILO_MODEL:'paid/model'})).reason,'model-invalid');
 assert.equal(loadFreeAiConfig(env({FIREWALL_FREE_AI_KILO_MODEL:'qwen/qwen3-coder:free'})).models.kilo,'qwen/qwen3-coder:free');
});

test('command parser rejects unknown fields, roles, providers and oversize prompts',()=>{
 assert.equal(parseFreeAiCommand(ask()).ok,true);
 assert.equal(parseFreeAiCommand(ask('deploy')).error,'invalid-role');
 assert.equal(parseFreeAiCommand(ask('summarize',{provider:'openai'})).error,'invalid-provider');
 assert.equal(parseFreeAiCommand(ask('summarize',{url:'https://evil.example'})).error,'invalid-request');
 assert.equal(parseFreeAiCommand(ask('summarize',{model:'x'})).error,'invalid-model');
 assert.equal(parseFreeAiCommand(ask('summarize',{provider:'kilo',model:'paid/model'})).error,'invalid-model');
 assert.equal(parseFreeAiCommand(JSON.stringify({role:'summarize',messages:[{role:'user',content:'x'.repeat(24001)}]})).error,'invalid-messages');
 assert.equal(parseFreeAiCommand(JSON.stringify({role:'summarize',messages:[{role:'system',content:'only system'}]})).error,'invalid-messages');
 assert.equal(parseFreeAiCommand(ask('summarize',{maxTokens:4096})).error,'invalid-max-tokens');
});

test('unsigned, browser and disabled requests never reach a provider',async()=>{
 const {calls,fetchImpl}=recorder(()=>ok('OK'));
 await withGateway({env:env(),fetchImpl},async origin=>{
  const unsigned=await fetch(origin+FREE_AI_PATH,{method:'POST',headers:{'content-type':'application/json'},body:ask()});
  assert.equal(unsigned.status,401);
  assert.equal((await post(origin,ask(),{headers:{origin:'https://evil.example'}})).status,403);
  assert.equal((await post(origin,ask(),{client:'seneschal'})).data.error,'client-not-allowed');
 });
 await withGateway({env:env({FIREWALL_FREE_AI_ENABLED:'false'}),fetchImpl},async origin=>{
  assert.equal((await post(origin,ask())).data.error,'free-ai-disabled');
 });
 assert.equal(calls.length,0);
});

test('anonymous call: no Authorization header, first answer wins, fallback on 429',async()=>{
 const {calls,fetchImpl}=recorder(url=>url.includes('ovh')?new Response('{}',{status:429}):ok('OK from llm7'));
 await withGateway({env:env(),fetchImpl},async origin=>{
  const res=await post(origin,ask('summarize'));
  assert.equal(res.status,200);
  assert.equal(res.data.provider,'llm7');
  assert.equal(res.data.paidCalls,0);
  assert.deepEqual(res.data.attempts.map(a=>a.provider),['ovh','llm7']);
 });
 assert.equal(calls.length,2);
 for(const c of calls){
  assert.equal(Object.keys(c.headers).some(h=>/authorization|api-?key/i.test(h)),false);
  assert.equal(c.body.stream,false);
 }
});

test('code roles never go to providers that may log prompts',async()=>{
 const {calls,fetchImpl}=recorder(()=>ok('diff'));
 await withGateway({env:env(),fetchImpl},async origin=>{
  const res=await post(origin,ask('implement'));
  assert.equal(res.data.provider,'ovh');
  assert.equal((await post(origin,ask('review',{provider:'kilo'}))).data.error,'provider-not-allowed-for-role');
 });
 assert.ok(calls.every(c=>c.url.includes('ovh')));
});

test('per-minute ceiling, paid-usage signal and status endpoint',async()=>{
 const {calls,fetchImpl}=recorder(url=>url.includes('kilo')
  ?new Response(JSON.stringify({choices:[{message:{content:'x'}}],usage:{cost:0.01}}),{status:200,headers:{'content-type':'application/json'}})
  :ok('OK'));
 await withGateway({env:env(),fetchImpl},async origin=>{
  assert.equal((await post(origin,ask('implement'))).status,200);
  assert.equal((await post(origin,ask('implement'))).status,200);
  const third=await post(origin,ask('implement'));
  assert.equal(third.status,429);
  assert.equal(third.data.error,'rate-limited');
  const paid=await post(origin,ask('summarize',{provider:'kilo'}));
  assert.equal(paid.status,503);
  assert.equal(paid.data.attempts[0].failed,'paid-usage-reported');
  const again=await post(origin,ask('summarize',{provider:'kilo'}));
  assert.equal(again.data.attempts[0].skipped,'stopped-today');
  const status=await (await fetch(origin+'/api/free-ai')).json();
  assert.equal(status.enabled,true);
  assert.equal(status.usageToday.ovh,2);
  assert.equal(JSON.stringify(status).includes(key),false);
 });
 assert.equal(calls.filter(c=>c.url.includes('ovh')).length,2);
});

test('dedicated FIREWALL_FREE_AI_FEDERATION_KEY works without FIREWALL_CLIENT_KEYS_JSON and only for free AI',async()=>{
 const dedicated=randomBytes(32).toString('base64url');
 const {calls,fetchImpl}=recorder(()=>ok('OK'));
 await withGateway({env:{FIREWALL_FREE_AI_ENABLED:'true',FIREWALL_FREE_AI_FEDERATION_KEY:dedicated},fetchImpl},async origin=>{
  const body=ask('summarize');
  const signed=signHeaders({client:'federation',key:Buffer.from(dedicated,'base64url'),body,path:FREE_AI_PATH,time:NOW});
  const res=await fetch(origin+FREE_AI_PATH,{method:'POST',body,headers:{'content-type':'application/json',...signed}});
  assert.equal(res.status,200);
  const wrong=signHeaders({client:'federation',key:randomBytes(32),body,path:FREE_AI_PATH,time:NOW});
  assert.equal((await fetch(origin+FREE_AI_PATH,{method:'POST',body,headers:{'content-type':'application/json',...wrong}})).status,401);
  const probeBody='{"routeId":"japan-holidays"}';
  const probe=signHeaders({client:'federation',key:Buffer.from(dedicated,'base64url'),body:probeBody,time:NOW});
  const other=await fetch(origin+'/api/v1/shadow/probe',{method:'POST',body:probeBody,headers:{'content-type':'application/json',...probe}});
  assert.equal(other.status,503);
 });
 assert.equal(calls.length,1);
});
const cmd=(role='reply-advice',provider)=>({role,provider,maxTokens:64,messages:[{role:'user',content:'Reply OK'}]});
const json=(status,data)=>new Response(JSON.stringify(data),{status,headers:{'content-type':'application/json'}});

test('BlockRun accepts only its free models and sends no payment or auth header',async()=>{
 assert.equal(loadFreeAiConfig({FIREWALL_FREE_AI_ENABLED:'true',FIREWALL_FREE_AI_BLOCKRUN_MODEL:'openai/gpt-5'}).reason,'model-invalid');
 const calls=[];
 const ai=createFreeAi({env:{FIREWALL_FREE_AI_ENABLED:'true',FIREWALL_FREE_AI_PROVIDERS:'blockrun'},clock:()=>NOW,
  fetchImpl:async(url,init)=>{calls.push({url,init});return json(200,{choices:[{message:{content:'OK'}}]});}});
 const r=await ai.chat('federation',cmd());
 assert.equal(r.status,200);assert.equal(r.result.provider,'blockrun');
 assert.equal(calls[0].url,'https://blockrun.ai/api/v1/chat/completions');
 assert.equal(JSON.parse(calls[0].init.body).model,'nvidia/nemotron-3-super-120b');
 for(const h of Object.keys(calls[0].init.headers))assert.ok(!/authorization|payment|x402/i.test(h),h);
});

test('AI Horde: anonymous submit, poll until done, never for code roles',async()=>{
 const calls=[];let polls=0;
 const ai=createFreeAi({env:{FIREWALL_FREE_AI_ENABLED:'true',FIREWALL_FREE_AI_PROVIDERS:'horde'},clock:()=>NOW,sleep:async()=>{},
  fetchImpl:async(url,init)=>{calls.push({url,method:init.method,headers:init.headers});
   if(init.method==='POST')return json(202,{id:'job-1234abcd'});
   polls++;return json(200,polls<2?{done:false,is_possible:true}:{done:true,generations:[{text:' OK ',model:'qwen3.8-27b-int4'}]});}});
 const r=await ai.chat('federation',cmd());
 assert.equal(r.status,200);assert.equal(r.result.text,'OK');
 assert.equal(calls[0].url,'https://aihorde.net/api/v2/generate/text/async');
 assert.equal(calls[0].headers.apikey,HORDE_ANONYMOUS_KEY);
 assert.ok(calls[1].url.endsWith('/generate/text/status/job-1234abcd'));
 const code=await ai.chat('federation',cmd('implement'));
 assert.equal(code.status,400);assert.equal(code.result.error,'provider-not-allowed-for-role');
});

test('AI Horde: impossible and timed-out jobs are cancelled',async()=>{
 let t=NOW;const methods=[];
 const make=state=>createFreeAi({env:{FIREWALL_FREE_AI_ENABLED:'true',FIREWALL_FREE_AI_PROVIDERS:'horde'},clock:()=>t,
  sleep:async()=>{t+=20000;},fetchImpl:async(url,init)=>{methods.push(init.method);
   return init.method==='POST'?json(202,{id:'job-1234abcd'}):json(200,state);}});
 let r=await make({done:false,is_possible:false}).chat('federation',cmd());
 assert.equal(r.status,503);assert.ok(methods.includes('DELETE'));
 methods.length=0;
 r=await make({done:false,is_possible:true}).chat('federation',cmd());
 assert.equal(r.status,503);assert.deepEqual(r.result.attempts[0],{provider:'horde',failed:'timeout-cancelled'});
 assert.equal(methods.at(-1),'DELETE');
});

test('Pollinations classic: GET with the prompt in the path, no key, plain-text answer',async()=>{
 const calls=[];
 const ai=createFreeAi({env:{FIREWALL_FREE_AI_ENABLED:'true',FIREWALL_FREE_AI_PROVIDERS:'pollinations'},clock:()=>NOW,
  fetchImpl:async(url,init)=>{calls.push({url,init});return new Response('OK',{status:200,headers:{'content-type':'text/plain'}});}});
 const r=await ai.chat('federation',cmd());
 assert.equal(r.status,200);assert.equal(r.result.text,'OK');
 assert.ok(calls[0].url.startsWith('https://text.pollinations.ai/Reply%20OK?model=openai'));
 assert.equal(calls[0].init.method,'GET');
 for(const h of Object.keys(calls[0].init.headers))assert.ok(!/authorization/i.test(h));
 const long=await ai.chat('federation',{...cmd(),messages:[{role:'user',content:'x'.repeat(2000)}]});
 assert.equal(long.status,503);assert.deepEqual(long.result.attempts.at(-1),{provider:'pollinations',failed:'prompt-too-large'});
});

test('mlvoca: Ollama generate, small models only, think block removed, never code roles',async()=>{
 assert.equal(loadFreeAiConfig({FIREWALL_FREE_AI_ENABLED:'true',FIREWALL_FREE_AI_MLVOCA_MODEL:'llama3:70b'}).reason,'model-invalid');
 const calls=[];
 const ai=createFreeAi({env:{FIREWALL_FREE_AI_ENABLED:'true',FIREWALL_FREE_AI_PROVIDERS:'mlvoca'},clock:()=>NOW,
  fetchImpl:async(url,init)=>{calls.push({url,body:JSON.parse(init.body)});return json(200,{response:'<think>hmm</think> OK',done:true});}});
 const r=await ai.chat('federation',cmd());
 assert.equal(r.result.text,'OK');assert.equal(calls[0].url,'https://mlvoca.com/api/generate');
 assert.equal(calls[0].body.model,'deepseek-r1:1.5b');assert.equal(calls[0].body.stream,false);
 assert.equal((await ai.chat('federation',cmd('review'))).result.error,'provider-not-allowed-for-role');
});
