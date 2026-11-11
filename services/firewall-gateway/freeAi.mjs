import {readBoundedJson} from './egress.mjs';
import {CLIENT_IDS} from './policy.mjs';
import {hasPersonalData,redactSecrets} from './hardening.mjs';
// Keyless free AI relay. Every provider here works WITHOUT an account or API key,
// so no credential is stored, forwarded or logged; nothing here can be billed.
// Callers are the nine signed family apps (HMAC server-to-server, no browsers).
// OFF unless FIREWALL_FREE_AI_ENABLED=true. Prompts and answers are never logged.
export const FREE_AI_PATH='/api/v1/free-ai/chat';
export const FREE_AI_MAX_BODY=65536;
// rpm/perDay are the gateway's own ceilings, set at or below each provider's
// published anonymous limit (2026-11-10, per IP). publicPrompts=true: the
// provider may log prompts, so source-code roles must never be sent there.
export const FREE_AI_PROVIDERS=Object.freeze({
 ovh:Object.freeze({name:'OVHcloud AI Endpoints (anonymous)',url:'https://oai.endpoints.kepler.ai.cloud.ovh.net/v1/chat/completions',
  model:'Qwen3.8-27B',freeModel:/^[A-Za-z0-9][A-Za-z0-9._-]{0,79}$/,rpm:2,perDay:1000,concurrent:1,publicPrompts:false}),
 // OVH limits anonymous use per model (2/min/IP), so each extra model is its own lane
 // (catalog.endpoints.ai.ovh.net/rest/v1/models_v2, name field, 2026-11-10).
 ovhgpt:Object.freeze({name:'OVHcloud AI Endpoints gpt-oss-120b (anonymous)',url:'https://oai.endpoints.kepler.ai.cloud.ovh.net/v1/chat/completions',
  model:'gpt-oss-120b',freeModel:/^[A-Za-z0-9][A-Za-z0-9._-]{0,79}$/,rpm:2,perDay:1000,concurrent:1,publicPrompts:false}),
 ovhllama:Object.freeze({name:'OVHcloud AI Endpoints Llama 3.3 70B (anonymous)',url:'https://oai.endpoints.kepler.ai.cloud.ovh.net/v1/chat/completions',
  model:'Meta-Llama-3_3-70B-Instruct',freeModel:/^[A-Za-z0-9][A-Za-z0-9._-]{0,79}$/,rpm:2,perDay:1000,concurrent:1,publicPrompts:false}),
 llm7:Object.freeze({name:'LLM7.io (anonymous)',url:'https://api.llm7.io/v1/chat/completions',
  model:'gpt-oss:20b',freeModel:/^[A-Za-z0-9][A-Za-z0-9.:_/-]{0,79}$/,rpm:20,perDay:1000,concurrent:2,publicPrompts:true}),
 kilo:Object.freeze({name:'Kilo AI Gateway (anonymous :free models)',url:'https://ai-gateway.kilo.ai/api/v1/chat/completions',
  model:'nvidia/nemotron-3.5-super-vl:free',freeModel:/^[a-z0-9][a-z0-9._/-]{0,79}:free$/,rpm:3,perHour:180,perDay:2000,concurrent:2,publicPrompts:true}),
 // Paid models share this endpoint (x402 payment headers); only billing_mode "free" models are allowed
 // and no payment header is ever sent (blockrun.ai/api/v1/models, 2026-11-10).
 blockrun:Object.freeze({name:'BlockRun free tier (anonymous, NVIDIA-hosted open models)',url:'https://blockrun.ai/api/v1/chat/completions',
  model:'nvidia/nemotron-3-super-120b',
  freeModel:/^(?:nvidia\/nemotron-3-super-120b|nvidia\/nemotron-3-ultra-550b|nvidia\/nemotron-3-nano-omni-30b-a3b-reasoning|nvidia\/nemotron-3\.5-bolt|poolside\/laguna-xs-2\.1)$/,
  rpm:10,perDay:1000,concurrent:2,publicPrompts:true}),
 // Distributed volunteer GPUs (kudos, no money). Async: submit, poll, cancel. Anonymous key.
 horde:Object.freeze({name:'AI Horde (distributed volunteer workers, anonymous)',kind:'horde',
  url:'https://aihorde.net/api/v2/generate/text/async',statusUrl:'https://aihorde.net/api/v2/generate/text/status/',
  model:'qwen3.8-27b-int4,lmstudio/Qwen3.6-35B-A3B,lmstudio/Qwen3.5-9B,koboldcpp/Llama-3.2-3B-Instruct',
  freeModel:/^[A-Za-z0-9][A-Za-z0-9._/:-]{0,79}(?:,[A-Za-z0-9][A-Za-z0-9._/:-]{0,79}){0,5}$/,
  rpm:10,perDay:500,concurrent:3,publicPrompts:true}),
 // Classic anonymous text endpoint (GET, prompt in the path, plain-text answer). The newer
 // gen.pollinations.ai chat API needs a key, so it is not used. The URL may be logged.
 pollinations:Object.freeze({name:'Pollinations classic text (anonymous tier)',kind:'pollinations',
  url:'https://text.pollinations.ai/',model:'openai',freeModel:/^[a-z0-9][a-z0-9.-]{0,39}$/,
  rpm:4,perDay:500,concurrent:1,publicPrompts:true,maxPromptChars:1800}),
 // Ollama-style generate API, no key, 5 requests/minute/IP, small models, non-commercial use only.
 mlvoca:Object.freeze({name:'mlvoca free LLM API (anonymous, non-commercial)',kind:'ollama',
  url:'https://mlvoca.com/api/generate',model:'deepseek-r1:1.5b',freeModel:/^(?:tinyllama|deepseek-r1:1\.5b)$/,
  rpm:4,perDay:500,concurrent:1,publicPrompts:true,maxPromptChars:8000}),
});
export const HORDE_ANONYMOUS_KEY='0000000000';
async function readBoundedText(response,maxBytes){
 if(response.type==='opaqueredirect'||response.status>=300&&response.status<400)throw Error('redirect-refused');
 const declared=Number(response.headers.get('content-length'));
 if(Number.isFinite(declared)&&declared>maxBytes)throw Error('response-too-large');
 if(!response.body?.getReader)throw Error('invalid-stream');
 const reader=response.body.getReader(),parts=[];let size=0;
 try{for(;;){const {value,done}=await reader.read();if(done)break;size+=value.byteLength;
  if(size>maxBytes){await reader.cancel().catch(()=>{});throw Error('response-too-large');}parts.push(value);}}
 finally{reader.releaseLock();}
 const bytes=new Uint8Array(size);let at=0;for(const p of parts){bytes.set(p,at);at+=p.byteLength;}
 return new TextDecoder('utf-8',{fatal:true}).decode(bytes);
}
const flatPrompt=messages=>messages.map(m=>(m.role==='user'?'':m.role+': ')+m.content).join('\n');
const stripThink=text=>text.replace(/<think>[\s\S]*?<\/think>/g,'').trim();
export const HORDE_CLIENT_AGENT='federation-firewall-gateway:1:github.com/Satofumi-Goto/federation-runtime';
export const FREE_AI_ROLES=Object.freeze(['plan','implement','review','test','reply-advice','summarize']);
const CODE_ROLES=new Set(['plan','implement','review','test']);
// Per calling app, across all providers: a leaked key cannot turn the gateway into an open relay.
// Floor of the per-calling-app cap. The live cap is the larger of this and the sum of the
// enabled providers' own ceilings, so adding a provider adds usable capacity instead of
// every provider being refused together once one app's minute is used up.
export const FREE_AI_CLIENT_LIMITS=Object.freeze({perMinute:30,perDay:3000});
export function clientLimitsFor(providers){
 let perMinute=0,perDay=0;
 for(const p of providers){const spec=FREE_AI_PROVIDERS[p];if(spec){perMinute+=spec.rpm;perDay+=spec.perDay;}}
 return Object.freeze({perMinute:Math.max(FREE_AI_CLIENT_LIMITS.perMinute,perMinute),
  perDay:Math.max(FREE_AI_CLIENT_LIMITS.perDay,perDay)});
}
export const FREE_AI_LIMITS=Object.freeze({maxMessages:16,maxMessageChars:24000,maxTotalChars:48000,
 maxOutputTokens:2048,maxResponseBytes:262144,timeoutMs:60000,maxAnswerChars:32000});
export const FREE_AI_POLICY=Object.freeze({version:'federation-firewall-free-ai/1',path:FREE_AI_PATH,defaultEnabled:false,
 keyless:true,credentialsStoredOrForwarded:false,signedServerToServerOnly:true,paidCalls:0,
 providers:Object.entries(FREE_AI_PROVIDERS).map(([id,p])=>({id,name:p.name,defaultModel:p.model,
  requestsPerMinute:p.rpm,requestsPerDay:p.perDay,concurrent:p.concurrent,publicPrompts:p.publicPrompts,
  codeRolesAllowed:!p.publicPrompts})),
 roles:FREE_AI_ROLES,requestFields:['provider','role','messages','maxTokens','model'],
 responseFields:['ok','provider','model','text','error','retryAfterSeconds'],
 auditFields:['type','at','method','status','client','provider','role','attempts'],promptOrAnswerLogged:false,
 personalDataToPublicPromptProviders:false,answerSecretsRedacted:true});
const CTRL=/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/;
export function loadFreeAiConfig(env=process.env){
 if(env.FIREWALL_FREE_AI_ENABLED!=='true')return {enabled:false,reason:'flag-off'};
 const ids=(env.FIREWALL_FREE_AI_CLIENT_IDS||'federation').split(',').filter(Boolean);
 if(!ids.length||ids.some(id=>!CLIENT_IDS.includes(id))||new Set(ids).size!==ids.length)
  return {enabled:false,reason:'clients-invalid'};
 const providers=(env.FIREWALL_FREE_AI_PROVIDERS||Object.keys(FREE_AI_PROVIDERS).join(',')).split(',').filter(Boolean);
 if(!providers.length||providers.some(p=>!Object.hasOwn(FREE_AI_PROVIDERS,p)))return {enabled:false,reason:'providers-invalid'};
 const models={};
 for(const p of providers){
  const raw=env['FIREWALL_FREE_AI_'+p.toUpperCase()+'_MODEL'];
  const model=raw===undefined||raw===''?FREE_AI_PROVIDERS[p].model:raw;
  if(!FREE_AI_PROVIDERS[p].freeModel.test(model))return {enabled:false,reason:'model-invalid'};
  models[p]=model;
 }
 return {enabled:true,clients:new Set(ids),providers,models};
}
export function parseFreeAiCommand(body){
 let q;
 try{q=JSON.parse(body);}catch{return {ok:false,status:400,error:'invalid-json'};}
 if(!q||typeof q!=='object'||Array.isArray(q))return {ok:false,status:400,error:'invalid-request'};
 if(Object.keys(q).some(k=>!['provider','role','messages','maxTokens','model'].includes(k)))
  return {ok:false,status:400,error:'invalid-request'};
 if(!FREE_AI_ROLES.includes(q.role))return {ok:false,status:400,error:'invalid-role'};
 if(q.provider!==undefined&&!Object.hasOwn(FREE_AI_PROVIDERS,q.provider))return {ok:false,status:400,error:'invalid-provider'};
 if(q.model!==undefined&&(q.provider===undefined||typeof q.model!=='string'||!FREE_AI_PROVIDERS[q.provider].freeModel.test(q.model)))
  return {ok:false,status:400,error:'invalid-model'};
 const L=FREE_AI_LIMITS,m=q.messages;
 if(!Array.isArray(m)||!m.length||m.length>L.maxMessages
  ||!m.every(x=>x&&typeof x==='object'&&!Array.isArray(x)&&Object.keys(x).every(k=>k==='role'||k==='content')
   &&['system','user','assistant'].includes(x.role)&&typeof x.content==='string'&&x.content.length<=L.maxMessageChars&&!CTRL.test(x.content))
  ||m.reduce((n,x)=>n+x.content.length,0)>L.maxTotalChars||!m.some(x=>x.role==='user'&&x.content.trim()))
  return {ok:false,status:400,error:'invalid-messages'};
 const maxTokens=q.maxTokens===undefined?1024:q.maxTokens;
 if(!Number.isInteger(maxTokens)||maxTokens<1||maxTokens>L.maxOutputTokens)return {ok:false,status:400,error:'invalid-max-tokens'};
 return {ok:true,command:{provider:q.provider,role:q.role,model:q.model,maxTokens,
  messages:m.map(x=>({role:x.role,content:x.content}))}};
}
function answerOf(data){
 const raw=data?.choices?.[0]?.message?.content;
 // Some providers return content as an array of parts. Reasoning text is never used as the answer.
 const text=typeof raw==='string'?raw:Array.isArray(raw)
  ?raw.map(part=>part&&part.type==='text'&&typeof part.text==='string'?part.text:'').join(''):'';
 return text.trim()?text.trim().slice(0,FREE_AI_LIMITS.maxAnswerChars):null;
}
// Reasoning models (Qwen3, gpt-oss, Nemotron) spend tokens thinking before they answer;
// a small budget leaves content empty with finish_reason "length".
export const FREE_AI_MIN_UPSTREAM_TOKENS=1024;
const upstreamTokens=maxTokens=>Math.min(FREE_AI_LIMITS.maxOutputTokens,Math.max(maxTokens,FREE_AI_MIN_UPSTREAM_TOKENS));
function emptyReason(data){
 const choice=data?.choices?.[0];
 const thought=choice?.message&&['reasoning_content','reasoning'].some(k=>typeof choice.message[k]==='string'&&choice.message[k].trim());
 return choice?.finish_reason==='length'?(thought?'reasoning-truncated':'answer-truncated'):'empty-answer';
}
function reportedCost(data){
 const u=data?.usage;
 return u&&typeof u==='object'?[u.cost,u.total_cost].some(v=>typeof v==='number'&&v>0):false;
}
const HORDE_WAIT_MS=50000,HORDE_POLL_MS=3000;
export function createFreeAi({env=process.env,fetchImpl=fetch,clock=Date.now,sleep=ms=>new Promise(r=>setTimeout(r,ms))}={}){
 const cfg=loadFreeAiConfig(env);
 const state=Object.fromEntries(Object.keys(FREE_AI_PROVIDERS).map(p=>[p,{minute:[],hour:[],day:'',dayCount:0,active:0,coolUntil:0,stoppedDay:''}]));
 const today=()=>new Date(clock()).toISOString().slice(0,10);
 function admit(p){
  const s=state[p],spec=FREE_AI_PROVIDERS[p],now=clock(),d=today();
  if(s.day!==d){s.day=d;s.dayCount=0;}
  s.minute=s.minute.filter(t=>now-t<60000);s.hour=s.hour.filter(t=>now-t<3600000);
  if(s.stoppedDay===d)return 'stopped-today';
  if(now<s.coolUntil)return 'cooling-down';
  if(s.active>=spec.concurrent)return 'busy';
  if(s.minute.length>=spec.rpm||(spec.perHour&&s.hour.length>=spec.perHour))return 'rate-limited';
  if(s.dayCount>=spec.perDay)return 'daily-cap';
  s.minute.push(now);s.hour.push(now);s.dayCount++;s.active++;return null;
 }
 function chain(command){
  // Code roles and personal contact data never go to providers that may log prompts.
  const personal=hasPersonalData(command.messages.map(m=>m.content));
  const allowed=cfg.providers.filter(p=>!((CODE_ROLES.has(command.role)||personal)&&FREE_AI_PROVIDERS[p].publicPrompts));
  return command.provider?allowed.filter(p=>p===command.provider):allowed;
 }
 async function callHorde(p,command,model){
  const spec=FREE_AI_PROVIDERS[p];
  const headers={'Content-Type':'application/json',Accept:'application/json',apikey:HORDE_ANONYMOUS_KEY,'Client-Agent':HORDE_CLIENT_AGENT};
  const prompt=command.messages.map(m=>'### '+m.role[0].toUpperCase()+m.role.slice(1)+':\n'+m.content).join('\n')+'\n### Assistant:\n';
  const submit=await fetchImpl(spec.url,{method:'POST',redirect:'manual',credentials:'omit',headers,
   body:JSON.stringify({prompt,models:model.split(','),params:{max_length:Math.max(16,Math.min(command.maxTokens,512)),
    max_context_length:4096,temperature:0.2,n:1}}),signal:AbortSignal.timeout(15000)});
  if(submit.status===429||submit.status>=500){state[p].coolUntil=clock()+60000;throw Error('upstream-'+submit.status);}
  if(submit.status!==200&&submit.status!==202)throw Error('upstream-'+submit.status);
  const job=await readBoundedJson(submit,8192);
  if(typeof job?.id!=='string'||!/^[A-Za-z0-9-]{8,64}$/.test(job.id))throw Error('bad-job');
  const statusUrl=spec.statusUrl+job.id,deadline=clock()+HORDE_WAIT_MS;
  const cancel=()=>fetchImpl(statusUrl,{method:'DELETE',redirect:'manual',credentials:'omit',headers,signal:AbortSignal.timeout(5000)}).catch(()=>{});
  while(true){
   await sleep(HORDE_POLL_MS);
   const r=await fetchImpl(statusUrl,{method:'GET',redirect:'manual',credentials:'omit',headers,signal:AbortSignal.timeout(10000)});
   if(r.status===200){
    const st=await readBoundedJson(r,FREE_AI_LIMITS.maxResponseBytes);
    if(st?.faulted||st?.is_possible===false){await cancel();throw Error(st?.faulted?'faulted':'no-worker-available');}
    if(st?.done){
     const g=Array.isArray(st.generations)?st.generations[0]:null;
     const text=typeof g?.text==='string'&&g.text.trim()?g.text.trim().slice(0,FREE_AI_LIMITS.maxAnswerChars):null;
     if(!text)throw Error('empty-answer');
     return {model:typeof g.model==='string'?g.model.slice(0,80):model,text};
    }
   }else if(r.status!==429&&r.status<500)throw Error('upstream-'+r.status);
   if(clock()>=deadline){await cancel();throw Error('timeout-cancelled');}
  }
 }
 async function call(p,command){
  const model=command.model||cfg.models[p];
  const spec=FREE_AI_PROVIDERS[p];
  if(spec.kind==='horde')return callHorde(p,command,model);
  if(spec.kind==='pollinations'||spec.kind==='ollama'){
   const prompt=flatPrompt(command.messages);
   if(prompt.length>spec.maxPromptChars)throw Error('prompt-too-large');
   const response=spec.kind==='pollinations'
    ?await fetchImpl(spec.url+encodeURIComponent(prompt)+'?model='+encodeURIComponent(model)+'&private=true',
      {method:'GET',redirect:'manual',credentials:'omit',headers:{Accept:'text/plain'},signal:AbortSignal.timeout(FREE_AI_LIMITS.timeoutMs)})
    :await fetchImpl(spec.url,{method:'POST',redirect:'manual',credentials:'omit',
      headers:{'Content-Type':'application/json',Accept:'application/json'},
      body:JSON.stringify({model,prompt,stream:false,options:{num_predict:upstreamTokens(command.maxTokens)}}),signal:AbortSignal.timeout(FREE_AI_LIMITS.timeoutMs)});
   if(response.status===429||response.status>=500){state[p].coolUntil=clock()+60000;throw Error('upstream-'+response.status);}
   if(response.status===401||response.status===402||response.status===403){state[p].stoppedDay=today();throw Error('upstream-'+response.status);}
   if(response.status!==200)throw Error('upstream-'+response.status);
   const raw=spec.kind==='pollinations'?await readBoundedText(response,FREE_AI_LIMITS.maxResponseBytes)
    :(await readBoundedJson(response,FREE_AI_LIMITS.maxResponseBytes))?.response;
   const text=typeof raw==='string'?stripThink(raw).slice(0,FREE_AI_LIMITS.maxAnswerChars):'';
   if(!text)throw Error('empty-answer');
   return {model,text};
  }
  // No Authorization header: these endpoints are anonymous. Redirects are refused.
  const response=await fetchImpl(FREE_AI_PROVIDERS[p].url,{method:'POST',redirect:'manual',credentials:'omit',
   headers:{'Content-Type':'application/json',Accept:'application/json'},
   body:JSON.stringify({model,messages:command.messages,max_tokens:upstreamTokens(command.maxTokens),temperature:0.2,stream:false}),
   signal:AbortSignal.timeout(FREE_AI_LIMITS.timeoutMs)});
  if(response.status===429||response.status>=500){state[p].coolUntil=clock()+60000;throw Error('upstream-'+response.status);}
  if(response.status===401||response.status===402||response.status===403){state[p].stoppedDay=today();throw Error('upstream-'+response.status);}
  if(response.status!==200)throw Error('upstream-'+response.status);
  const data=await readBoundedJson(response,FREE_AI_LIMITS.maxResponseBytes);
  if(reportedCost(data)){state[p].stoppedDay=today();throw Error('paid-usage-reported');}
  const text=answerOf(data);
  if(!text)throw Error(emptyReason(data));
  return {model,text};
 }
 const clientUse=new Map();
 const clientLimits=clientLimitsFor(cfg.enabled?cfg.providers:[]);
 function admitClient(client){
  const now=clock(),d=today();
  let u=clientUse.get(client);
  if(!u||u.day!==d){u={day:d,count:0,minute:[]};clientUse.set(client,u);}
  u.minute=u.minute.filter(t=>now-t<60000);
  if(u.minute.length>=clientLimits.perMinute||u.count>=clientLimits.perDay)return false;
  u.minute.push(now);u.count++;return true;
 }
 async function chat(client,command){
  if(!cfg.enabled)return {status:503,result:{ok:false,error:'free-ai-disabled'}};
  if(!cfg.clients.has(client))return {status:403,result:{ok:false,error:'client-not-allowed'}};
  if(!admitClient(client))return {status:429,result:{ok:false,error:'client-rate-limited',retryAfterSeconds:60,paidCalls:0}};
  const order=chain(command);
  if(!order.length)return {status:400,result:{ok:false,error:'provider-not-allowed-for-role'}};
  const attempts=[];
  for(const p of order){
   const refused=admit(p);
   if(refused){attempts.push({provider:p,skipped:refused});continue;}
   try{
    const answer=await call(p,command);
    attempts.push({provider:p,ok:true});
    const safe=redactSecrets(answer.text);
    return {status:200,result:{ok:true,provider:p,model:answer.model,text:safe.text,
     ...(safe.redacted?{redactedSecrets:safe.redacted}:{}),attempts,paidCalls:0}};
   }catch(error){
    attempts.push({provider:p,failed:String(error?.message||'network').slice(0,40).replace(/[^a-z0-9-]/g,'')||'network'});
   }finally{state[p].active--;}
  }
  const limited=attempts.every(a=>a.skipped&&a.skipped!=='stopped-today');
  return {status:limited?429:503,result:{ok:false,error:limited?'rate-limited':'no-free-provider-answered',attempts,
   ...(limited?{retryAfterSeconds:60}:{}),paidCalls:0}};
 }
 return {chat,get enabled(){return cfg.enabled;},
  info:()=>({enabled:cfg.enabled,reason:cfg.enabled?'armed':cfg.reason,providers:cfg.enabled?cfg.providers:[],clientLimits,
   usageToday:Object.fromEntries(Object.entries(state).map(([p,s])=>[p,s.day===today()?s.dayCount:0]))})};
}
