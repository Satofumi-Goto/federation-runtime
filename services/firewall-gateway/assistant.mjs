import {readBoundedJson} from './egress.mjs';
import {CLIENT_IDS} from './policy.mjs';
// Shared avatar-question intake for the nine Federation family apps.
// Request/response fields follow the assistant answer contract
// (Satofumi-Goto/seneschal docs/qa/assistant-answer-contract.md):
//   {appId, question, language, history, context, character, page, requestId?}
//   -> {ok, status: answered|denied|unavailable, answer, provider, error, requestId}
// Transport differs on purpose: the Gateway accepts only HMAC-signed server-to-server
// calls; browsers must go through their own app server.
// The Gateway owns transport security only: each app keeps its own character
// definitions (characterProfile) and sends them with the question.
// Provider calls are OFF unless an explicit flag, provider, key, model, total
// budget, per-call ceiling and short expiry are all valid at process start.
export const ASSISTANT_PATH='/api/v1/assistant/ask';
export const ASSISTANT_APPS=CLIENT_IDS;
export const ASSISTANT_MAX_BODY=32768;
const PROVIDERS=Object.freeze({
 openai:Object.freeze({url:()=>'https://api.openai.com/v1/chat/completions'}),
 gemini:Object.freeze({url:model=>'https://generativelanguage.googleapis.com/v1beta/models/'+encodeURIComponent(model)+':generateContent'}),
});
export const ASSISTANT_LIMITS=Object.freeze({
 maxRequestBytes:ASSISTANT_MAX_BODY,maxQuestionChars:1200,maxHistory:8,maxHistoryChars:1200,
 maxContextChars:3000,maxPageChars:120,maxAnswerChars:2000,maxOutputTokens:700,
 maxResponseBytes:65536,timeoutMs:15000,
 maxConcurrent:2,maxPerMinute:12,maxPerClientPerMinute:6,
 maxBudgetMicros:5000000,maxCallMicros:100000,maxWindowMs:86400000,
});
export const ASSISTANT_POLICY=Object.freeze({
 version:'federation-firewall-assistant/2',path:ASSISTANT_PATH,defaultEnabled:false,
 contract:'Satofumi-Goto/seneschal docs/qa/assistant-answer-contract.md',
 requestFields:['appId','question','language','history','context','character','page','requestId'],
 responseFields:['ok','status','answer','provider','error','requestId'],
 providers:Object.keys(PROVIDERS),providerKeyInBrowser:false,signedServerToServerOnly:true,
 requiresBudgetAndExpiry:true,personaOwner:'each-app (characterProfile)',
 auditFields:['type','at','method','status','client','characterId'],questionOrAnswerLogged:false,
 maxBodyBytes:ASSISTANT_LIMITS.maxRequestBytes,maxConcurrentPerWorker:ASSISTANT_LIMITS.maxConcurrent,
 maxNewRequestsPerMinutePerWorker:ASSISTANT_LIMITS.maxPerMinute,
 maxNewRequestsPerMinutePerClient:ASSISTANT_LIMITS.maxPerClientPerMinute,
 maxBudgetMicros:ASSISTANT_LIMITS.maxBudgetMicros,maxCallMicros:ASSISTANT_LIMITS.maxCallMicros,
 maxWindowMs:ASSISTANT_LIMITS.maxWindowMs,
});
const RULES='You are the read-only in-app guide behind an avatar. Answer as the supplied character: let its personality shape the content itself '
 +'(what it notices, what it treats as most important, its opinion and judgement, what it recommends or warns about, its examples and how it closes), not only the wording. '
 +'Never invent facts, numbers or features. Never change safety cautions, permissions, commands or operational status. '
 +'Never claim that you booked, paid, dispatched, deployed or changed any setting. Say clearly when information is unknown or unverified. '
 +'Do not impersonate a real person or quote them.';
const CTRL=/[\u0000-\u0008\u000b-\u001f\u007f]/;
const str=(v,n,{required=false}={})=>typeof v==='string'&&v.length<=n&&!CTRL.test(v)&&(!required||v.trim().length>0);
const ISO=/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/;
const int=(v,max)=>/^[1-9][0-9]{0,8}$/.test(v||'')&&Number(v)<=max?Number(v):NaN;
const CHARACTER_TEXT=Object.freeze({id:120,name:80,personality:300,firstPerson:20,secondPerson:20,tone:60,
 rhythm:160,length:20,opening:200,followUp:200,reactionStyle:160});
const CHARACTER_LISTS=Object.freeze({acknowledgments:6,endings:6,rules:10});
const CHARACTER_SCALES=Object.freeze(['directness','humor','empathy','actionBias']);
const CHARACTER_KEYS=new Set([...Object.keys(CHARACTER_TEXT),...Object.keys(CHARACTER_LISTS),...CHARACTER_SCALES]);
const REQUEST_KEYS=new Set(['appId','question','language','history','context','character','page','requestId']);


function parseCharacter(c){
 if(c===null||c===undefined)return {ok:true,character:null};
 if(typeof c!=='object'||Array.isArray(c)||Object.keys(c).some(k=>!CHARACTER_KEYS.has(k)))return {ok:false};
 if(typeof c.id!=='string'||!/^[A-Za-z0-9][A-Za-z0-9_-]{0,119}$/.test(c.id))return {ok:false};
 const out={id:c.id};
 for(const [k,n] of Object.entries(CHARACTER_TEXT)){
  if(k==='id')continue;
  if(c[k]===undefined)continue;
  if(!str(c[k],n))return {ok:false};
  out[k]=c[k].trim();
 }
 for(const [k,n] of Object.entries(CHARACTER_LISTS)){
  if(c[k]===undefined)continue;
  if(!Array.isArray(c[k])||c[k].length>n||!c[k].every(x=>str(x,160)))return {ok:false};
  out[k]=c[k].map(x=>x.trim()).filter(Boolean);
 }
 for(const k of CHARACTER_SCALES){
  if(c[k]===undefined||c[k]===null)continue;
  if(typeof c[k]!=='number'||!Number.isFinite(c[k])||c[k]<0||c[k]>5)return {ok:false};
  out[k]=c[k];
 }
 return {ok:true,character:out};
}

// Transitional: the first #1015 shape {characterId,question,locale?,persona?,screen?}
// (used by apps/remote-monitoring/server/assistant-relay.mjs) is mapped onto the
// contract; appId then comes from the signed client. Remove once relays send the contract.
const LEGACY_KEYS=new Set(['characterId','question','locale','persona','screen']);
function legacyToContract(q){
 if(typeof q.characterId!=='string'||!/^[a-z0-9-]{1,64}$/.test(q.characterId))return null;
 if(typeof q.question!=='string'||!q.question.trim()||[...q.question].length>ASSISTANT_LIMITS.maxQuestionChars)return null;
 if(q.locale!==undefined&&q.locale!=='ja'&&q.locale!=='en')return null;
 if(q.persona!==undefined&&!str(q.persona,600))return null;
 if(q.screen!==undefined&&!(typeof q.screen==='string'&&/^[A-Za-z0-9/_.:-]{0,120}$/.test(q.screen)))return null;
 const character={id:q.characterId};
 if(q.persona&&q.persona.trim())character.personality=q.persona.trim();
 return {appId:null,language:q.locale||'ja',question:q.question.trim(),history:[],context:'',
  page:q.screen||'',character,requestId:null,legacyShape:true};
}

// Returns {ok:true,command} or {ok:false,error,requestId}.
export function parseAssistantCommand(body){
 let q;
 try{q=JSON.parse(body);}catch{return {ok:false,error:'invalid_question',requestId:null};}
 if(!q||typeof q!=='object'||Array.isArray(q))return {ok:false,error:'invalid_question',requestId:null};
 if(q.appId===undefined&&q.characterId!==undefined&&Object.keys(q).every(k=>LEGACY_KEYS.has(k))){
  const command=legacyToContract(q);
  return command?{ok:true,command}:{ok:false,error:'invalid_question',requestId:null};
 }
 const requestId=typeof q.requestId==='string'&&/^[A-Za-z0-9_.:-]{1,64}$/.test(q.requestId)?q.requestId:null;
 if(q.requestId!==undefined&&requestId===null)return {ok:false,error:'invalid_question',requestId:null};
 if(Object.keys(q).some(k=>!REQUEST_KEYS.has(k)))return {ok:false,error:'invalid_question',requestId};
 if(typeof q.appId!=='string'||!CLIENT_IDS.includes(q.appId))
  return {ok:false,error:'invalid_app',requestId};
 const L=ASSISTANT_LIMITS;
 const history=q.history===undefined?[]:q.history;
 if(!str(q.question,L.maxQuestionChars,{required:true})||!['ja','en'].includes(q.language)
  ||!Array.isArray(history)||history.length>L.maxHistory
  ||!history.every(m=>m&&typeof m==='object'&&!Array.isArray(m)&&Object.keys(m).every(k=>k==='role'||k==='content')
    &&['user','assistant'].includes(m.role)&&str(m.content,L.maxHistoryChars))
  ||q.context!==undefined&&!str(q.context,L.maxContextChars)
  ||q.page!==undefined&&!str(q.page,L.maxPageChars))
  return {ok:false,error:'invalid_question',requestId};
 const character=parseCharacter(q.character);
 if(!character.ok)return {ok:false,error:'invalid_question',requestId};
 return {ok:true,command:{appId:q.appId,language:q.language,question:q.question.trim(),
  history:history.map(m=>({role:m.role,content:m.content})),context:(q.context||'').trim(),
  page:(q.page||'').trim(),character:character.character,requestId}};
}

// Provider calls require ALL of: FIREWALL_ASSISTANT_ENABLED=true, a provider key
// (FIREWALL_ASSISTANT_GEMINI_KEY or FIREWALL_ASSISTANT_OPENAI_KEY for the selected
// FIREWALL_ASSISTANT_PROVIDER, default gemini), a valid model, a total budget, a
// per-call ceiling, an expiry within 24h of boot and the enabled app list.
const DEFAULT_MODEL=Object.freeze({gemini:'gemini-2.5-flash'});
const KEY_ENV=Object.freeze({gemini:'FIREWALL_ASSISTANT_GEMINI_KEY',openai:'FIREWALL_ASSISTANT_OPENAI_KEY'});
export function loadAssistantConfig(env=process.env,boot=Date.now()){
 const off=reason=>({enabled:false,reason});
 if(env.FIREWALL_ASSISTANT_ENABLED!=='true')return off('flag-off');
 const name=env.FIREWALL_ASSISTANT_PROVIDER===undefined?'gemini':env.FIREWALL_ASSISTANT_PROVIDER;
 const provider=Object.hasOwn(PROVIDERS,name)?name:null;
 if(!provider)return off('provider-invalid');
 const key=env[KEY_ENV[provider]];
 if(typeof key!=='string'||!/^[A-Za-z0-9_-]{20,256}$/.test(key))return off('key-invalid');
 const model=env.FIREWALL_ASSISTANT_MODEL===undefined?DEFAULT_MODEL[provider]:env.FIREWALL_ASSISTANT_MODEL;
 if(typeof model!=='string'||!/^[A-Za-z0-9][A-Za-z0-9._-]{0,79}$/.test(model))return off('model-invalid');
 const budget=int(env.FIREWALL_ASSISTANT_BUDGET_MICROS,ASSISTANT_LIMITS.maxBudgetMicros);
 const perCall=int(env.FIREWALL_ASSISTANT_MAX_CALL_MICROS,ASSISTANT_LIMITS.maxCallMicros);
 if(!Number.isFinite(budget)||!Number.isFinite(perCall)||perCall>budget)return off('budget-invalid');
 const raw=env.FIREWALL_ASSISTANT_EXPIRES_AT||'';
 const expiresAt=ISO.test(raw)?Date.parse(raw):NaN;
 if(!Number.isFinite(expiresAt)||expiresAt<=boot||expiresAt-boot>ASSISTANT_LIMITS.maxWindowMs)
  return off('expiry-invalid');
 const ids=(env.FIREWALL_ASSISTANT_CLIENT_IDS||'').split(',').filter(Boolean);
 if(!ids.length||ids.some(id=>!CLIENT_IDS.includes(id))||new Set(ids).size!==ids.length)
  return off('clients-invalid');
 return {enabled:true,provider,key,model,budget,perCall,expiresAt,clients:new Set(ids)};
}

export function buildInstruction(q){
 const c=q.character;
 const lines=[RULES,'App: '+q.appId+(q.page?' / page: '+q.page:'')];
 if(c){
  lines.push('Character profile (defined by the app, apply as-is):');
  for(const [k,v] of Object.entries(c))if(k!=='id'&&(Array.isArray(v)?v.length:v!==''))
   lines.push('- '+k+': '+(Array.isArray(v)?v.join(' / '):String(v)));
 }
 if(q.context)lines.push('Screen reference (read-only, may be incomplete):\n'+q.context);
 lines.push('Answer in '+(q.language==='en'?'English':'Japanese')+'.');
 return lines.join('\n');
}
function providerRequest(cfg,q){
 const system=buildInstruction(q);
 if(cfg.provider==='gemini')return {url:PROVIDERS.gemini.url(cfg.model),headers:{'x-goog-api-key':cfg.key},
  body:{systemInstruction:{parts:[{text:system}]},
   contents:[...q.history.map(m=>({role:m.role==='assistant'?'model':'user',parts:[{text:m.content}]})),
    {role:'user',parts:[{text:q.question}]}],
   generationConfig:{maxOutputTokens:ASSISTANT_LIMITS.maxOutputTokens}}};
 return {url:PROVIDERS.openai.url(),headers:{Authorization:'Bearer '+cfg.key},
  body:{model:cfg.model,max_tokens:ASSISTANT_LIMITS.maxOutputTokens,
   messages:[{role:'system',content:system},...q.history,{role:'user',content:q.question}]}};
}
function answerText(provider,data){
 const value=provider==='gemini'
  ?(Array.isArray(data?.candidates?.[0]?.content?.parts)?data.candidates[0].content.parts.map(p=>typeof p?.text==='string'?p.text:'').join(''):'')
  :data?.choices?.[0]?.message?.content;
 return typeof value==='string'&&value.trim()?value.trim().slice(0,ASSISTANT_LIMITS.maxAnswerChars):null;
}
const unavailable=requestId=>({status:503,result:{ok:false,status:'unavailable',error:'ai_unavailable',requestId}});

export function createAssistant({env=process.env,fetchImpl=fetch,clock=Date.now}={}){
 const cfg=loadAssistantConfig(env,clock());
 const started=new Map();
 let spent=0,active=0,total=0,windowStart=clock();
 const live=()=>cfg.enabled&&clock()<cfg.expiresAt;
 function admit(client){
  const now=clock();
  if(now<windowStart||now-windowStart>=60000){windowStart=now;total=0;started.clear();}
  if(total>=ASSISTANT_LIMITS.maxPerMinute||active>=ASSISTANT_LIMITS.maxConcurrent
   ||(started.get(client)||0)>=ASSISTANT_LIMITS.maxPerClientPerMinute)return false;
  total++;started.set(client,(started.get(client)||0)+1);return true;
 }
 async function ask(client,command){
  let q=command;
  const requestId=q.requestId;
  if(q.legacyShape)q={...q,appId:client};
  if(q.appId!==client)return {status:403,result:{ok:false,status:'denied',error:'origin_not_allowed',requestId}};
  if(!live()||!cfg.clients.has(client)||spent+cfg.perCall>cfg.budget)return unavailable(requestId);
  if(!admit(client))return {status:429,result:{ok:false,status:'denied',error:'rate_limited',requestId,retryAfterSeconds:60}};
  // Reserve the worst-case cost before calling; reservations are never refunded.
  spent+=cfg.perCall;active++;
  try{
   const request=providerRequest(cfg,q);
   const response=await fetchImpl(request.url,{method:'POST',redirect:'manual',credentials:'omit',
    headers:{'Content-Type':'application/json',Accept:'application/json',...request.headers},
    body:JSON.stringify(request.body),signal:AbortSignal.timeout(ASSISTANT_LIMITS.timeoutMs)});
   const data=await readBoundedJson(response,ASSISTANT_LIMITS.maxResponseBytes);
   if(!live())return unavailable(requestId);
   const answer=answerText(cfg.provider,data);
   if(!answer)throw Error('empty-answer');
   return {status:200,result:{ok:true,status:'answered',answer,provider:cfg.provider,requestId,
    ...(q.legacyShape?{characterId:q.character.id}:{})}};
  }catch{
   return unavailable(requestId);
  }finally{active--;}
 }
 return {ask,get enabled(){return live();},
  info:()=>({providerEnabled:live(),providerReason:cfg.enabled?(live()?'armed':'expired'):cfg.reason,
   spentMicros:spent,budgetMicros:cfg.enabled?cfg.budget:0})};
}
