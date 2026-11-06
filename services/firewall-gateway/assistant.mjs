import {readBoundedJson} from './egress.mjs';

// Shared avatar-tap AI answer route. Deny by default: it answers only when
// FIREWALL_ASSISTANT_ENABLED=true AND a server-side provider key is present.
// The provider key never leaves this process; callers authenticate by HMAC.
export const ASSISTANT_PATH='/api/v1/assistant/ask';
export const ASSISTANT_MAX_BODY=4096;
const PROVIDER_HOST='generativelanguage.googleapis.com';
const DEFAULT_MODEL='gemini-2.5-flash';
const ALLOWED_KEYS=new Set(['characterId','question','locale','persona','screen']);

export const ASSISTANT_POLICY=Object.freeze({
 version:'federation-firewall-assistant/1',path:ASSISTANT_PATH,defaultEnabled:false,
 provider:'gemini',providerKeyInBrowser:false,signedServerToServerOnly:true,
 auditFields:['type','at','method','status','client','characterId'],
 questionOrAnswerLogged:false,maxBodyBytes:ASSISTANT_MAX_BODY,
 maxConcurrentPerWorker:2,maxNewRequestsPerMinutePerWorker:12,maxNewRequestsPerMinutePerClient:6,
});

export function parseAssistantCommand(body){
 let command;
 try{command=JSON.parse(body);}catch{return {ok:false,status:400,reason:'invalid-json'};}
 const bad={ok:false,status:400,reason:'unsupported-command'};
 if(!command||typeof command!=='object'||Array.isArray(command))return bad;
 const keys=Object.keys(command);
 if(keys.some(k=>!ALLOWED_KEYS.has(k)))return bad;
 const {characterId,question,locale,persona,screen}=command;
 if(typeof characterId!=='string'||!/^[a-z0-9-]{1,64}$/.test(characterId))return bad;
 if(typeof question!=='string'||!question.trim()||[...question].length>1200)return bad;
 if(locale!==undefined&&locale!=='ja'&&locale!=='en')return bad;
 if(persona!==undefined&&(typeof persona!=='string'||[...persona].length>600))return bad;
 if(screen!==undefined&&(typeof screen!=='string'||!/^[A-Za-z0-9/_.:-]{0,120}$/.test(screen)))return bad;
 return {ok:true,command:{characterId,question:question.trim(),locale:locale||'ja',
  persona:typeof persona==='string'?persona.trim():'',screen:screen||''}};
}

export function buildInstruction({client,characterId,locale,persona,screen}){
 return [
  'You are the in-app guide character "'+characterId+'" for the "'+client+'" console.',
  persona?'Character voice and reasoning style (keep it consistently): '+persona:
   'Keep a consistent, recognisable voice for this character.',
  locale==='en'?'Answer in English.':'日本語で答える。',
  'Answer the user question briefly (at most about 8 sentences).',
  'Never invent numbers, plan values, safety thresholds, permissions or operational status; '+
  'if unknown, say so and point to the screen. Never claim to be a real person or quote one.',
  screen?'Current screen: '+screen:'',
 ].filter(Boolean).join('\n');
}

export function createAssistant({env=process.env,fetchImpl=fetch,clock=Date.now}={}){
 const key=env.FIREWALL_ASSISTANT_GEMINI_KEY||'';
 const model=env.FIREWALL_ASSISTANT_MODEL||DEFAULT_MODEL;
 const keyOk=/^[A-Za-z0-9_-]{20,200}$/.test(key);
 const modelOk=/^gemini-[a-z0-9.-]{3,60}$/.test(model);
 const enabled=env.FIREWALL_ASSISTANT_ENABLED==='true'&&keyOk&&modelOk;
 const started=new Map();let active=0,total=0,windowStart=clock();
 function admit(client){
  const now=clock();
  if(now<windowStart||now-windowStart>=60000){windowStart=now;total=0;started.clear();}
  if(total>=ASSISTANT_POLICY.maxNewRequestsPerMinutePerWorker||active>=ASSISTANT_POLICY.maxConcurrentPerWorker||
   (started.get(client)||0)>=ASSISTANT_POLICY.maxNewRequestsPerMinutePerClient)return false;
  total++;started.set(client,(started.get(client)||0)+1);return true;
 }
 async function ask(client,command){
  if(!enabled)return {status:503,result:{ok:false,reason:'assistant-disabled'}};
  if(!admit(client))
   return {status:429,result:{ok:false,reason:'assistant-budget-exhausted',retryAfterSeconds:60}};
  active++;
  try{
   const url='https://'+PROVIDER_HOST+'/v1beta/models/'+encodeURIComponent(model)+':generateContent';
   const response=await fetchImpl(url,{method:'POST',redirect:'manual',credentials:'omit',
    signal:AbortSignal.timeout(20000),
    headers:{'x-goog-api-key':key,'Content-Type':'application/json',Accept:'application/json'},
    body:JSON.stringify({
     systemInstruction:{parts:[{text:buildInstruction({client,...command})}]},
     contents:[{role:'user',parts:[{text:command.question}]}],
     generationConfig:{maxOutputTokens:800}})});
   const data=await readBoundedJson(response,262144);
   const parts=data?.candidates?.[0]?.content?.parts;
   const answer=Array.isArray(parts)?parts.map(p=>typeof p?.text==='string'?p.text:'').join('').trim():'';
   if(!answer)throw Error('empty-answer');
   return {status:200,result:{ok:true,mode:'assistant',client,characterId:command.characterId,
    answer:answer.slice(0,4000),provider:'gemini',model,answeredAt:new Date(clock()).toISOString()}};
  }catch{
   return {status:502,result:{ok:false,reason:'assistant-provider-unavailable',retryAfterSeconds:60}};
  }finally{active--;}
 }
 return {ask,get enabled(){return enabled;}};
}
