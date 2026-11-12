import {parseFreeAiCommand,FREE_AI_LIMITS,failureCode} from './freeAi.mjs';
import {readBoundedJson} from './egress.mjs';
import {hasPersonalData,redactSecrets} from './hardening.mjs';

// These services require accounts. A key alone is NOT evidence of a free tier.
// Only enable a lane after verifying a provider-side free-only account/budget.
// No automatic fallback from the anonymous relay into these accounts.
export const REGISTERED_AI_PROVIDERS=Object.freeze({
 gemini:{url:'https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent',model:'gemini-2.5-flash',key:'GEMINI_API_KEY'},
 groq:{url:'https://api.groq.com/openai/v1/chat/completions',model:'llama-3.3-70b-versatile',key:'GROQ_API_KEY'},
 mistral:{url:'https://api.mistral.ai/v1/chat/completions',model:'mistral-small-latest',key:'MISTRAL_API_KEY'},
 openrouter:{url:'https://openrouter.ai/api/v1/chat/completions',model:'meta-llama/llama-3.3-70b-instruct:free',key:'OPENROUTER_API_KEY'},
 cerebras:{url:'https://api.cerebras.ai/v1/chat/completions',model:'gpt-oss-120b',key:'CEREBRAS_API_KEY'},
 cloudflare:{model:'@cf/meta/llama-3.1-8b-instruct',key:'CLOUDFLARE_API_TOKEN'},
 nvidia:{url:'https://integrate.api.nvidia.com/v1/chat/completions',model:'meta/llama-3.3-70b-instruct',key:'NVIDIA_API_KEY'},
});
for(const value of Object.values(REGISTERED_AI_PROVIDERS))Object.freeze(value);
const ids=Object.keys(REGISTERED_AI_PROVIDERS);
const prefix=id=>'FIREWALL_REGISTERED_AI_'+id.toUpperCase();
const codeRoles=new Set(['plan','implement','review','test']);
export function registeredProvider(body){
 try{const p=JSON.parse(body)?.provider;return typeof p==='string'&&Object.hasOwn(REGISTERED_AI_PROVIDERS,p)?p:null;}
 catch{return null;}
}
export function parseRegisteredAiCommand(body){
 let value;
 try{value=JSON.parse(body);}catch{return {ok:false,status:400,error:'invalid-json'};}
 const spec=REGISTERED_AI_PROVIDERS[value?.provider];
 if(typeof value?.provider!=='string'||!Object.hasOwn(REGISTERED_AI_PROVIDERS,value.provider))return {ok:false,status:400,error:'invalid-provider'};
 // Reuse the exact existing message/body/role limits. Models are server selected.
 if(value.model!==undefined)return {ok:false,status:400,error:'server-selected-model'};
 const {provider,...rest}=value;
 const result=parseFreeAiCommand(JSON.stringify(rest));
 return result.ok?{ok:true,command:{...result.command,provider,model:spec.model}}:result;
}
function configFor(id,env){
 const spec=REGISTERED_AI_PROVIDERS[id],p=prefix(id);
 let reason=null;
 if(env.FIREWALL_REGISTERED_AI_ENABLED!=='true'||env[p+'_ENABLED']!=='true')reason='flag-off';
 else if(env[p+'_FREE_TIER_CONFIRMED']!=='true')reason='free-tier-unverified';
 else if(!/^[A-Za-z0-9._-]+$/.test(env[spec.key]||''))reason='key-missing-or-invalid';
 else if(id==='cloudflare'&&!/^[a-f0-9]{32}$/.test(env.CLOUDFLARE_ACCOUNT_ID||''))reason='account-id-missing';
 // Public by default, including Gemini and Mistral training-enabled free tiers.
 const privatePrompts=env[p+'_PRIVATE_PROCESSING_CONFIRMED']==='true'&&!['gemini','mistral'].includes(id);
 return {enabled:!reason,reason:reason||'armed',privatePrompts};
}
export function createRegisteredAi({env=process.env,fetchImpl=fetch,clock=Date.now}={}){
 const configs=Object.fromEntries(ids.map(id=>[id,configFor(id,env)]));
 const state=Object.fromEntries(ids.map(id=>[id,{day:'',count:0,minute:[],active:false,stop:false,coolUntil:0,lastHttpStatus:null}]));
 const clients=new Set((env.FIREWALL_FREE_AI_CLIENT_IDS||'federation').split(',').filter(Boolean));
 // Deliberate small ceilings, not assertions about providers' current quotas.
 const limits={perMinute:2,perDay:25,maxOutputTokens:1024};
 async function chat(client,command){
  const id=command.provider,cfg=configs[id],spec=REGISTERED_AI_PROVIDERS[id];
  const deny=(status,error)=>({status,result:{ok:false,provider:id,error}});
  if(!cfg?.enabled)return deny(503,'registered-ai-disabled');
  if(!clients.has(client))return deny(403,'client-not-allowed');
  if(Object.values(REGISTERED_AI_PROVIDERS).some(p=>env[p.key]&&command.messages.some(m=>m.content.includes(env[p.key]))))
   return deny(422,'secret-detected');
  if(!cfg.privatePrompts&&(codeRoles.has(command.role)||hasPersonalData(command.messages.map(m=>m.content))))
   return deny(400,'provider-not-allowed-for-role-or-personal-data');
  const s=state[id],now=clock(),day=new Date(now).toISOString().slice(0,10);
  if(s.day!==day){s.day=day;s.count=0;s.stop=false;}
  s.minute=s.minute.filter(t=>now-t<60000);
  if(s.stop)return deny(503,'provider-stopped');
  if(s.active||now<s.coolUntil||s.minute.length>=limits.perMinute||s.count>=limits.perDay)
   return deny(429,'rate-limited');
  s.minute.push(now);s.count++;s.active=true;
  try{
   const url=id==='cloudflare'
    ?'https://api.cloudflare.com/client/v4/accounts/'+env.CLOUDFLARE_ACCOUNT_ID+'/ai/run/'+spec.model:spec.url;
   const tokens=Math.min(command.maxTokens,limits.maxOutputTokens);
   const body=id==='gemini'?{
    contents:command.messages.filter(m=>m.role!=='system').map(m=>({role:m.role==='assistant'?'model':'user',parts:[{text:m.content}]})),
    generationConfig:{maxOutputTokens:tokens,thinkingConfig:{thinkingBudget:0}},
   }:{messages:command.messages,max_tokens:tokens,stream:false};
   if(id==='gemini'){
    const system=command.messages.filter(m=>m.role==='system').map(m=>({text:m.content}));
    if(system.length)body.systemInstruction={parts:system};
   }else if(id!=='cloudflare')body.model=spec.model;
   if(id==='openrouter'){
    // No model routing to paid endpoints; cap endpoint prices at zero too.
    body.provider={max_price:{prompt:0,completion:0},allow_fallbacks:false};
   }
   const response=await fetchImpl(url,{method:'POST',redirect:'manual',credentials:'omit',
    headers:{'Content-Type':'application/json',Accept:'application/json',
     ...(id==='gemini'?{'x-goog-api-key':env[spec.key]}:{Authorization:'Bearer '+env[spec.key]})},
    body:JSON.stringify(body),signal:AbortSignal.timeout(FREE_AI_LIMITS.timeoutMs)});
   s.lastHttpStatus=response.status;
   if([401,402,403].includes(response.status)){s.stop=true;return deny(503,'provider-auth-or-budget-refused');}
   if(response.status!==200){s.coolUntil=now+60000;return deny(503,'provider-unavailable');}
   const data=await readBoundedJson(response,FREE_AI_LIMITS.maxResponseBytes);
   if([data?.usage?.cost,data?.usage?.total_cost].some(v=>typeof v==='number'&&v>0)){
    s.stop=true;return deny(503,'paid-usage-reported');
   }
   const raw=id==='gemini'?(data?.candidates?.[0]?.content?.parts||[])
    .filter(p=>p?.thought!==true&&typeof p?.text==='string').map(p=>p.text).join('')
    :id==='cloudflare'?data?.result?.response:data?.choices?.[0]?.message?.content;
   if(typeof raw!=='string'||!raw.trim())return deny(503,'empty-answer');
   // Redact this provider's own key even when its format is not recognized.
   const safe=redactSecrets(raw.split(env[spec.key]).join('[REDACTED]').slice(0,FREE_AI_LIMITS.maxAnswerChars));
   return {status:200,result:{ok:true,provider:id,model:spec.model,text:safe.text,
    freeTierConfirmed:true,costVerified:false}};
  }catch(error){
   const code=failureCode(error);
   return deny(503,['timeout','aborted','network'].includes(code)?code:'provider-request-failed');
  }
  finally{s.active=false;}
 }
 return {chat,info:()=>({enabled:ids.some(id=>configs[id].enabled),signedServerToServerOnly:true,
  automaticFallback:false,costVerified:false,limits,
  providers:ids.map(id=>({id,model:REGISTERED_AI_PROVIDERS[id].model,...configs[id],
   codeRolesAllowed:configs[id].privatePrompts,requestsToday:state[id].count,lastHttpStatus:state[id].lastHttpStatus}))})};
}
