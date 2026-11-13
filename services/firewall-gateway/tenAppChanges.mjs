// Durable audit hints and a separate volatile boot hint share the existing signed
// callback. Timers exist only while work/retry is pending; no idle polling.
import {randomUUID} from 'node:crypto';
import {CHANGE_SCHEMA,CHANGE_URL,signChange,validChange} from './tenAppChangeContract.mjs';
function selectedKey(env){try{const source=env.FIREWALL_TEN_APP_CHANGE_KEY_SOURCE||'free-ai';if(source==='free-ai')return env.FIREWALL_FREE_AI_FEDERATION_KEY||'';const ring=JSON.parse(env.FIREWALL_CLIENT_KEYS_JSON||'{}').federation,keys=Array.isArray(ring)?ring:[ring];return source==='main-current'?keys[0]||'':source==='main-next'?keys[1]||'':'';}catch{return '';}}
export function createTenAppChanges({env=process.env,store,fetchImpl=fetch,clock=Date.now,setTimer=setTimeout,clearTimer=clearTimeout,observe=()=>{},debounceMs=5000}={}){
 const key=selectedKey(env),enabled=env.FIREWALL_TEN_APP_CHANGE_NOTIFY_ENABLED==='true'&&/^[A-Za-z0-9_-]{43}$/.test(key)&&typeof store?.readPendingChange==='function'&&typeof store?.ackPendingChange==='function';
 let timer=null,running=false,started=false,stopped=false,queued=false,failures=0,generation=0,bootPending=null;
 const emit=result=>{try{observe({type:'firewall.ten-app-change',...result});}catch{}};
 const schedule=delay=>{if(!enabled||stopped||timer)return;timer=setTimer(()=>{timer=null;void drain();},delay);timer.unref?.();};
 async function drain(){
  if(stopped||!enabled)return;if(running){queued=true;return;}running=true;queued=false;
  const own=generation,active=()=>!stopped&&own===generation;let failed=false;
  async function deliver(marker){
   const command={schema:CHANGE_SCHEMA,source:'firewall-gateway',eventId:marker.eventId,kind:marker.kind};if(!validChange(command))throw Error('invalid');
   const raw=JSON.stringify(command),response=await fetchImpl(CHANGE_URL,{method:'POST',redirect:'error',credentials:'omit',signal:AbortSignal.timeout(4000),headers:signChange(raw,key,clock()),body:raw});
   if(!active()){await response.body?.cancel();return null;}
   if(!response.ok){await response.body?.cancel();throw Error('unconfirmed');}
   const text=await response.text();if(!active())return null;if(text.length>4096)throw Error('invalid');const ack=JSON.parse(text);
   if(ack.ok!==true||ack.schema!==CHANGE_SCHEMA||ack.eventId!==marker.eventId||typeof ack.accepted!=='boolean')throw Error('invalid');return ack;
  }
  try{
   const boot=bootPending;let audit=null,auditRaw=null;
   try{const result=await store.readPendingChange();if(!active())return;if(!result?.ok)throw Error('unavailable');if(result.marker){auditRaw=result.marker;audit=JSON.parse(result.marker);}}catch{failed=true;}
   // Each drain attempts both slots once: a failed boot cannot starve audit,
   // and a coalesced audit marker can never overwrite the boot epoch.
   if(boot)try{const ack=await deliver(boot);if(!active())return;if(ack&&bootPending?.eventId===boot.eventId){bootPending=null;emit({state:'acknowledged',accepted:ack.accepted});}}catch{failed=true;}
   if(!active())return;
   if(audit)try{const ack=await deliver(audit);if(!active())return;if(ack){const cleared=await store.ackPendingChange(auditRaw);if(!active())return;if(!cleared?.ok)throw Error('unavailable');emit({state:'acknowledged',accepted:ack.accepted});}}catch{failed=true;}
   if(!active())return;
   let next;try{next=await store.readPendingChange();if(!next?.ok)throw Error('unavailable');}catch{failed=true;}
   if(!active())return;
   const pending=bootPending||next?.marker||queued||!next?.ok;
   if(failed&&pending){emit({state:'pending',reason:'callback-unavailable'});schedule(Math.min(300000,1000*2**Math.min(failures++,8)));}
   else{failures=0;if(pending)schedule(debounceMs);}
  }finally{running=false;if(!stopped&&own!==generation&&(bootPending||queued))schedule(0);}
 }
 return {enabled,
  changed(){if(!enabled||stopped)return;if(running)queued=true;else schedule(debounceMs);},
  start(){if(!enabled||started)return;started=true;stopped=false;generation++;bootPending={eventId:randomUUID(),kind:'gateway-started'};clearTimer(timer);timer=null;schedule(0);},
  stop(){stopped=true;started=false;generation++;queued=false;clearTimer(timer);timer=null;}
 };
}
