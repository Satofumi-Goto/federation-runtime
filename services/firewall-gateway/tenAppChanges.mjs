// Sends only durable change hints. A timer exists solely while a change/retry is pending.
import {CHANGE_SCHEMA,CHANGE_URL,signChange,validChange} from './tenAppChangeContract.mjs';
function selectedKey(env){try{const source=env.FIREWALL_TEN_APP_CHANGE_KEY_SOURCE||'free-ai';if(source==='free-ai')return env.FIREWALL_FREE_AI_FEDERATION_KEY||'';const ring=JSON.parse(env.FIREWALL_CLIENT_KEYS_JSON||'{}').federation,keys=Array.isArray(ring)?ring:[ring];return source==='main-current'?keys[0]||'':source==='main-next'?keys[1]||'':'';}catch{return '';}}
export function createTenAppChanges({env=process.env,store,fetchImpl=fetch,clock=Date.now,setTimer=setTimeout,clearTimer=clearTimeout,observe=()=>{},debounceMs=5000}={}){
 const key=selectedKey(env),enabled=env.FIREWALL_TEN_APP_CHANGE_NOTIFY_ENABLED==='true'&&/^[A-Za-z0-9_-]{43}$/.test(key)&&typeof store?.readPendingChange==='function'&&typeof store?.ackPendingChange==='function';
 let timer=null,running=false,stopped=false,queued=false,failures=0;
 const emit=result=>{try{observe({type:'firewall.ten-app-change',...result});}catch{}};
 const schedule=delay=>{if(!enabled||stopped||timer)return;timer=setTimer(()=>{timer=null;void drain();},delay);timer.unref?.();};
 async function drain(){if(stopped||!enabled)return;if(running){queued=true;return;}running=true;queued=false;
  try{
   const result=await store.readPendingChange();if(!result?.ok)throw Error('pending-store-unavailable');if(!result.marker){failures=0;return;}
   let marker;try{marker=JSON.parse(result.marker);}catch{throw Error('pending-marker-invalid');}
   const command={schema:CHANGE_SCHEMA,source:'firewall-gateway',eventId:marker.eventId,kind:marker.kind};if(!validChange(command))throw Error('pending-marker-invalid');
   const raw=JSON.stringify(command),response=await fetchImpl(CHANGE_URL,{method:'POST',redirect:'error',credentials:'omit',signal:AbortSignal.timeout(4000),headers:signChange(raw,key,clock()),body:raw});
   if(!response.ok){await response.body?.cancel();throw Error('callback-unconfirmed');}
   const text=await response.text();if(text.length>4096)throw Error('callback-invalid');let ack;try{ack=JSON.parse(text);}catch{throw Error('callback-invalid');}
   if(ack.ok!==true||ack.schema!==CHANGE_SCHEMA||ack.eventId!==marker.eventId||typeof ack.accepted!=='boolean')throw Error('callback-invalid');
   const cleared=await store.ackPendingChange(result.marker);if(!cleared?.ok)throw Error('pending-ack-unconfirmed');
   failures=0;emit({state:'acknowledged',accepted:ack.accepted});
   // A newer marker arriving during transmission must survive this ACK.
   const next=await store.readPendingChange();if(!next?.ok)throw Error('pending-store-unavailable');if(next.marker||queued)schedule(debounceMs);
  }catch(error){emit({state:'pending',reason:/^[a-z-]{1,50}$/.test(error.message)?error.message:'callback-unavailable'});schedule(Math.min(300000,1000*2**Math.min(failures++,8)));}
  finally{running=false;}
 }
 return {enabled,changed(){if(!enabled||stopped)return;if(running)queued=true;else schedule(debounceMs);},start(){if(!enabled)return;stopped=false;schedule(0);},stop(){stopped=true;clearTimer(timer);timer=null;}};
}
