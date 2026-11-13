import test from 'node:test';
import assert from 'node:assert/strict';
import {EventEmitter} from 'node:events';
import {createTenAppChanges} from '../tenAppChanges.mjs';
import {CHANGE_SCHEMA,CHANGE_URL,signChange,validChange} from '../tenAppChangeContract.mjs';
import {createRenderValkeyStore} from '../renderValkey.mjs';
const key=Buffer.alloc(32,7).toString('base64url');
const env={FIREWALL_TEN_APP_CHANGE_NOTIFY_ENABLED:'true',FIREWALL_FREE_AI_FEDERATION_KEY:key};
const marker=n=>JSON.stringify({eventId:`11111111-1111-4111-8111-${String(n).padStart(12,'0')}`,kind:'shadow-probe'});
const flush=()=>new Promise(resolve=>setImmediate(resolve));
function harness(options={}){
 let pending=options.pending??null,next=0;const timers=new Map(),calls=[],acks=[];
 const store={async readPendingChange(){return {ok:true,marker:pending};},async ackPendingChange(value){acks.push(value);const cleared=value===pending;if(cleared)pending=null;return {ok:true,cleared};}};
 const fetchImpl=options.fetchImpl??(async(url,request)=>{calls.push({url,request});return Response.json({ok:true,schema:CHANGE_SCHEMA,eventId:JSON.parse(request.body).eventId,accepted:true});});
 const notifier=createTenAppChanges({env,store,clock:()=>123456789,fetchImpl,setTimer(fn,delay){const t={id:++next,unref(){}};timers.set(t.id,{fn,delay});return t;},clearTimer(t){timers.delete(t?.id);},...options});
 return {notifier,timers,calls,acks,set pending(v){pending=v;},get pending(){return pending;},async fire(){const [id,t]=timers.entries().next().value;timers.delete(id);t.fn();await flush();}};
}
test('disabled notifier creates no timer or callback',()=>{
 const h=harness({env:{}});h.notifier.start();h.notifier.changed();assert.equal(h.notifier.enabled,false);assert.equal(h.timers.size,0);assert.equal(h.calls.length,0);
});
test('startup sends one boot hint then healthy idle leaves no recurring timer or callback',async()=>{
 const h=harness();h.notifier.start();await h.fire();assert.equal(h.timers.size,0);assert.equal(h.calls.length,1);assert.equal(JSON.parse(h.calls[0].request.body).kind,'gateway-started');assert.equal(h.acks.length,0);
 h.notifier.changed();await h.fire();assert.equal(h.timers.size,0);assert.equal(h.calls.length,1);
});
test('burst sends latest marker once with fixed scoped signed request',async()=>{
 const h=harness();for(let n=1;n<=20;n++){h.pending=marker(n);h.notifier.changed();}
 assert.equal(h.timers.size,1);assert.equal([...h.timers.values()][0].delay,5000);await h.fire();assert.equal(h.calls.length,1);assert.equal(h.pending,null);assert.equal(h.timers.size,0);
 const {url,request}=h.calls[0];assert.equal(url,CHANGE_URL);assert.equal(request.method,'POST');assert.equal(request.redirect,'error');assert.equal(request.credentials,'omit');
 assert.deepEqual(request.headers,signChange(request.body,key,123456789));assert.equal(JSON.parse(request.body).eventId,JSON.parse(marker(20)).eventId);
});
test('inflight acknowledgement cannot erase a newer pending marker',async()=>{
 let release;const calls=[];const h=harness({pending:marker(1),fetchImpl:async(url,request)=>{calls.push(JSON.parse(request.body));if(calls.length===1)await new Promise(resolve=>{release=resolve;});return Response.json({ok:true,schema:CHANGE_SCHEMA,eventId:JSON.parse(request.body).eventId,accepted:true});}});
 h.notifier.start();await h.fire();h.pending=marker(2);h.notifier.changed();release();await flush();assert.equal(h.pending,marker(2));assert.equal(h.timers.size,1);await h.fire();assert.equal(calls.filter(c=>c.kind!=='gateway-started').length,2);assert.equal(calls.length,3);assert.equal(h.pending,null);assert.equal(h.timers.size,0);
});
test('failed callback retries only pending work and restart accepts duplicate acknowledgement',async()=>{
 const h=harness({pending:marker(1),fetchImpl:async()=>new Response('',{status:503})});h.notifier.start();await h.fire();assert.equal(h.pending,marker(1));assert.equal([...h.timers.values()][0].delay,1000);h.notifier.stop();assert.equal(h.timers.size,0);
 const recovered=harness({pending:h.pending,fetchImpl:async(url,r)=>Response.json({ok:true,schema:CHANGE_SCHEMA,eventId:JSON.parse(r.body).eventId,accepted:false})});recovered.notifier.start();await recovered.fire();assert.equal(recovered.pending,null);assert.equal(recovered.timers.size,0);
});
test('wrong acknowledgement leaves marker pending and export command is rejected',async()=>{
 const h=harness({pending:marker(1),fetchImpl:async()=>Response.json({ok:true,schema:CHANGE_SCHEMA,eventId:JSON.parse(marker(2)).eventId,accepted:true})});h.notifier.start();await h.fire();assert.equal(h.pending,marker(1));assert.equal(h.acks.length,0);assert.equal(h.timers.size,1);h.notifier.stop();
 assert.equal(validChange({schema:CHANGE_SCHEMA,source:'firewall-gateway',eventId:JSON.parse(marker(1)).eventId,kind:'audit-export'}),false);
});
// RESP transport fake checks the exact atomic commands without network or live data.
function valkeyHarness(){
 const seen=[],keys=new Map(),list=[];
 const bulk=v=>v==null?'$-1\r\n':`$${Buffer.byteLength(v)}\r\n${v}\r\n`;
 const transport=()=>{const socket=new EventEmitter();socket.setTimeout=()=>{};socket.destroy=()=>{};socket.write=buffer=>{
  const lines=buffer.toString().split('\r\n');const commands=[];let i=0;
  while(i<lines.length-1){const count=Number(lines[i++].slice(1)),command=[];for(let n=0;n<count;n++){assert.match(lines[i++],/^\$/);command.push(lines[i++]);}commands.push(command);}
  let reply='';for(const c of commands){seen.push(c);const [op,k]=c;
   if(op==='EVAL'&&c[2]==='2'){list.unshift(c[5]);list.splice(Number(c[6]));keys.set(c[4],c[7]);reply+=':1\r\n';}
   else if(op==='EVAL'){const cleared=keys.get(c[3])===c[4];if(cleared)keys.delete(c[3]);reply+=cleared?':1\r\n':':0\r\n';}
   else if(op==='GET')reply+=bulk(keys.get(k));
   else if(op==='LPUSH'){list.unshift(c[2]);reply+=`:${list.length}\r\n`;}
   else if(op==='LTRIM'){list.splice(Number(c[3])+1);reply+='+OK\r\n';}
   else throw Error('unexpected-command');
  }queueMicrotask(()=>socket.emit('data',Buffer.from(reply)));
 };queueMicrotask(()=>socket.emit('connect'));return socket;};
 return {seen,keys,list,store:createRenderValkeyStore({url:'redis://red-dbmo50ei0phs73cdg1f0:6379',transport,notifyChanges:true})};
}
test('audit append uses one atomic EVAL and ACK compares the exact marker',async()=>{
 const h=valkeyHarness();assert.deepEqual(await h.store.appendAudit({kind:'shadow-probe'}),{ok:true,changePending:true});assert.equal(h.seen.length,1);
 const command=h.seen[0];assert.equal(command[0],'EVAL');for(const name of ['LPUSH','LTRIM','SET'])assert.ok(command[1].includes(`redis.call('${name}'`));
 const a=(await h.store.readPendingChange()).marker;assert.equal(JSON.parse(a).eventId,JSON.parse(h.list[0]).id);
 await h.store.appendAudit({kind:'assistant'});const b=(await h.store.readPendingChange()).marker;assert.notEqual(a,b);
 assert.deepEqual(await h.store.ackPendingChange(a),{ok:true,cleared:false});assert.equal((await h.store.readPendingChange()).marker,b);
 assert.deepEqual(await h.store.ackPendingChange(b),{ok:true,cleared:true});assert.equal((await h.store.readPendingChange()).marker,null);
});
test('audit-export does not replace pending marker or emit change hint',async()=>{
 const h=valkeyHarness();await h.store.appendAudit({kind:'shadow-probe'});const before=(await h.store.readPendingChange()).marker;const offset=h.seen.length;
 assert.deepEqual(await h.store.appendAudit({kind:'audit-export'}),{ok:true});assert.deepEqual(h.seen.slice(offset).map(c=>c[0]),['LPUSH','LTRIM']);assert.equal((await h.store.readPendingChange()).marker,before);
});

test('boot and audit slots drain fairly even when only the boot callback fails',async()=>{
 const calls=[];const h=harness({pending:marker(1),fetchImpl:async(url,r)=>{const command=JSON.parse(r.body);calls.push(command);return command.kind==='gateway-started'?Response.json({},{status:503}):Response.json({ok:true,schema:CHANGE_SCHEMA,eventId:command.eventId,accepted:true});}});
 h.notifier.start();await h.fire();assert.equal(calls.length,2);assert.equal(h.pending,null);assert.equal(h.acks.length,1);assert.equal(h.timers.size,1);
 h.pending=marker(2);await h.fire();assert.equal(calls.length,4);assert.equal(h.pending,null);assert.equal(calls[0].eventId,calls[2].eventId,'same boot epoch retries');h.notifier.stop();
});
test('stop/start rejects old boot ACK and old audit ACK while allowing the new generation to drain',async()=>{
 let release;const calls=[];const h=harness({pending:marker(1),fetchImpl:async(url,r)=>{const command=JSON.parse(r.body);calls.push(command);if(calls.length===1)await new Promise(resolve=>{release=resolve;});return Response.json({ok:true,schema:CHANGE_SCHEMA,eventId:command.eventId,accepted:true});}});
 h.notifier.start();await h.fire();h.notifier.stop();h.notifier.start();await h.fire();release();await flush();assert.equal(h.acks.length,0);assert.equal(h.pending,marker(1));assert.equal(h.timers.size,1);
 await h.fire();assert.equal(h.pending,null);assert.equal(h.acks.length,1);assert.equal(calls[0].eventId,calls[1].eventId,'notifier pause does not change server lifetime epoch');assert.equal(h.timers.size,0);h.notifier.stop();
});
test('startup hint never overwrites a superseding audit marker and duplicate boot ACK is valid',async()=>{
 const h=harness({pending:marker(1),fetchImpl:async(url,r)=>{const command=JSON.parse(r.body);if(command.kind==='gateway-started')h.pending=marker(2);return Response.json({ok:true,schema:CHANGE_SCHEMA,eventId:command.eventId,accepted:false});}});
 h.notifier.start();await h.fire();assert.equal(h.pending,marker(2));assert.equal(h.acks[0],marker(1));assert.equal(h.timers.size,1);await h.fire();assert.equal(h.pending,null);assert.equal(h.timers.size,0);h.notifier.stop();
});
