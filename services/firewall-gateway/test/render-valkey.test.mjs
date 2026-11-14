import test from 'node:test';
import assert from 'node:assert/strict';
import net from 'node:net';
import {createRenderValkeyStore} from '../renderValkey.mjs';
import {storeFromEnv,createSharedGuards} from '../store.mjs';

const valid='redis://red-dbmo50ei0phs73cdg1f0:6379';
function readCommands(buffer){
 const commands=[];
 let offset=0;
 while(offset<buffer.length){
  if(buffer[offset]!==42)return null;
  const sep=buffer.indexOf('\r\n',offset);
  if(sep<0)return null;
  const argc=Number(buffer.subarray(offset+1,sep).toString());
  if(!Number.isInteger(argc)||argc<1||argc>8)throw Error('invalid-resp');
  const command=[];
  let pos=sep+2;
  for(let i=0;i<argc;i++){
   if(pos>=buffer.length)return null;
   if(buffer[pos]!==36)throw Error('invalid-bulk');
   const end=buffer.indexOf('\r\n',pos);
   if(end<0)return null;
   const size=Number(buffer.subarray(pos+1,end).toString());
   pos=end+2;
   if(!Number.isInteger(size)||size<0||size>2500)throw Error('invalid-size');
   if(buffer.length<pos+size+2)return null;
   command.push(buffer.subarray(pos,pos+size).toString());
   pos+=size+2;
  }
  commands.push(command);offset=pos;
 }
 return commands;
}
async function fakeValkey(callback){
 const keys=new Map(),list=[],seen=[];
 const server=net.createServer(socket=>{
  const parts=[];
  socket.on('data',b=>{
   parts.push(b);
   const input=Buffer.concat(parts);
   let commands;
   try{commands=readCommands(input);}catch{socket.destroy();return;}
   if(!commands)return;
   parts.length=0;
   const replies=[];
   for(const command of commands){
    seen.push(command[0]);
    const [op,key]=command;
    if(op==='SET'&&!command.includes('NX')){keys.set(key,command[2]);replies.push('+OK\r\n');}
    else if(op==='GET'){const v=keys.get(key);replies.push(typeof v==='string'?'$'+Buffer.byteLength(v)+'\r\n'+v+'\r\n':'$-1\r\n');}
    else if(op==='DEL'){replies.push(':'+(keys.delete(key)?1:0)+'\r\n');}
    else if(op==='SET'){
     if(keys.has(key))replies.push('$-1\r\n');
     else{keys.set(key,1);replies.push('+OK\r\n');}
    }else if(op==='INCR'){
     const n=(keys.get(key)||0)+1;keys.set(key,n);
     replies.push(':'+n+'\r\n');
    }else if(op==='PEXPIRE')replies.push(':1\r\n');
    else if(op==='LPUSH'){
     list.unshift(command[2]);replies.push(':'+list.length+'\r\n');
    }else if(op==='LTRIM'){
     list.splice(Number(command[3])+1);replies.push('+OK\r\n');
    }else if(op==='LRANGE'){
     const items=list.slice(Number(command[2]),Number(command[3])+1);
     replies.push('*'+items.length+'\r\n'+items.map(i=>'$'+Buffer.byteLength(i)+'\r\n'+i+'\r\n').join(''));
    }else{socket.write('-ERR invalid request\r\n');return;}
   }
   socket.write(replies.join(''));
  });
 });
 await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
 const port=server.address().port;
 const transport=()=>net.createConnection({host:'127.0.0.1',port});
 try{await callback({transport,keys,seen,list});}
 finally{await new Promise(resolve=>server.close(resolve));}
}
test('Render private endpoint must be exact Redis-internal host, no outbound or credentials',()=>{
 for(const url of [
  'https://red-dbmo50ei0phs73cdg1f0:6379',
  'redis://example.com:6379',
  'redis://red-dbmo50ei0phs73cdg1f0:6380',
  'redis://user:password@red-dbmo50ei0phs73cdg1f0:6379',
  'redis://red-dbmo50ei0phs73cdg1f0:6379/a',
  'redis://red-dbmo50ei0phs73cdg1f0:6379/?x=1',
 ]){
  assert.throws(()=>createRenderValkeyStore({url}),/invalid-private-valkey-url/);
 }
 const bad=storeFromEnv({FIREWALL_STORE:'render-valkey',FIREWALL_STORE_INTERNAL_URL:'redis://bad.example:6379'});
 assert.equal(bad.store,null);assert.equal(bad.error,'render-valkey-config-invalid');
});
test('shared replay, rate and audit work on different Redis connections',async()=>{
 await fakeValkey(async({transport,seen,list})=>{
  const env={FIREWALL_STORE:'render-valkey',FIREWALL_STORE_INTERNAL_URL:valid};
  const {store,error}=storeFromEnv(env);
  assert.equal(error,null);
  assert.equal(store.kind,'render-valkey');assert.equal(store.distributed,true);
  assert.equal(store.durable,false);
  const s1=createRenderValkeyStore({url:valid,transport});
  const s2=createRenderValkeyStore({url:valid,transport});
  const g1=createSharedGuards(s1),g2=createSharedGuards(s2);
  assert.equal((await g1.replay('activity','nonce-1')).ok,true);
  assert.equal((await g2.replay('activity','nonce-1')).status,409);
  for(let i=0;i<6;i++)assert.equal((await g1.budget('activity',0)).ok,true);
  assert.equal((await g2.budget('activity',0)).status,429);
  assert.equal((await s2.appendAudit({client:'activity',at:'fixed',kind:'shadow-probe'})).ok,true);
  assert.equal(list.length,1);
  assert.deepEqual(seen.filter(x=>x==='SET').length,2);
 });
});
test('downed or stalled socket fails closed within bounded time',async()=>{
 await fakeValkey(async({transport})=>{
  const store=createRenderValkeyStore({url:valid,transport});
  const bad=await store.claimOnce('../bad',2000).then(()=>null,e=>e);
  assert.match(bad.message,/invalid-store-key/);
  assert.equal((await store.claimOnce('safe',2000)).ok,true);
 });
 const unavailable=createRenderValkeyStore({url:valid,transport:()=>{
  const socket=net.createConnection({host:'127.0.0.1',port:1});
  return socket;
 }});
 assert.equal((await unavailable.claimOnce('safe',2000)).ok,false);
});


test('render-valkey mode automatically forces fail-closed shared guards at HTTP boundary',async()=>{
 const {createGatewayServer}=await import('../server.mjs');
 const {randomBytes}=await import('node:crypto');
 const {signHeaders}=await import('../auth.mjs');
 const key=randomBytes(32),body='{"routeId":"japan-holidays"}';
 const app=createGatewayServer({env:{
  FIREWALL_STORE:'render-valkey',
  FIREWALL_CLIENT_KEYS_JSON:JSON.stringify({activity:key.toString('base64url')}),
  FIREWALL_CANARY_EGRESS:'false',
 }});
 await new Promise(resolve=>app.server.listen(0,'127.0.0.1',resolve));
 try{
  const base='http://127.0.0.1:'+app.server.address().port;
  const status=await (await fetch(base+'/api/status')).json();
  assert.equal(status.sharedSecurity.mode,'render-valkey');
  assert.equal(status.sharedSecurity.required,true);
  assert.equal(status.sharedSecurity.configured,false);
  const response=await fetch(base+'/api/v1/shadow/probe',{
   method:'POST',
   headers:{'Content-Type':'application/json',
    ...signHeaders({client:'activity',key,body})},
   body
  });
  assert.equal(response.status,503);
  assert.equal((await response.json()).reason,'security-store-unavailable');
 }finally{await new Promise(resolve=>app.server.close(resolve));}
});

test('audit list can be read back newest-first through LRANGE, bounded and bulk-only',async()=>{
 await fakeValkey(async({transport})=>{
  const s=createRenderValkeyStore({url:valid,transport});
  for(let i=0;i<3;i++)assert.deepEqual(await s.appendAudit({type:'firewall.test',i}),{ok:true});
  const r=await s.readAudit(2);
  assert.equal(r.ok,true);
  assert.deepEqual(r.lines.map(l=>JSON.parse(l).i),[2,1]);
  const all=await s.readAudit(300);
  assert.equal(all.lines.length,3);
 });
});

test('危ないAPIの自動遮断は監査記録と分けた期限付きのキーに置き、別の接続から読み戻せる',async()=>{
 await fakeValkey(async({transport,keys,list})=>{
  const a=createRenderValkeyStore({url:valid,transport}),b=createRenderValkeyStore({url:valid,transport});
  const rows=[{key:'host:flaky.example.net',reason:'redirect-refused',until:'2026-11-14T01:00:00.000Z'}];
  assert.deepEqual(await a.saveRiskBlocks(rows,1800000),{ok:true});
  assert.equal(list.length,0);
  assert.deepEqual(await b.readRiskBlocks(),{ok:true,records:rows});
  assert.deepEqual(await a.saveRiskBlocks([],1000),{ok:true});
  assert.equal(keys.has('fw:risk-blocks'),false);
  assert.deepEqual(await b.readRiskBlocks(),{ok:true,records:[]});
 });
});
