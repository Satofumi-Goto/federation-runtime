// Shared Render Key Value (Valkey/Redis RESP2) guard store.
// Node built-in socket client, private in-region endpoint, no dependencies.
// Free Render KV is NON-DURABLE and may restart; never call it immutable audit.
import net from 'node:net';
const KEY=/^[A-Za-z0-9:_.-]{1,200}$/;
const RENDER_HOST=/^red-[a-z0-9]{12,48}$/;
const MAX_REPLY=65536;
function checkKey(key){if(typeof key!=='string'||!KEY.test(key))throw Error('invalid-store-key');}
function checkTtl(ms){if(!Number.isInteger(ms)||ms<1000||ms>86400000)throw Error('invalid-store-ttl');}
function command(args){
 if(!Array.isArray(args)||args.length<1||args.length>8)throw Error('invalid-command');
 const chunks=[Buffer.from('*'+args.length+'\r\n')];
 for(const a of args){
  if(typeof a!=='string'||Buffer.byteLength(a)>2500)throw Error('invalid-argument');
  const value=Buffer.from(a,'utf8');
  chunks.push(Buffer.from('$'+value.length+'\r\n'),value,Buffer.from('\r\n'));
 }
 return Buffer.concat(chunks);
}
const MAX_ARRAY=1000;
function parse(buf,from=0){
 if(buf.length<=from)return null;
 const type=String.fromCharCode(buf[from]);
 const end=buf.indexOf('\r\n',from+1,'utf8');
 if(end<0)return null;
 const head=buf.subarray(from+1,end).toString('utf8'),next=end+2;
 if(type==='-')throw Error('redis-command-rejected');
 if(type==='+')return {value:head,next};
 if(type===':'){
  if(!/^-?\d{1,18}$/.test(head))throw Error('redis-number-invalid');
  const number=Number(head);
  if(!Number.isSafeInteger(number))throw Error('redis-number-invalid');
  return {value:number,next};
 }
 if(type==='$'){
  if(!/^-?\d{1,6}$/.test(head))throw Error('redis-bulk-invalid');
  const len=Number(head);
  if(len===-1)return {value:null,next};
  if(len<0||len>16384)throw Error('redis-bulk-invalid');
  if(buf.length<next+len+2)return null;
  if(buf[next+len]!==13||buf[next+len+1]!==10)throw Error('redis-bulk-invalid');
  return {value:buf.subarray(next,next+len).toString('utf8'),next:next+len+2};
 }
 // Arrays are accepted only for LRANGE of the audit list: bounded, bulk strings only.
 if(type==='*'){
  if(!/^-?\d{1,4}$/.test(head))throw Error('redis-array-invalid');
  const count=Number(head);
  if(count===-1)return {value:null,next};
  if(count<0||count>MAX_ARRAY)throw Error('redis-array-invalid');
  const items=[];let at=next;
  for(let i=0;i<count;i++){
   if(buf.length>at&&buf[at]!==36)throw Error('redis-array-invalid');
   const item=parse(buf,at);
   if(!item)return null;
   items.push(item.value);at=item.next;
  }
  return {value:items,next:at};
 }
 throw Error('redis-response-type-not-allowed');
}
export function createRenderValkeyStore({url,timeoutMs=1600,transport=net.createConnection,prefix='fw:',maxAudit=1000}={}){
 let endpoint;
 try{endpoint=new URL(url);}catch{throw Error('invalid-private-valkey-url');}
 if(endpoint.protocol!=='redis:'||endpoint.port!=='6379'||!RENDER_HOST.test(endpoint.hostname)
   ||!['','/'].includes(endpoint.pathname)||endpoint.search||endpoint.hash
   ||endpoint.username||endpoint.password)
  throw Error('invalid-private-valkey-url');
 if(!Number.isInteger(timeoutMs)||timeoutMs<250||timeoutMs>5000)throw Error('invalid-store-timeout');
 if(!/^[a-z0-9:_-]{1,32}$/.test(prefix))throw Error('invalid-store-prefix');
 async function run(commands,{maxReply=MAX_REPLY}={}){
  let frames;try{frames=Buffer.concat(commands.map(command));}catch{return null;}
  return new Promise(resolve=>{
   let socket,settled=false,data=Buffer.alloc(0),offset=0;
   const values=[];
   const finish=result=>{
    if(settled)return;settled=true;
    try{socket?.destroy();}catch{}
    resolve(result);
   };
   try{
    socket=transport({host:endpoint.hostname,port:6379});
    socket.setTimeout(timeoutMs,()=>finish(null));
    socket.once('error',()=>finish(null));
    socket.once('close',()=>finish(null));
    socket.once('connect',()=>{try{socket.write(frames);}catch{finish(null);}});
    socket.on('data',chunk=>{
     if(settled)return;
     try{
      data=Buffer.concat([data,chunk]);
      if(data.length>maxReply)return finish(null);
      while(values.length<commands.length){
       const reply=parse(data,offset);
       if(!reply)break;
       values.push(reply.value);offset=reply.next;
      }
      if(values.length===commands.length)finish(values);
     }catch{finish(null);}
    });
   }catch{finish(null);}
  });
 }
 return{
  kind:'render-valkey',distributed:true,durable:false,
  async claimOnce(key,ttlMs){
   checkKey(key);checkTtl(ttlMs);
   const replies=await run([['SET',prefix+key,'1','NX','PX',String(ttlMs)]]);
   if(!replies)return {ok:false,reason:'store-unavailable'};
   if(replies[0]==='OK')return {ok:true,claimed:true};
   if(replies[0]===null)return {ok:true,claimed:false};
   return {ok:false,reason:'store-unavailable'};
  },
  async increment(key,ttlMs){
   checkKey(key);checkTtl(ttlMs);
   const replies=await run([['INCR',prefix+key],['PEXPIRE',prefix+key,String(ttlMs),'NX']]);
   if(!replies||!Number.isSafeInteger(replies[0])||replies[0]<1
      ||![0,1].includes(replies[1]))return {ok:false,reason:'store-unavailable'};
   return {ok:true,count:replies[0]};
  },
  async appendAudit(record){
   const line=JSON.stringify(record);
   if(line.length>2048)return {ok:false,reason:'audit-record-too-large'};
   const replies=await run([['LPUSH',prefix+'audit',line],['LTRIM',prefix+'audit','0',String(maxAudit-1)]]);
   if(!replies||!Number.isSafeInteger(replies[0])||replies[0]<1||replies[1]!=='OK')
    return {ok:false,reason:'store-unavailable'};
   return {ok:true};
  },
  async readAudit(limit){
   // Each record is at most 2048 bytes; the reply bound follows the requested count.
   const replies=await run([['LRANGE',prefix+'audit','0',String(limit-1)]],{maxReply:limit*2100+64});
   if(!replies||!Array.isArray(replies[0]))return {ok:false,reason:'store-unavailable'};
   return {ok:true,lines:replies[0].filter(l=>typeof l==='string')};
  }
 };
}
