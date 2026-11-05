import {createHash,createHmac,timingSafeEqual,randomUUID} from 'node:crypto';
const CLIENTS=new Set(['activity','seneschal','fleet','urban','service','federation','simulator','remote-monitoring']);
export function loadKeys(env=process.env){
 if(!env.FIREWALL_CLIENT_KEYS_JSON)return new Map();
 if(env.FIREWALL_CLIENT_KEYS_JSON.length>8192)throw Error('invalid-keys');
 let parsed;
 try{parsed=JSON.parse(env.FIREWALL_CLIENT_KEYS_JSON);}catch{throw Error('invalid-keys');}
 if(!parsed||Array.isArray(parsed)||typeof parsed!=='object')throw Error('invalid-keys');
 const keys=new Map();
 for(const [id,value] of Object.entries(parsed)){
  if(!CLIENTS.has(id)||typeof value!=='string'||!/^[A-Za-z0-9_-]{43}$/.test(value))
   throw Error('invalid-keys');
  const key=Buffer.from(value,'base64url');
  if(key.length!==32||key.toString('base64url')!==value)throw Error('invalid-keys');
  keys.set(id,key);
 }
 return keys;
}
export function signHeaders({client,key,body,method='POST',path='/api/v1/shadow/probe',time=Date.now(),nonce=randomUUID()}){
 const hash=createHash('sha256').update(body).digest('hex');
 const message=['federation-firewall-hmac/1',client,method,path,String(time),nonce,hash].join('\n');
 return {'x-fw-client':client,'x-fw-time':String(time),'x-fw-nonce':nonce,
  'x-fw-signature':createHmac('sha256',key).update(message).digest('hex')};
}
export function createAuthenticator({env=process.env,clock=Date.now}={}){
 const keys=loadKeys(env),used=new Map();
 function verify(req,body,path){
  if(!keys.size)return {ok:false,status:503,reason:'service-auth-unconfigured'};
  const client=req.headers['x-fw-client'],time=req.headers['x-fw-time'];
  const nonce=req.headers['x-fw-nonce'],signature=req.headers['x-fw-signature'];
  if(typeof client!=='string'||!keys.has(client)||typeof time!=='string'
   ||!/^[0-9]{13}$/.test(time)||Math.abs(clock()-Number(time))>60000
   ||typeof nonce!=='string'||!/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(nonce)
   ||typeof signature!=='string'||!/^[0-9a-f]{64}$/.test(signature))
   return {ok:false,status:401,reason:'signature-required'};
  const supplied=Buffer.from(signature,'hex');
  const hash=createHash('sha256').update(body).digest('hex');
  const message=['federation-firewall-hmac/1',client,req.method,path,time,nonce,hash].join('\n');
  const correct=createHmac('sha256',keys.get(client)).update(message).digest();
  if(supplied.length!==correct.length||!timingSafeEqual(supplied,correct))
   return {ok:false,status:401,reason:'signature-invalid'};
  const now=clock();
  for(const [tag,seenAt] of used)if(now-seenAt>60000)used.delete(tag);
  const tag=client+':'+nonce;
  if(used.has(tag))return {ok:false,status:409,reason:'replay-refused'};
  if(used.size>=2000)return {ok:false,status:503,reason:'replay-store-full'};
  used.set(tag,now);
  return {ok:true,client};
 }
 return {verify,configured:keys.size>0};
}
