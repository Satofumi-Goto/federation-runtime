import test from 'node:test';
import assert from 'node:assert/strict';
import {randomBytes} from 'node:crypto';
import {createGatewayServer} from '../server.mjs';
import {signHeaders} from '../auth.mjs';

const CLIENT_KEY=randomBytes(32);
const KEYS=JSON.stringify({activity:CLIENT_KEY.toString('base64url')});
const REDIS_CONFIG={
 FIREWALL_CLIENT_KEYS_JSON:KEYS,
 FIREWALL_STORE:'redis-rest',
 FIREWALL_STORE_REST_URL:'https://firewall-example.upstash.io',
 FIREWALL_STORE_REST_TOKEN:'a'.repeat(30),
 FIREWALL_REQUIRE_DISTRIBUTED_STORE:'true',
 FIREWALL_CANARY_EGRESS:'false'
};
const body='{"routeId":"japan-holidays"}';
async function withApp(env,fetchImpl,run){
 const app=createGatewayServer({env,fetchImpl,auditSink:()=>{}});
 await new Promise(resolve=>app.server.listen(0,'127.0.0.1',resolve));
 const origin='http://127.0.0.1:'+app.server.address().port;
 try{
  async function signed(path='/api/v1/shadow/probe',data=body){
   const headers=signHeaders({client:'activity',key:CLIENT_KEY,body:data,path});
   const response=await fetch(origin+path,{method:'POST',
     headers:{'Content-Type':'application/json',...headers},body:data});
   return {status:response.status,data:await response.json()};
  }
  await run({origin,signed});
 }finally{await new Promise(resolve=>app.server.close(resolve));}
}
function redisMock({breakStore=false,breakAudit=false}={}){
 const seen=new Set(),counts=new Map(),audits=[];
 let outbound=0;
 const fetchImpl=async(url,init)=>{
  if(url!=='https://firewall-example.upstash.io/pipeline')throw Error('unexpected-provider-request');
  outbound++;
  if(breakStore)return Response.json({error:'down'}, {status:503});
  const commands=JSON.parse(init.body);
  const results=commands.map(command=>{
   const [op,key]=command;
   if(op==='SET'){
    if(seen.has(key))return {result:null};
    seen.add(key);return {result:'OK'};
   }
   if(op==='INCR'){
    const next=(counts.get(key)||0)+1;counts.set(key,next);return{result:next};
   }
   if(op==='PEXPIRE')return{result:1};
   if(op==='LPUSH'){
    if(breakAudit)return {error:'audit-unavailable'};
    audits.push(command[2]);return{result:audits.length};
   }
   if(op==='LTRIM')return{result:'OK'};
   throw Error('unapproved-store-command');
  });
  return Response.json(results);
 };
 return {fetchImpl,requests:()=>outbound,audits};
}

test('explicit distributed enforcement denies signed holiday calls if store is absent',async()=>{
 await withApp({
  FIREWALL_CLIENT_KEYS_JSON:KEYS,FIREWALL_REQUIRE_DISTRIBUTED_STORE:'true',
  FIREWALL_CANARY_EGRESS:'false'
 },async()=>{throw Error('not allowed to fetch a provider');},async({origin,signed})=>{
  const status=await (await fetch(origin+'/api/status')).json();
  assert.equal(status.sharedSecurity.required,true);
  assert.equal(status.sharedSecurity.configured,false);
  assert.equal(status.sharedSecurity.distributed,false);
  const result=await signed();
  assert.equal(result.status,503);
  assert.equal(result.data.reason,'security-store-unavailable');
 });
});

test('an invalid distributed store or unreachable Redis fails closed',async()=>{
 const m=redisMock({breakStore:true});
 await withApp(REDIS_CONFIG,m.fetchImpl,async({signed})=>{
  const result=await signed();
  assert.equal(result.status,503);
  assert.equal(result.data.reason,'replay-store-unavailable');
 });
 assert.equal(m.requests(),1,'no provider or second storage writes after outage');
});

test('healthy shared Redis claims nonce, enforces budgets and writes a metadata-only audit before egress',async()=>{
 const m=redisMock();
 await withApp(REDIS_CONFIG,m.fetchImpl,async({origin,signed})=>{
  const status=await (await fetch(origin+'/api/status')).json();
  assert.deepEqual(status.sharedSecurity,{
   mode:'redis-rest',required:true,configured:true,distributed:true
  });
  const result=await signed();
  assert.equal(result.status,503);
  assert.equal(result.data.reason,'egress-disabled');
 });
 assert.equal(m.requests(),4,'one replay, two budget commands, one audit pipeline');
 assert.equal(m.audits.length,1);
 const record=JSON.parse(m.audits[0]);
 assert.deepEqual(Object.keys(record).sort(),['at','client','id','kind','type']);
 assert.match(record.id,/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/);
 assert.equal(record.kind,'shadow-probe');
 assert.equal(record.client,'activity');
 assert.doesNotMatch(m.audits[0],/key|signature|holiday|question|bearer/i);
});

test('shared audit storage failure denies signed requests before any provider access',async()=>{
 const m=redisMock({breakAudit:true});
 await withApp(REDIS_CONFIG,m.fetchImpl,async({signed})=>{
  const result=await signed();
  assert.equal(result.status,503);
  assert.equal(result.data.reason,'security-audit-unavailable');
 });
 assert.equal(m.requests(),4);
});

test('existing memory-mode preview stays safe and backward compatible',async()=>{
 await withApp({FIREWALL_CLIENT_KEYS_JSON:KEYS,FIREWALL_CANARY_EGRESS:'false'},async()=>{
  throw Error('upstream must remain OFF');
 },async({origin,signed})=>{
  const status=await (await fetch(origin+'/api/status')).json();
  assert.equal(status.sharedSecurity.required,false);
  assert.equal(status.sharedSecurity.distributed,false);
  const result=await signed();
  assert.equal(result.status,503);
  assert.equal(result.data.reason,'egress-disabled');
 });
});


test('distributed nonce claim denies replay on a second server instance',async()=>{
 const m=redisMock();
 const nonce='12345678-1234-4123-8123-123456789abc';
 const headers=signHeaders({client:'activity',key:CLIENT_KEY,body,nonce});
 async function issue(){
  let status;
  await withApp(REDIS_CONFIG,m.fetchImpl,async({origin})=>{
   const response=await fetch(origin+'/api/v1/shadow/probe',{method:'POST',
    headers:{'Content-Type':'application/json',...headers},body});
   status={http:response.status,body:await response.json()};
  });
  return status;
 }
 const a=await issue(),b=await issue();
 assert.equal(a.http,503);
 assert.equal(a.body.reason,'egress-disabled');
 assert.equal(b.http,409);
 assert.equal(b.body.reason,'replay-refused');
 assert.equal(m.audits.length,1);
});

test('distributed per-client rate gate protects the signed endpoint across instances',async()=>{
 const m=redisMock();
 const responses=[];
 for(let index=0;index<7;index++){
  await withApp(REDIS_CONFIG,m.fetchImpl,async({signed})=>{
   responses.push(await signed());
  });
 }
 assert.deepEqual(responses.slice(0,6).map(x=>x.data.reason),Array(6).fill('egress-disabled'));
 assert.equal(responses[6].status,429);
 assert.equal(responses[6].data.reason,'upstream-budget-exhausted');
 assert.equal(m.audits.length,6);
});
