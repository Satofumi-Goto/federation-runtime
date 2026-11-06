import test from 'node:test';
import assert from 'node:assert/strict';
import {createMemoryStore,createRedisRestStore,storeFromEnv,createSharedGuards} from '../store.mjs';

// In-process fake of the Upstash REST /pipeline contract (SET NX PX, INCR, PEXPIRE NX, LPUSH, LTRIM).
function fakeRedis({clock}){
 const data=new Map(),calls=[];
 const live=k=>{const v=data.get(k);if(v&&v.exp&&v.exp<=clock()){data.delete(k);return undefined;}return v;};
 const run=([cmd,...a])=>{
  if(cmd==='SET'){if(live(a[0]))return null;data.set(a[0],{v:a[1],exp:clock()+Number(a[4])});return 'OK';}
  if(cmd==='INCR'){const v=live(a[0])||{v:0,exp:0};v.v=Number(v.v)+1;data.set(a[0],v);return v.v;}
  if(cmd==='PEXPIRE'){const v=live(a[0]);if(!v||v.exp)return 0;v.exp=clock()+Number(a[1]);return 1;}
  if(cmd==='LPUSH'){const v=live(a[0])||{v:[],exp:0};v.v.unshift(a[1]);data.set(a[0],v);return v.v.length;}
  if(cmd==='LTRIM'){const v=live(a[0]);if(v)v.v=v.v.slice(Number(a[1]),Number(a[2])+1);return 'OK';}
  return {error:'unknown'};
 };
 const fetchImpl=async(url,init)=>{
  calls.push({url,init});
  const body=JSON.parse(init.body);
  return new Response(JSON.stringify(body.map(c=>({result:run(c)}))),{status:200,headers:{'content-type':'application/json'}});
 };
 return {fetchImpl,calls,data};
}
const URL_OK='https://example-store.upstash.io';
const TOKEN='A'.repeat(40);

test('memory store is honest about being per-process',async()=>{
 let now=1_000_000;
 const s=createMemoryStore({clock:()=>now});
 assert.equal(s.distributed,false);
 assert.deepEqual(await s.claimOnce('nonce:a:1',1000),{ok:true,claimed:true});
 assert.deepEqual(await s.claimOnce('nonce:a:1',1000),{ok:true,claimed:false});
 now+=1001;
 assert.deepEqual(await s.claimOnce('nonce:a:1',1000),{ok:true,claimed:true});
 const full=createMemoryStore({clock:()=>now,maxKeys:1});
 await full.claimOnce('k1',1000);
 assert.deepEqual(await full.claimOnce('k2',1000),{ok:false,reason:'store-full'});
});

test('two gateway instances sharing one Redis store refuse a replayed nonce',async()=>{
 let now=2_000_000;
 const redis=fakeRedis({clock:()=>now});
 const a=createSharedGuards(createRedisRestStore({url:URL_OK,token:TOKEN,fetchImpl:redis.fetchImpl}));
 const b=createSharedGuards(createRedisRestStore({url:URL_OK,token:TOKEN,fetchImpl:redis.fetchImpl}));
 assert.equal(a.distributed,true);
 assert.deepEqual(await a.replay('activity','n-1'),{ok:true});
 assert.deepEqual(await b.replay('activity','n-1'),{ok:false,status:409,reason:'replay-refused'});
 assert.deepEqual(await b.replay('fleet','n-1'),{ok:true});
 const sent=redis.calls[0];
 assert.equal(sent.url,URL_OK+'/pipeline');
 assert.equal(sent.init.redirect,'manual');
 assert.equal(sent.init.credentials,'omit');
});

test('request budget is shared across instances and resets per window',async()=>{
 let now=3_000_000*60000;
 const redis=fakeRedis({clock:()=>now});
 const mk=()=>createSharedGuards(createRedisRestStore({url:URL_OK,token:TOKEN,fetchImpl:redis.fetchImpl}),{limits:{total:3,perClient:2}});
 const a=mk(),b=mk();
 assert.equal((await a.budget('activity',now)).ok,true);
 assert.equal((await b.budget('activity',now)).ok,true);
 const third=await a.budget('activity',now);
 assert.equal(third.status,429);
 assert.equal((await b.budget('fleet',now)).status,429,'total limit counts every client');
 now+=60000;
 assert.equal((await b.budget('activity',now)).ok,true);
});

test('store failures fail closed (deny), never allow',async()=>{
 const broken=[
  async()=>{throw Error('network');},
  async()=>new Response('nope',{status:500}),
  async()=>new Response('<html>',{status:200,headers:{'content-type':'text/html'}}),
  async()=>new Response(JSON.stringify([{error:'ERR'}]),{status:200,headers:{'content-type':'application/json'}}),
  async()=>new Response('',{status:307,headers:{location:'https://evil.example'}}),
  async()=>new Response(JSON.stringify([{result:'OK'}]),{status:200,headers:{'content-type':'application/json','content-length':'999999'}}),
 ];
 for(const fetchImpl of broken){
  const g=createSharedGuards(createRedisRestStore({url:URL_OK,token:TOKEN,fetchImpl}));
  assert.equal((await g.replay('activity','n')).status,503);
  assert.equal((await g.budget('activity',0)).status,503);
 }
});

test('store URL and token are validated; no silent fallback to memory',()=>{
 for(const url of ['http://x.upstash.io','https://evil.example','https://u:p@x.upstash.io','https://x.upstash.io:8443','https://x.upstash.io/path','https://169.254.169.254'])
  assert.throws(()=>createRedisRestStore({url,token:TOKEN}),/invalid-store-url/);
 assert.throws(()=>createRedisRestStore({url:URL_OK,token:'short'}),/invalid-store-token/);
 assert.equal(storeFromEnv({}).store.distributed,false);
 assert.deepEqual(storeFromEnv({FIREWALL_STORE:'redis-rest'}),{store:null,error:'invalid-store-url'});
 assert.deepEqual(storeFromEnv({FIREWALL_STORE:'other'}),{store:null,error:'store-mode-invalid'});
 assert.equal(storeFromEnv({FIREWALL_STORE:'redis-rest',FIREWALL_STORE_REST_URL:URL_OK,FIREWALL_STORE_REST_TOKEN:TOKEN}).store.kind,'redis-rest');
});

test('audit records are size-bounded and trimmed; token never appears in records',async()=>{
 const redis=fakeRedis({clock:()=>0});
 const s=createRedisRestStore({url:URL_OK,token:TOKEN,fetchImpl:redis.fetchImpl,maxAudit:2});
 for(let i=0;i<3;i++)assert.deepEqual(await s.appendAudit({type:'firewall.shadow.request',i}),{ok:true});
 assert.equal(redis.data.get('fw:audit').v.length,2);
 assert.deepEqual(await s.appendAudit({big:'x'.repeat(3000)}),{ok:false,reason:'audit-record-too-large'});
 assert.ok(![...redis.data.values()].some(v=>JSON.stringify(v.v).includes(TOKEN)));
});
