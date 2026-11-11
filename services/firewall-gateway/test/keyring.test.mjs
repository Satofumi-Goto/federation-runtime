import test from 'node:test';
import assert from 'node:assert/strict';
import {randomBytes} from 'node:crypto';
import {createAuthenticator,loadKeyring,loadKeys,keyringHealth,signHeaders} from '../auth.mjs';
import {createGatewayServer} from '../server.mjs';

const NOW=Date.parse('2026-11-11T02:00:00.000Z');
const k=()=>randomBytes(32).toString('base64url');
const req=(headers,method='POST')=>({method,headers});
const PATH='/api/v1/shadow/probe';

test('a client can hold [current, next] keys; both verify, unknown keys do not',()=>{
 const current=k(),next=k(),other=k();
 const auth=createAuthenticator({env:{FIREWALL_CLIENT_KEYS_JSON:JSON.stringify({federation:[current,next]})},clock:()=>NOW});
 for(const key of [current,next]){
  const h=signHeaders({client:'federation',key:Buffer.from(key,'base64url'),body:'{}',path:PATH,time:NOW});
  assert.deepEqual(auth.verify(req(h),'{}',PATH),{ok:true,client:'federation'});
 }
 const bad=signHeaders({client:'federation',key:Buffer.from(other,'base64url'),body:'{}',path:PATH,time:NOW});
 assert.equal(auth.verify(req(bad),'{}',PATH).reason,'signature-invalid');
 assert.equal(loadKeys({FIREWALL_CLIENT_KEYS_JSON:JSON.stringify({federation:[current,next]})}).get('federation')
  .toString('base64url'),current);
});

test('keyring shape is strict: at most two distinct valid keys per client',()=>{
 const a=k();
 for(const bad of [[],[a,a],[a,k(),k()],['short'],[a,123]])
  assert.throws(()=>loadKeyring({FIREWALL_CLIENT_KEYS_JSON:JSON.stringify({federation:bad})}),/invalid-keys/);
 assert.equal(loadKeyring({FIREWALL_CLIENT_KEYS_JSON:JSON.stringify({federation:a})}).get('federation').length,1);
});

test('key health reports sharing, rotation and weak keys without key material',()=>{
 const shared=k(),weak='A'.repeat(43);
 const ring=loadKeyring({FIREWALL_CLIENT_KEYS_JSON:JSON.stringify({federation:[shared,k()],seneschal:shared,activity:weak})});
 const h=keyringHealth(ring);
 assert.deepEqual(h,{clientKeysDistinct:false,sharedKeyGroups:1,weakKeys:1,rotatingClients:['federation']});
 assert.ok(!JSON.stringify(h).includes(shared));
 assert.deepEqual(keyringHealth(loadKeyring({FIREWALL_CLIENT_KEYS_JSON:JSON.stringify({federation:k(),seneschal:k()})})),
  {clientKeysDistinct:true,sharedKeyGroups:0,weakKeys:0,rotatingClients:[]});
});

test('status exposes key health across main and dedicated keys',async()=>{
 const main=k();
 const app=createGatewayServer({clock:()=>NOW,auditSink:()=>{},env:{FIREWALL_CLIENT_KEYS_JSON:JSON.stringify({federation:main,seneschal:k()}),
  FIREWALL_FREE_AI_FEDERATION_KEY:main}});
 await new Promise(r=>app.server.listen(0,'127.0.0.1',r));
 try{
  const s=await (await fetch('http://127.0.0.1:'+app.server.address().port+'/api/status')).json();
  const ck=JSON.stringify(s).match(/"clientKeys":(\{[^}]*\})/);
  assert.ok(ck,'clientKeys present');
  assert.deepEqual(JSON.parse(ck[1]),{clientKeysDistinct:false,sharedKeyGroups:1,weakKeys:0,rotatingClients:[]});
  assert.ok(!JSON.stringify(s).includes(main));
 }finally{await new Promise(r=>app.server.close(r));}
});
