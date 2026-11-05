import test from 'node:test';
import assert from 'node:assert/strict';
import {randomBytes} from 'node:crypto';
import {createGatewayServer} from '../../services/firewall-gateway/server.mjs';
import {signHeaders} from '../../services/firewall-gateway/auth.mjs';

test('signed local HTTP E2E accepts authentication but refuses egress and replay',async()=>{
  const key=randomBytes(32);
  const env={
    FIREWALL_CLIENT_KEYS_JSON:JSON.stringify({activity:key.toString('base64url')}),
    FIREWALL_CANARY_EGRESS:'false',
  };
  const app=createGatewayServer({env,fetchImpl:async()=>{throw Error('upstream network must never be called')}});
  await new Promise(resolve=>app.server.listen(0,'127.0.0.1',resolve));
  const url='http://127.0.0.1:'+app.server.address().port;
  const body=JSON.stringify({routeId:'japan-holidays'});
  const sign=(input=body,params={})=>signHeaders({client:'activity',key,body:input,...params});
  const post=(text,headers)=>fetch(url+'/api/v1/shadow/probe',{
    method:'POST',headers:{'content-type':'application/json',...headers},body:text,redirect:'error'
  });
  try{
    const health=await (await fetch(url+'/api/status')).json();
    assert.equal(health.configuredClients,true);
    assert.equal(health.canaryEgressEnabled,false);
    assert.equal(health.cutoverEnabled,false);
    const signed=sign();
    const valid=await post(body,signed);
    assert.equal(valid.status,503);
    assert.equal((await valid.json()).reason,'egress-disabled');
    // The exact same signed nonce is not accepted twice.
    const replay=await post(body,signed);
    assert.equal(replay.status,409);
    assert.equal((await replay.json()).reason,'replay-refused');
    // A different payload cannot reuse an existing signature.
    const changed=await post(JSON.stringify({routeId:'jma-earthquake-list'}),sign());
    assert.equal(changed.status,401);
    assert.equal((await changed.json()).reason,'signature-invalid');
    const expired=await post(body,sign(body,{time:Date.now()-120000}));
    assert.equal(expired.status,401);
    assert.equal((await expired.json()).reason,'signature-required');
    const unsigned=await post(body,{});
    assert.equal(unsigned.status,401);
    assert.equal((await unsigned.json()).reason,'signature-required');
  }finally{
    await new Promise(resolve=>app.server.close(resolve));
  }
});
