import test from 'node:test';
import assert from 'node:assert/strict';
import {createGatewayServer} from '../server.mjs';
test('independent app serves holding screen without changing application routes',async()=>{
 const app=createGatewayServer({env:{}});
 await new Promise(resolve=>app.server.listen(0,'127.0.0.1',resolve));
 const root='http://127.0.0.1:'+app.server.address().port;
 try{
  const health=await fetch(root+'/healthz');
  assert.equal(health.status,200);
  assert.equal((await health.json()).cutoverEnabled,false);
  const ui=await fetch(root+'/');
  assert.equal(ui.status,200);
  assert.match(await ui.text(),/SHADOW/);
  const admin=await fetch(root+'/admin');
  assert.equal(admin.status,503);
 }finally{await new Promise(resolve=>app.server.close(resolve));}
});
