import test from 'node:test';
import assert from 'node:assert/strict';
import {randomBytes} from 'node:crypto';
import {createGatewayServer} from '../server.mjs';
import {signHeaders} from '../auth.mjs';
import {CARD_TOOLS_PATH,CARD_TOOLS_POLICY,parseCardToolCommand,createCardTools} from '../cardTools.mjs';

const NOW=Date.parse('2026-11-14T03:30:00.000Z');
const key=randomBytes(32).toString('base64url');
const env=(over={})=>({FIREWALL_CLIENT_KEYS_JSON:JSON.stringify({federation:key,seneschal:key}),FIREWALL_CARD_TOOLS_ENABLED:'true',...over});
const json=(data)=>new Response(JSON.stringify(data),{status:200,headers:{'content-type':'application/json'}});
const osrm={code:'Ok',durations:[[0,600,1200]],distances:[[0,5000,11000]]};
const cmd=(tool,params)=>JSON.stringify({tool,params});

async function withGateway(options,run){
  const app=createGatewayServer({clock:()=>NOW,auditSink:()=>{},...options});
  await new Promise((r)=>app.server.listen(0,'127.0.0.1',r));
  const origin='http://127.0.0.1:'+app.server.address().port;
  try{await run(origin,app);}finally{await new Promise((r)=>app.server.close(r));}
}
async function post(origin,body,{client='federation',headers={}}={}){
  const signed=signHeaders({client,key:Buffer.from(key,'base64url'),body,path:CARD_TOOLS_PATH,time:NOW});
  const r=await fetch(origin+CARD_TOOLS_PATH,{method:'POST',body,headers:{'content-type':'application/json',...signed,...headers}});
  return {status:r.status,data:await r.json()};
}
const recorder=(handler)=>{const calls=[];return {calls,fetchImpl:async(url,init)=>{if(!String(url).startsWith('https://'))return fetch(url,init);calls.push({url:String(url),init});return handler(String(url));}};};

test('カードの道具：入力は固定の道具と日本国内の座標・日数だけを受け付ける',()=>{
  assert.equal(parseCardToolCommand(cmd('osrm-table',{from:[35.68,139.76],to:[[35.7,139.8]]})).ok,true);
  assert.equal(parseCardToolCommand(cmd('osrm-table',{from:[35.68,139.76],to:Array(11).fill([35.7,139.8])})).error,'invalid-params');
  assert.equal(parseCardToolCommand(cmd('osrm-table',{from:[51.5,-0.1],to:[[35.7,139.8]]})).error,'invalid-params');
  assert.equal(parseCardToolCommand(cmd('osrm-table',{from:['35.68','139.76'],to:[[35.7,139.8]]})).error,'invalid-params');
  assert.equal(parseCardToolCommand(cmd('http-get',{url:'https://evil.example'})).error,'unknown-tool');
  assert.equal(parseCardToolCommand(JSON.stringify({tool:'osrm-table',params:{},url:'x'})).error,'invalid-command');
  assert.equal(parseCardToolCommand(cmd('open-meteo-hourly',{at:[35.68,139.76],days:8})).error,'invalid-params');
  assert.equal(parseCardToolCommand(cmd('open-meteo-hourly',{at:[35.68,139.76],days:3})).ok,true);
  assert.equal(CARD_TOOLS_POLICY.defaultEnabled,false);
  assert.deepEqual(CARD_TOOLS_POLICY.clients,['federation']);
});

test('カードの道具：既定は OFF。federation 以外の依頼元は拒否し、上流へは固定の URL だけを送る',async()=>{
  const off=createCardTools({env:{},fetchImpl:()=>{throw Error('no');},clock:()=>NOW});
  assert.equal((await off.run('federation',{tool:'osrm-table',params:{from:[35.68,139.76],to:[[35.7,139.8]]}})).status,503);
  const rec=recorder(()=>json(osrm));
  const on=createCardTools({env:{FIREWALL_CARD_TOOLS_ENABLED:'true'},fetchImpl:rec.fetchImpl,clock:()=>NOW});
  assert.equal((await on.run('seneschal',{tool:'osrm-table',params:{from:[35.68,139.76],to:[[35.7,139.8],[35.65,139.7]]}})).status,403);
  const r=await on.run('federation',{tool:'osrm-table',params:{from:[35.68,139.76],to:[[35.7,139.8],[35.65,139.7]]}});
  assert.equal(r.status,200); assert.deepEqual(r.result.data.durationsSec,[600,1200]); assert.deepEqual(r.result.data.distancesM,[5000,11000]);
  assert.equal(rec.calls[0].url,'https://router.project-osrm.org/table/v1/driving/139.76,35.68;139.8,35.7;139.7,35.65?sources=0&annotations=duration,distance');
  assert.equal(rec.calls[0].init.redirect,'manual'); assert.equal(rec.calls[0].init.credentials,'omit');
  // 同じ依頼は10分間キャッシュから返し、上流へは送らない
  const again=await on.run('federation',{tool:'osrm-table',params:{from:[35.68,139.76],to:[[35.7,139.8],[35.65,139.7]]}});
  assert.equal(again.result.cached,true); assert.equal(rec.calls.length,1);
});

test('カードの道具：予報の時刻は日時の形だけを返す（上流の文字列をそのまま渡さない）',async()=>{
  const t=createCardTools({env:{FIREWALL_CARD_TOOLS_ENABLED:'true'},fetchImpl:async()=>json({hourly:{time:['2026-11-14T12:00','<img src=x onerror=1>'],temperature_2m:[1,'x'],precipitation:[0,0],wind_speed_10m:[1,1],shortwave_radiation:[0,0]}}),clock:()=>NOW});
  const r=await t.run('federation',{tool:'open-meteo-hourly',params:{at:[35.68,139.76],days:1}});
  assert.deepEqual(r.result.data.time,['2026-11-14T12:00',null]); assert.deepEqual(r.result.data.temperatureC,[1,null]);
});

test('カードの道具：上流の転送・大きすぎる応答・形の違う応答は数値を返さない',async()=>{
  for(const [res,err] of [[new Response('',{status:302,headers:{location:'https://evil.example'}}),'redirect-refused'],[new Response('<html>',{status:200,headers:{'content-type':'text/html'}}),'invalid-content-type'],[json({code:'NoRoute'}),'upstream-invalid']]){
    const t=createCardTools({env:{FIREWALL_CARD_TOOLS_ENABLED:'true'},fetchImpl:async()=>res,clock:()=>NOW});
    const r=await t.run('federation',{tool:'osrm-table',params:{from:[35.68,139.76],to:[[35.7,139.8]]}});
    assert.equal(r.status,502); assert.equal(r.result.error,err);
  }
});

test('カードの道具：Gateway の入口は署名した federation だけを通し、ブラウザ由来の依頼を拒否する',async()=>{
  const rec=recorder(()=>json({hourly:{time:['2026-11-14T12:00'],temperature_2m:[15.2],precipitation:[0],wind_speed_10m:[3.1],shortwave_radiation:[220]}}));
  const audits=[];
  await withGateway({env:env(),fetchImpl:rec.fetchImpl,auditSink:(x)=>audits.push(JSON.parse(x))},async(origin)=>{
    const body=cmd('open-meteo-hourly',{at:[35.68,139.76],days:2});
    const ok=await post(origin,body); assert.equal(ok.status,200); assert.deepEqual(ok.data.data.windMs,[3.1]);
    assert.match(rec.calls[0].url,/^https:\/\/api\.open-meteo\.com\/v1\/forecast\?latitude=35\.68&longitude=139\.76&/);
    assert.equal((await post(origin,body,{headers:{origin:'https://evil.example'}})).status,403);
    const unsigned=await fetch(origin+CARD_TOOLS_PATH,{method:'POST',body,headers:{'content-type':'application/json'}}); assert.ok(unsigned.status>=400);
    assert.equal((await post(origin,cmd('osrm-table',{from:[0,0],to:[[0,0]]}))).status,400);
    const status=await (await fetch(origin+'/api/status')).json(); assert.equal(status.cardToolsEnabled,true);
  });
  // 監査には道具の名前だけを残し、座標・応答は残さない
  const a=audits.find((x)=>x.type==='firewall.card-tools.request'&&x.status===200);
  assert.equal(a.tool,'open-meteo-hourly'); assert.ok(!JSON.stringify(audits).includes('139.76'));
  await withGateway({env:env({FIREWALL_CARD_TOOLS_ENABLED:''}),fetchImpl:rec.fetchImpl},async(origin)=>{
    assert.equal((await post(origin,cmd('open-meteo-hourly',{at:[35.68,139.76],days:2}))).status,503);
  });
});
