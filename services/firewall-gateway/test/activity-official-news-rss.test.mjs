import test from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { createGatewayServer } from '../server.mjs';
import { createActivityAcquisition, NEWS_SOURCE_IDS } from '../activitySources.mjs';
import { signHeaders } from '../auth.mjs';

const NOW=Date.parse('2026-11-08T00:00:00Z');
const KEY=randomBytes(32),PATH='/api/v1/activity/acquire';
const urls={
  meti:'https://www.meti.go.jp/ml_index_release_atom.xml',
  digital:'https://www.digital.go.jp/rss/news.xml',
};
test('government RSS routes are fixed, keyless, bounded and cannot be replaced with an arbitrary URL',async()=>{
  assert(NEWS_SOURCE_IDS.includes('meti'));
  assert(NEWS_SOURCE_IDS.includes('digital'));
  const calls=[];
  const rss=Buffer.from('<?xml version="1.0" encoding="UTF-8"?><rss><channel><item><title>新着情報</title><link>https://www.digital.go.jp/news</link></item></channel></rss>');
  const acquire=createActivityAcquisition({clock:()=>NOW,fetchImpl:async(url,opts)=>{
    calls.push(url);
    assert.equal(opts.method,'GET'); assert.equal(opts.credentials,'omit'); assert.equal(opts.redirect,'manual');
    assert.match(opts.headers.Accept,/xml/);
    return new Response(rss,{status:200,headers:{'content-type':'application/rss+xml'}});
  }});
  for(const name of ['meti','digital']){
    const data=await acquire.get(name);
    assert.equal(data.schema,'gateway.activity-raw/1');
    assert.equal(data.source,name);
    assert.equal(data.personalDataCollected,false);
    assert.equal(Buffer.from(data.data.body,'base64url').toString(),rss.toString());
    const cached=await acquire.get(name);
    assert.equal(cached.cached,true);
  }
  assert.deepEqual(calls,[urls.meti,urls.digital]);
  await assert.rejects(acquire.get('https://attacker.invalid'),/invalid-source/);
  assert.equal(calls.length,2);
});

test('government RSS accepts only Activity news key, never a browser, generic client or unsigned request',async()=>{
  const seen=[];
  const app=createGatewayServer({
    env:{FIREWALL_ACTIVITY_SOURCES_ENABLED:'true',FIREWALL_ACTIVITY_NEWS_KEY:KEY.toString('base64url')},
    clock:()=>NOW,fetchImpl:async(url)=>{seen.push(url);return new Response('<?xml version="1.0"?><rss/>');},
    auditSink:()=>{},
  });
  await new Promise(resolve=>app.server.listen(0,'127.0.0.1',resolve));
  const root='http://127.0.0.1:'+app.server.address().port;
  const call=async(source,header={})=>{
    const body=JSON.stringify({source});
    const headers={'content-type':'application/json',
      ...signHeaders({client:'activity',key:KEY,body,path:PATH,time:NOW}),...header};
    const r=await fetch(root+PATH,{method:'POST',headers,body});
    return {status:r.status,body:await r.json()};
  };
  try{
    assert.equal((await call('digital',{origin:'https://example.org'})).status,403);
    assert.equal((await call('meti')).status,200);
    assert.equal((await call('digital')).status,200);
    assert.equal((await call('source-not-allowlisted')).status,400);
    assert.deepEqual(seen,[urls.meti,urls.digital]);
  }finally{await new Promise(resolve=>app.server.close(resolve));}
});
