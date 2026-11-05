// One-shot GitHub-signed holiday parity probe. No secrets printed, no app cutover.
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';

const gateway='https://federation-firewall-gateway.onrender.com';
const provider='https://holidays-jp.github.io/api/v1/date.json';
const apiPath='/api/v1/canary/github';
const body='{"routeId":"japan-holidays"}';
const audience='federation-firewall-holidays-canary/1';
const upperBytes=300000;
function validHolidayMap(data){
  assert.ok(data&&typeof data==='object'&&!Array.isArray(data),'invalid-holidays-shape');
  const entries=Object.entries(data);
  assert.ok(entries.length>0&&entries.length<=500,'invalid-holiday-record-count');
  for(const [date,label] of entries)assert.ok(
    /^\d{4}-\d{2}-\d{2}$/.test(date)&&typeof label==='string'&&
    label.trim()&&label.length<=120,'invalid-holiday-entry');
  const sorted=entries.sort(([left],[right])=>left.localeCompare(right));
  return {count:sorted.length,hash:createHash('sha256').update(JSON.stringify(sorted)).digest('hex')};
}
async function boundedJson(url,options,{maxBytes=upperBytes,timeout=15000}={}){
  const response=await fetch(url,{...options,redirect:'error',credentials:'omit',
    signal:AbortSignal.timeout(timeout)});
  const contentType=response.headers.get('content-type')||'';
  if(!/application\/json/i.test(contentType)||Number(response.headers.get('content-length'))>maxBytes)
    throw Error('invalid-content-contract');
  const reader=response.body?.getReader();
  if(!reader)throw Error('invalid-response-stream');
  let length=0;
  const parts=[];
  try{
    for(;;){
      const {value,done}=await reader.read();
      if(done)break;
      length+=value.length;
      if(length>maxBytes){await reader.cancel();throw Error('response-over-limit');}
      parts.push(value);
    }
  }finally{reader.releaseLock();}
  const bytes=Buffer.concat(parts.map(v=>Buffer.from(v)),length);
  return {status:response.status,data:JSON.parse(bytes.toString('utf8'))};
}
async function signedIdentity(){
  const base=process.env.ACTIONS_ID_TOKEN_REQUEST_URL;
  const requestToken=process.env.ACTIONS_ID_TOKEN_REQUEST_TOKEN;
  if(!base||!requestToken)throw Error('github-id-token-unavailable');
  const endpoint=new URL(base);
  if(endpoint.protocol!=='https:')throw Error('github-id-token-url-not-https');
  endpoint.searchParams.set('audience',audience);
  const result=await boundedJson(endpoint.href,{
    method:'GET',headers:{Authorization:'Bearer '+requestToken,Accept:'application/json'}},
    {maxBytes:24000,timeout:9000});
  if(result.status!==200||typeof result.data?.value!=='string'||
    result.data.value.length<100||result.data.value.length>12000)
    throw Error('github-id-token-failed');
  return result.data.value;
}
async function main(){
  // Check the live deployment remains isolated and specifically armed for this
  // one signed probe; do not attempt provider traffic on an unready deployment.
  const status=await boundedJson(gateway+'/api/status',{
    method:'GET',headers:{Accept:'application/json'}},
    {maxBytes:8192,timeout:65000});
  assert.equal(status.status,200,'firewall-status-http');
  assert.equal(status.data.stage,'shadow-hold');
  assert.equal(status.data.cutoverEnabled,false);
  assert.equal(status.data.legacyConnectionsPreserved,true);
  assert.equal(status.data.canaryEgressEnabled,true,'holiday-only-canary-not-armed');
  const jwt=await signedIdentity();
  // Never print or include the JWT in any thrown exception.
  const [viaGateway,incumbent]=await Promise.all([
    boundedJson(gateway+apiPath,{method:'POST',
      headers:{Authorization:'Bearer '+jwt,'Content-Type':'application/json',Accept:'application/json'},
      body},{maxBytes:upperBytes,timeout:12000}),
    boundedJson(provider,{method:'GET',headers:{Accept:'application/json'}},
      {maxBytes:131072,timeout:12000})
  ]);
  assert.equal(viaGateway.status,200,'signed-gateway-http');
  assert.equal(incumbent.status,200,'holiday-provider-http');
  const p=viaGateway.data;
  assert.equal(p.ok,true,'gateway-did-not-confirm-read');
  assert.equal(p.mode,'shadow-only');
  assert.equal(p.routeId,'japan-holidays');
  assert.equal(p.provider,'holidays-jp');
  assert.equal(p.sourceUrl,provider);
  assert.equal(p.cached,false,'gateway-returned-cached-not-new-canary');
  const age=Date.now()-Date.parse(String(p.fetchedAt));
  assert.ok(Number.isFinite(age)&&age>=-60000&&age<=180000,'gateway-freshness-invalid');
  const gatewayMap=validHolidayMap(p.data),originalMap=validHolidayMap(incumbent.data);
  assert.equal(gatewayMap.count,originalMap.count,'holiday-count-mismatch');
  assert.equal(gatewayMap.hash,originalMap.hash,'holiday-full-hash-mismatch');
  console.log(JSON.stringify({
    ok:true,mode:'one-shot-holiday-signed-canary',gatewayStatus:viaGateway.status,
    providerStatus:incumbent.status,records:gatewayMap.count,
    sha256:gatewayMap.hash,upstreamFetchedAt:p.fetchedAt,
    actualAppHmacE2e:false,cutover:false,legacyRetained:true,
    testedAt:new Date().toISOString()
  }));
}
main().catch(e=>{
  // Error details never contain JWTs, credentials or raw upstream JSON.
  console.error('holiday-canary-incomplete:',String(e?.message||'unknown').slice(0,100));
  process.exitCode=1;
});
