// One-shot, public-read-only G0 baseline: Activity's existing holiday source
// versus its original provider. This is NOT a Firewall signed-E2E or cutover.
import assert from 'node:assert/strict';
import {pathToFileURL} from 'node:url';
const ACTIVITY='https://life-ledger-link.base44.app/api/apps/6a0bebc2df6284483f852302/functions/externalSignals';
const PROVIDER='https://holidays-jp.github.io/api/v1/date.json';
const MAX_BYTES=131072;
const DEFAULT_TIMEOUT=12000;
const acceptedURL=new Set([ACTIVITY,PROVIDER]);

async function boundedJson(response){
  if(!response.ok)throw Error('http-'+response.status);
  if(!/\bapplication\/(?:[\w.+-]+\+)?json\b/i.test(response.headers.get('content-type')||''))
    throw Error('invalid-response-type');
  if(Number(response.headers.get('content-length'))>MAX_BYTES)throw Error('response-too-large');
  const reader=response.body?.getReader();
  if(!reader)throw Error('no-response-stream');
  const chunks=[];let size=0;
  try{
    for(;;){
      const {value,done}=await reader.read();
      if(done)break;
      size+=value.byteLength;
      if(size>MAX_BYTES){await reader.cancel();throw Error('response-too-large');}
      chunks.push(value);
    }
  }finally{reader.releaseLock();}
  const bytes=new Uint8Array(size);let offset=0;
  for(const chunk of chunks){bytes.set(chunk,offset);offset+=chunk.length;}
  return JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(bytes));
}

export function normalizeHolidayForActivity(raw,now=Date.now()){
  assert.ok(raw&&typeof raw==='object'&&!Array.isArray(raw),'provider map required');
  const entries=Object.entries(raw);
  assert.ok(entries.length>0&&entries.length<=500,'provider record count invalid');
  assert.ok(entries.every(([date,label])=>/^\d{4}-\d{2}-\d{2}$/.test(date)
    &&typeof label==='string'&&label.trim()&&label.length<=120),'provider shape invalid');
  const today=new Date(now+9*3600000).toISOString().slice(0,10);
  const value=date=>typeof raw[date]==='string'&&raw[date].trim()?raw[date].trim().slice(0,30):null;
  return {today,isHoliday:!!raw[today],todayName:value(today),
    upcoming:entries.map(([date])=>date).filter(date=>date>=today).sort().slice(0,3)
      .map(date=>({date,name:value(date)}))};
}

export async function compareHolidayIncumbent({fetchImpl=fetch,now=Date.now,timeoutMs=DEFAULT_TIMEOUT}={}){
  const checkedAt=new Date(now()).toISOString();
  const calls=[];
  const fetchFixed=async(url,method,body)=>{
    assert.ok(acceptedURL.has(url),'unapproved upstream');
    const controller=new AbortController();
    const timeout=setTimeout(()=>controller.abort(),Math.min(15000,Math.max(1000,timeoutMs)));
    try{
      calls.push({origin: url===ACTIVITY?'activity':'holidays-jp',method});
      const response=await fetchImpl(url,{
        method,redirect:'error',credentials:'omit',signal:controller.signal,
        headers:{Accept:'application/json',...(body?{'Content-Type':'application/json'}:{})},
        ...(body?{body:JSON.stringify(body)}:{})
      });
      return await boundedJson(response);
    }finally{clearTimeout(timeout);}
  };
  try{
    // Strictly two fixed requests. The Activity 'only' selector avoids the full
    // multi-provider dashboard fetch; its internal address lookup remains owned
    // by the existing Activity implementation.
    const [provider,activity]=await Promise.all([
      fetchFixed(PROVIDER,'GET'),fetchFixed(ACTIVITY,'POST',{only:['holidays']})
    ]);
    assert.equal(activity?.version,'external-signals.v1','wrong Activity contract');
    const record=activity?.sources?.holidays;
    if(record?.status!=='ok')throw Error('activity-holidays-'+(record?.status||'missing'));
    const expected=normalizeHolidayForActivity(provider,now());
    const actual=record.data;
    assert.ok(actual&&typeof actual==='object','holiday data missing');
    const equal=JSON.stringify(expected)===JSON.stringify({
      today:actual.today,isHoliday:actual.isHoliday,todayName:actual.todayName,upcoming:actual.upcoming});
    return {ok:equal,phase:'G0-incumbent-baseline',checkedAt,
      comparison:equal?'normalized-holiday-parity':'normalized-holiday-mismatch',
      activityStatus:record.status,sourceFetchedAt:record.fetchedAt||null,
      nextHolidayCount:expected.upcoming.length,requests:calls,
      gatewaySignedE2e:false,cutover:false,legacyRetained:true};
  }catch(error){
    return {ok:false,phase:'G0-incumbent-baseline',checkedAt,
      reason:error?.name==='AbortError'?'timeout':String(error?.message||'unknown').slice(0,80),
      requests:calls,gatewaySignedE2e:false,cutover:false,legacyRetained:true};
  }
}
if(process.argv[1]&&import.meta.url===pathToFileURL(process.argv[1]).href){
  const report=await compareHolidayIncumbent();
  console.log(JSON.stringify(report));
  if(!report.ok)process.exitCode=1;
}
