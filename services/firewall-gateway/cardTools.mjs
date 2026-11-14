// Federation のカードの道具（シミュレーション・CAD・BI）が使う外部の計算・データを、Gateway が代わりに取りに行く。
// - 依頼元は Federation の共通バックエンドだけ（HMAC 署名、client=federation）。ブラウザから直接は呼べない。
// - 取りに行く先は固定のテンプレートだけ。利用者が URL・ヘッダー・認証情報を指定することはできない。
// - 入力は数値（座標・日数）だけを検査して埋め込み、返すのは数値の要約だけ（上流の本文・地名・HTML は返さない）。
// - 既定は OFF。FIREWALL_CARD_TOOLS_ENABLED=true の時だけ外部へ接続する。費用のかかる API・鍵の要る API は使わない。
import {readBoundedJson} from './egress.mjs';

export const CARD_TOOLS_PATH='/api/v1/card-tools/fetch';
export const CARD_TOOLS_MAX_BODY=1024;
const TTL_MS=10*60_000;
const MAX_BYTES=262_144;
// 日本の範囲（離島を含む概略）。範囲外の座標は上流へ送らない
const inJapan=(lat,lon)=>lat>=20&&lat<=46&&lon>=122&&lon<=154;
const coord=(v)=>Array.isArray(v)&&v.length===2&&v.every((x)=>typeof x==='number'&&Number.isFinite(x))&&inJapan(v[0],v[1])?[Math.round(v[0]*1e5)/1e5,Math.round(v[1]*1e5)/1e5]:null;

export const CARD_TOOLS=Object.freeze({
  // 道路網の所要時間（OSRM の公開サーバー、自由流＝渋滞なし）。1地点から最大10地点まで
  'osrm-table':{label:'道路網の所要時間（OSRM）',provider:'osrm',license:'ODbL（OpenStreetMap）・OSRM 公開デモサーバーの利用規約（少量・非商用）',
    parse(params){
      const from=coord(params?.from); const to=Array.isArray(params?.to)?params.to.map(coord):null;
      if(!from||!to||!to.length||to.length>10||to.some((x)=>!x))return null;
      return {from,to};
    },
    url({from,to}){
      const pts=[from,...to].map(([lat,lon])=>`${lon},${lat}`).join(';');
      return `https://router.project-osrm.org/table/v1/driving/${pts}?sources=0&annotations=duration,distance`;
    },
    project(data,{to}){
      if(data?.code!=='Ok'||!Array.isArray(data.durations?.[0]))throw Error('upstream-invalid');
      const d=data.durations[0].slice(1),m=Array.isArray(data.distances?.[0])?data.distances[0].slice(1):[];
      if(d.length!==to.length)throw Error('upstream-invalid');
      return {durationsSec:d.map((x)=>(typeof x==='number'&&Number.isFinite(x)?Math.round(x):null)),distancesM:to.map((_,i)=>(typeof m[i]==='number'&&Number.isFinite(m[i])?Math.round(m[i]):null)),freeFlow:true};
    }},
  // 地点の1時間ごとの予報（Open-Meteo、鍵なし・非商用）。最大7日
  'open-meteo-hourly':{label:'地点の1時間ごとの予報（Open-Meteo）',provider:'open-meteo',license:'CC BY 4.0（Open-Meteo、非商用の無料枠）',
    parse(params){
      const at=coord(params?.at); const days=Number.isInteger(params?.days)&&params.days>=1&&params.days<=7?params.days:null;
      return at&&days?{at,days}:null;
    },
    url({at:[lat,lon],days}){
      return `https://api.open-meteo.com/v1/forecast?latitude=${lat}&longitude=${lon}&hourly=temperature_2m,precipitation,wind_speed_10m,shortwave_radiation&wind_speed_unit=ms&timezone=Asia%2FTokyo&forecast_days=${days}`;
    },
    project(data){
      const h=data?.hourly; if(!h||!Array.isArray(h.time))throw Error('upstream-invalid');
      const n=Math.min(h.time.length,24*7); const num=(a)=>(Array.isArray(a)?a.slice(0,n).map((x)=>(typeof x==='number'&&Number.isFinite(x)?x:null)):[]);
      return {time:h.time.slice(0,n).map((t)=>(typeof t==='string'&&/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}/.test(t)?t.slice(0,16):null)),temperatureC:num(h.temperature_2m),precipitationMm:num(h.precipitation),windMs:num(h.wind_speed_10m),shortwaveWm2:num(h.shortwave_radiation)};
    }},
});
export const CARD_TOOLS_POLICY=Object.freeze({version:'federation-firewall-card-tools/1',path:CARD_TOOLS_PATH,defaultEnabled:false,clients:['federation'],
  tools:Object.fromEntries(Object.entries(CARD_TOOLS).map(([id,t])=>[id,{label:t.label,provider:t.provider,license:t.license}])),
  limits:{concurrent:2,perMinute:20,perClientPerMinute:12,timeoutMs:4500,maxResponseBytes:MAX_BYTES,cacheTtlMs:TTL_MS}});

/** 依頼の本文 {tool, params} を検査する。 */
export function parseCardToolCommand(body){
  let data; try{data=JSON.parse(body);}catch{return {ok:false,status:400,error:'invalid-json'};}
  if(!data||typeof data!=='object'||Array.isArray(data)||Object.keys(data).some((k)=>!['tool','params'].includes(k)))return {ok:false,status:400,error:'invalid-command'};
  const tool=CARD_TOOLS[data.tool]; if(!tool)return {ok:false,status:400,error:'unknown-tool'};
  const params=tool.parse(data.params); if(!params)return {ok:false,status:400,error:'invalid-params'};
  return {ok:true,command:{tool:data.tool,params}};
}

export function createCardTools({env=process.env,fetchImpl=fetch,clock=Date.now}={}){
  const enabled=env.FIREWALL_CARD_TOOLS_ENABLED==='true';
  const cache=new Map(),started=new Map(); let active=0,total=0,windowStart=clock();
  const admit=(client)=>{const now=clock();if(now-windowStart>=60_000||now<windowStart){windowStart=now;total=0;started.clear();}
    if(active>=2||total>=20||(started.get(client)||0)>=12)return false;total++;started.set(client,(started.get(client)||0)+1);return true;};
  async function run(client,{tool,params}){
    if(!enabled)return {status:503,result:{ok:false,error:'card-tools-disabled'}};
    if(client!=='federation')return {status:403,result:{ok:false,error:'client-not-permitted'}};
    const t=CARD_TOOLS[tool]; const url=new URL(t.url(params));
    if(url.protocol!=='https:'||url.username||url.password||(url.port&&url.port!=='443'))return {status:503,result:{ok:false,error:'upstream-policy-invalid'}};
    const key=url.href; const hit=cache.get(key); const now=clock();
    if(hit&&now-hit.at<TTL_MS)return {status:200,result:{...hit.result,cached:true}};
    if(!admit(client))return {status:429,result:{ok:false,error:'rate-limited',retryAfterSeconds:60}};
    active++;
    try{
      const response=await fetchImpl(url.href,{method:'GET',redirect:'manual',credentials:'omit',headers:{Accept:'application/json','User-Agent':'FederationFirewall/0.1 (card-tools)'},signal:AbortSignal.timeout(4500)});
      const data=await readBoundedJson(response,MAX_BYTES);
      const result={ok:true,tool,provider:t.provider,license:t.license,fetchedAt:new Date(clock()).toISOString(),data:t.project(data,params)};
      cache.set(key,{at:clock(),result}); if(cache.size>200)cache.delete(cache.keys().next().value);
      return {status:200,result};
    }catch(e){return {status:502,result:{ok:false,error:['redirect-refused','response-too-large','invalid-content-type','upstream-invalid'].includes(e.message)?e.message:'upstream-unavailable'}};}
    finally{active--;}
  }
  return {enabled,run,info:()=>({enabled,cached:cache.size})};
}
