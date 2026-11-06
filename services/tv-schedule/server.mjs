// Independent, read-only television schedule feed owned by Federation.
// No per-user data, dynamic upstream URLs, credentials, calendar writes or firewall cutover.
import http from 'node:http';
import {fileURLToPath} from 'node:url';
import {resolve} from 'node:path';
const PROVIDER='https://api.tvmaze.com';
const MAX_EPISODES=12;
const TTL=30*60*1000;
const MAX_BYTES=2*1024*1024;
const ORIGINS=new Set([
  'https://seneschal-standalone-staging.onrender.com',
  'https://seneschal-runtime.com',
  'https://seneschal.base44.app',
]);
const iso=ms=>new Date(ms).toISOString();
const jstDay=now=>new Date(now+9*3600000).toISOString().slice(0,10);
const trimmed=(x,n=120)=>typeof x==='string'?x.replace(/<[^>]+>/g,'').trim().slice(0,n):'';
const httpsUrl=x=>{try{const v=new URL(x);return v.protocol==='https:'&&!v.username&&!v.password?v.href:null;}catch{return null;}};
const castNames=raw=>Array.isArray(raw)?[...new Set(raw.map(x=>trimmed(x?.person?.name,100)).filter(Boolean))].slice(0,40):[];
function reply(res,status,body,{origin,cache=false}={}){
  const h={'Content-Type':'application/json; charset=utf-8','X-Content-Type-Options':'nosniff',
    'Referrer-Policy':'no-referrer','Cache-Control':cache?'public, max-age=120':'no-store',
    'Access-Control-Allow-Methods':'GET, OPTIONS','Vary':'Origin'};
  if(ORIGINS.has(origin))h['Access-Control-Allow-Origin']=origin;
  res.writeHead(status,h);res.end(JSON.stringify(body));
}
export function createTvScheduleService({fetchImpl=fetch,clock=Date.now}={}){
  let cache=null,ongoing=null;
  async function json(url,signal){
    // Every URL comes from fixed server-owned templates, never a request parameter.
    const parsed=new URL(url);
    if(parsed.protocol!=='https:'||parsed.origin!==PROVIDER||parsed.username||parsed.password)
      throw Error('upstream-denied');
    const r=await fetchImpl(url,{signal,headers:{Accept:'application/json'}});
    if(!r.ok)throw Error('upstream-http-'+r.status);
    if(Number(r.headers?.get?.('content-length'))>MAX_BYTES)throw Error('upstream-too-large');
    const bytes=await r.arrayBuffer();
    if(bytes.byteLength>MAX_BYTES)throw Error('upstream-too-large');
    return JSON.parse(new TextDecoder().decode(bytes));
  }
  async function fetchCast(url,signal){
    try{return castNames(await json(url,signal));}catch{return [];}
  }
  async function collect(){
    const controller=new AbortController();
    const timeout=setTimeout(()=>controller.abort(),25000);
    try{
      const now=clock();
      const days=[jstDay(now),jstDay(now+24*3600000)];
      const schedules=await Promise.all(days.map(day=>json(PROVIDER+'/schedule?country=JP&date='+day,controller.signal)));
      const unique=new Map();
      for(const ep of schedules.flat()){
        const start=Date.parse(ep?.airstamp||''),id=ep?.id;
        if(!Number.isSafeInteger(id)||id<=0||!Number.isFinite(start)||start<=now||
          start>now+48*3600000||unique.has(id))continue;
        unique.set(id,ep);
      }
      const soon=[...unique.values()].sort((a,b)=>Date.parse(a.airstamp)-Date.parse(b.airstamp)).slice(0,MAX_EPISODES);
      const showCastCache=new Map();
      // Bounded lookups. The 2-way batches avoid a burst of unbounded parallel calls.
      const items=[];
      for(let at=0;at<soon.length;at+=2){
        const batch=soon.slice(at,at+2);
        const enriched=await Promise.all(batch.map(async ep=>{
          const start=Date.parse(ep.airstamp),minutes=Number(ep.runtime);
          const showId=ep?.show?.id;
          let regulars=Promise.resolve([]);
          if(Number.isSafeInteger(showId)&&showId>0){
            if(!showCastCache.has(showId))
              showCastCache.set(showId,fetchCast(PROVIDER+'/shows/'+showId+'/cast',controller.signal));
            regulars=showCastCache.get(showId);
          }
          const [guestCast,showCast]=await Promise.all([
            fetchCast(PROVIDER+'/episodes/'+ep.id+'/guestcast',controller.signal),regulars
          ]);
          const endOk=Number.isFinite(minutes)&&minutes>0&&minutes<=360;
          const url=httpsUrl(ep.url||ep?.show?.url);
          return {id:String(ep.id),title:trimmed(ep.show?.name),url,
            detail:trimmed(ep.name,160),channel:trimmed(ep?.show?.network?.name||ep?.show?.webChannel?.name),
            startsAt:iso(start),...(endOk?{endsAt:iso(start+minutes*60000),endsAtBasis:'episode_runtime_estimate'}:{}),
            guestCast,showCast};
        }));
        items.push(...enriched.filter(x=>x.title&&x.url));
      }
      return {schema:'federation.tv-schedule/1',sourceId:'tvmaze',sourceName:'TVmaze',
        attribution:'TVmaze (CC BY-SA)',fetchedAt:iso(clock()),timezone:'Asia/Tokyo',
        coverage:'partial-JP',count:items.length,items};
    }finally{clearTimeout(timeout);}
  }
  async function get(){
    const now=clock();
    if(cache&&now<cache.until)return cache.value;
    if(ongoing)return ongoing;
    ongoing=collect().then(value=>{cache={value,until:clock()+TTL};return value;}).finally(()=>{ongoing=null;});
    return ongoing;
  }
  const server=http.createServer(async(req,res)=>{
    const origin=req.headers.origin||'';
    const u=req.url||'';
    const path=u.split('?')[0];
    if(u.length>150||u.includes('?')||u.includes('#')){
      return reply(res,400,{ok:false,reason:'unsupported-query'},{origin});
    }
    if(req.method==='OPTIONS'&&path==='/api/v1/tv/schedule')
      return reply(res,204,null,{origin});
    if(req.method!=='GET')return reply(res,405,{ok:false,reason:'read-only'},{origin});
    if(path==='/healthz')return reply(res,200,{ok:true,service:'federation-tv-schedule',mode:'read-only'},{origin});
    if(path==='/api/status')return reply(res,200,{service:'federation-tv-schedule',
      schema:'federation.tv-schedule/1',cacheReady:Boolean(cache),maxEpisodes:MAX_EPISODES,
      upstream:'tvmaze',personalDataCollected:false},{origin});
    if(path!=='/api/v1/tv/schedule')return reply(res,404,{ok:false,reason:'not-found'},{origin});
    try{return reply(res,200,await get(),{origin,cache:true});}
    catch{return reply(res,503,{ok:false,reason:'upstream-unavailable',sourceId:'tvmaze'},{origin});}
  });
  server.requestTimeout=30000;
  server.headersTimeout=32000;
  return {server,get};
}
export function startServer(env=process.env){
  const port=Number(env.PORT||10000);
  if(!Number.isSafeInteger(port)||port<1||port>65535)throw Error('invalid-port');
  const app=createTvScheduleService();
  app.server.listen(port,'0.0.0.0',()=>console.log('federation-tv-schedule ready'));
  return app;
}
if(process.argv[1]&&resolve(process.argv[1])===fileURLToPath(import.meta.url))startServer();
