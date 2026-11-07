// Gateway owns outbound hobby/event requests. Activity owns parsing, presentation
// and publication. No browser access, user parameters, credentials or calendar data.
const HOSTS=Object.freeze({
  swiss:'https://swissdataevents.ch/events.json',
  fellowship:'https://rmxirzudhsautnsrdvib.supabase.co/functions/v1/public-events?format=json',
  redlook:'https://red-look.com/ja/online.html',
});
const TV='https://api.tvmaze.com';
const KAWASAKI='https://eventapp.city.kawasaki.jp/data/api/v1/events';
// Only two fixed, keyless headline providers. No caller URL, topic or location.
const NEWS=Object.freeze({
  gdelt:'https://api.gdeltproject.org/api/v2/doc/doc?query='+encodeURIComponent('"electric vehicle"')+'&mode=artlist&maxrecords=6&timespan=12h&sort=datedesc&format=json',
  mlit:'https://www.mlit.go.jp/pressrelease.rdf',
});
// One fixed, non-personal AniList request. No caller-supplied GraphQL, URL or credentials.
const ANILIST_URL='https://graphql.anilist.co/';
const ANILIST_BODY=JSON.stringify({query:'query { Page(page:1,perPage:6) { media(type:ANIME,sort:TRENDING_DESC,isAdult:false) { id title { native romaji } siteUrl format nextAiringEpisode { airingAt episode } } } }'});
const TTL=30*60_000;
const MAX_BYTES=350_000;
const HOUR=3_600_000;
const day=ms=>new Date(ms+9*HOUR).toISOString().slice(0,10);
const parseTime=x=>typeof x==='string'?Date.parse(x):NaN;
export function createActivityAcquisition({fetchImpl=fetch,clock=Date.now}={}){
  const cache=new Map(),pending=new Map(),cooldowns=new Map();
  async function read(url,signal,{html=false,bytes=false,anilist=false}={}){
    const u=new URL(url);
    if(u.protocol!=='https:'||u.username||u.password||
       !([HOSTS.swiss,HOSTS.fellowship,HOSTS.redlook,...Object.values(NEWS)].includes(u.href)||
         anilist&&u.href===ANILIST_URL||
         u.hostname==='api.tvmaze.com'&&(
           /^\/schedule$/.test(u.pathname)&&/^country=JP&date=\d{4}-\d{2}-\d{2}$/.test(u.search.slice(1))||
           /^\/(?:episodes|shows)\/[0-9]+\/(?:guestcast|cast)$/.test(u.pathname)&&!u.search
         )||u.origin==='https://eventapp.city.kawasaki.jp'&&
           u.pathname==='/data/api/v1/events'&&
           [...u.searchParams.keys()].sort().join(',')==='format,from,page,to'&&
           u.searchParams.get('format')==='JSON'&&
           u.searchParams.get('page')==='1'&&
           /^\d{4}-\d{2}-\d{2}$/.test(u.searchParams.get('from')||'')&&
           /^\d{4}-\d{2}-\d{2}$/.test(u.searchParams.get('to')||'')
         ))throw Error('upstream-not-allowed');
    const response=await fetchImpl(u.href,{method:anilist?'POST':'GET',redirect:'manual',credentials:'omit',
      headers:{Accept:html?'text/html':'application/json',...(anilist?{'Content-Type':'application/json'}:{})},
      ...(anilist?{body:ANILIST_BODY}:{}),signal});
    if(!response.ok||response.status>=300&&response.status<400){
      const error=new Error('upstream-unavailable');
      if((anilist||u.href===NEWS.gdelt)&&response.status===429){
        const retry=response.headers?.get?.('retry-after')||'';
        const ms=/^\d{1,6}$/.test(retry)?Number(retry)*1000:Date.parse(retry)-clock();
        error.cooldownMs=Math.min(24*HOUR,Math.max(HOUR,Number.isFinite(ms)?ms:0));
      }
      throw error;
    }
    const declared=Number(response.headers?.get?.('content-length'));
    if(Number.isFinite(declared)&&declared>MAX_BYTES)throw Error('upstream-too-large');
    const buf=await response.arrayBuffer();
    if(buf.byteLength>MAX_BYTES)throw Error('upstream-too-large');
    if(u.href===NEWS.gdelt){
      // GDELT can return a throttle/usage notice as HTTP 200 text.
      // Reject and back off rather than caching malformed headlines.
      let document;
      try{document=JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(buf));}
      catch{const error=new Error('invalid-gdelt-json');error.cooldownMs=HOUR;throw error;}
      if(!Array.isArray(document?.articles)||document.articles.length>6)
        throw Error('invalid-gdelt-articles');
    }
    if(anilist){
      let raw;
      try{raw=JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(buf));}
      catch{throw Error('invalid-anilist-json');}
      if(raw?.errors?.length||!Array.isArray(raw?.data?.Page?.media)||raw.data.Page.media.length>6)
        throw Error('invalid-anilist-payload');
    }
    if(bytes)return {encoding:'base64url',body:Buffer.from(buf).toString('base64url')};
    const text=new TextDecoder('utf-8',{fatal:true}).decode(buf);
    if(html)return text;
    const data=JSON.parse(text);
    if(!data||typeof data!=='object')throw Error('bad-provider-json');
    return data;
  }
  async function tv(signal){
    const now=clock(),days=[day(now),day(now+24*HOUR)];
    const schedules=await Promise.all(days.map(x=>read(TV+'/schedule?country=JP&date='+x,signal)));
    if(schedules.some(x=>!Array.isArray(x)))throw Error('invalid-schedule');
    const list=new Map();
    for(const ep of schedules.flat()){
      const start=parseTime(ep?.airstamp);
      if(!Number.isSafeInteger(ep?.id)||ep.id<1||!Number.isFinite(start)||start<=now||
        start>now+48*HOUR||list.has(ep.id))continue;
      list.set(ep.id,ep);
    }
    const upcoming=[...list.values()].sort((a,b)=>parseTime(a.airstamp)-parseTime(b.airstamp)).slice(0,6);
    const casts=new Map();
    const episodes=await Promise.all(upcoming.map(async ep=>{
      const guest=read(TV+'/episodes/'+ep.id+'/guestcast',signal).catch(()=>[]);
      const showId=ep?.show?.id;
      let regular=Promise.resolve([]);
      if(Number.isSafeInteger(showId)&&showId>0){
        if(!casts.has(showId))casts.set(showId,read(TV+'/shows/'+showId+'/cast',signal).catch(()=>[]));
        regular=casts.get(showId);
      }
      const [g,r]=await Promise.all([guest,regular]);
      return {...ep,guestCast:Array.isArray(g)?g.map(c=>c?.person?.name).filter(x=>typeof x==='string').slice(0,40):[],
        showCast:Array.isArray(r)?r.map(c=>c?.person?.name).filter(x=>typeof x==='string').slice(0,60):[]};
    }));
    return {episodes,providers:[{id:'tvmaze',state:'ok',count:episodes.length}]};
  }
  async function online(signal){
    const resources=[['swiss',HOSTS.swiss],['fellowship',HOSTS.fellowship],['redlook',HOSTS.redlook]];
    const responses=await Promise.allSettled(resources.map(async([id,url])=>read(url,signal,{html:id==='redlook'})));
    const providers=resources.map(([id],i)=>({id,state:responses[i].status==='fulfilled'?'ok':'unavailable'}));
    if(providers.every(x=>x.state==='unavailable'))throw Error('all-providers-unavailable');
    const swiss=responses[0].status==='fulfilled'&&Array.isArray(responses[0].value?.events)?
      responses[0].value.events.filter(x=>x?.online===true).slice(0,25):[];
    const fellowship=responses[1].status==='fulfilled'&&Array.isArray(responses[1].value?.events)?
      responses[1].value.events.filter(x=>['virtual','online','livestream'].includes(String(x?.format||'').toLowerCase())).slice(0,25):[];
    const redlook=responses[2].status==='fulfilled'?String(responses[2].value).slice(0,24000):'';
    return {swiss,fellowship,redlook,providers};
  }
  async function events(signal){
    // Server-clock bounded public date window. No caller dates, URL or identity.
    const from=day(clock()),to=day(clock()+14*24*HOUR);
    const url=new URL(KAWASAKI);
    url.search=new URLSearchParams({format:'JSON',page:'1',from,to}).toString();
    const raw=await read(url.href,signal);
    if(!Array.isArray(raw?.event_data)||raw.event_data.length>100)
      throw Error('invalid-kawasaki-events');
    // Activity handles date/location parsing, provenance and publication.
    return {kawasaki:{event_data:raw.event_data,from,to},
      providers:[{id:'kawasaki',state:'ok',count:raw.event_data.length}]};
  }
  async function get(source){
    if(!['tv','online','gdelt','mlit','events','anilist'].includes(source))throw Error('invalid-source');
    const now=clock(),hit=cache.get(source);
    if(hit&&now<hit.until)return {...hit.value,cached:true};
    if(pending.has(source))return pending.get(source);
    if(now<(cooldowns.get(source)||0))throw Error('upstream-cooldown');
    const promise=(async()=>{
      const controller=new AbortController();
      const timer=setTimeout(()=>controller.abort(),18000);
      try{
        const data=source==='tv'?await tv(controller.signal):source==='online'?await online(controller.signal)
          :source==='events'?await events(controller.signal)
          :source==='anilist'?{data:await read(ANILIST_URL,controller.signal,{bytes:true,anilist:true})}
          : {data:await read(NEWS[source],controller.signal,{bytes:true})};
        const value={schema:'gateway.activity-raw/1',source,fetchedAt:new Date(clock()).toISOString(),
          personalDataCollected:false,...data};
        cache.set(source,{until:clock()+TTL,value});cooldowns.delete(source);
        return value;
      }catch(e){cooldowns.set(source,clock()+((source==='anilist'||source==='gdelt')&&Number.isFinite(e.cooldownMs)?e.cooldownMs:source==='gdelt'?15*60_000:60_000));throw e;}
      finally{clearTimeout(timer);}
    })().finally(()=>pending.delete(source));
    pending.set(source,promise);
    return promise;
  }
  return {get};
}
