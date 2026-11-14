// Gateway owns outbound hobby/event requests. Activity owns parsing, presentation
// and publication. No browser access, user parameters, credentials or calendar data.
const HOSTS=Object.freeze({
  swiss:'https://swissdataevents.ch/events.json',
  fellowship:'https://rmxirzudhsautnsrdvib.supabase.co/functions/v1/public-events?format=json',
  redlook:'https://red-look.com/ja/online.html',
});
const TV='https://api.tvmaze.com';
const KAWASAKI='https://eventapp.city.kawasaki.jp/data/api/v1/events';
// Japan Event publishes this public event-data feed with commercial reuse by
// attribution. Only fixed factual listings are projected; never images/HTML/PII.
const JAPAN_EVENT_URL='https://owned-media-production.up.railway.app/api/sites/event/articles/?type=event&lang=ja&page_size=1000';
const TOKYO_EVENT_URLS=Object.freeze({
  tokyo_koto_events:'https://service.api.metro.tokyo.lg.jp/api/t131083d0000000017-252a3033bb76c746c8ee30c24a3a2b5a-0/json?limit=250',
  tokyo_sumida_events:'https://service.api.metro.tokyo.lg.jp/api/t131075d0000000136-d97c9fdbf7d4a3ad38c0cac25c78beb3-0/json?limit=250',
  tokyo_itabashi_events:'https://service.api.metro.tokyo.lg.jp/api/t131199d0000000141-800c4c5f071f4be278136b4d19b2bcf8-0/json?limit=250',
  tokyo_bunkyo_events:'https://service.api.metro.tokyo.lg.jp/api/t131059d0000000001-630186c15946c72991dddc3808cd46dc-0/json?limit=250',
  tokyo_chuo_events:'https://service.api.metro.tokyo.lg.jp/api/t131024d0000000041-e5e6d00248bbe97738bfb80d0d3d3e00-0/json?limit=250',
  tokyo_bigsight_events:'https://service.api.metro.tokyo.lg.jp/api/t001001d0000000001-1db9fd22025886d3d5c9607d5c24fdf0-0/json?limit=250',
});
// Fixed public headline RSS feeds plus the existing signed news sources.
// No caller-defined query, URL, location, publisher text or paid endpoint.
const NEWS=Object.freeze({
  gdelt:'https://api.gdeltproject.org/api/v2/doc/doc?query='+encodeURIComponent('"electric vehicle"')+'&mode=artlist&maxrecords=6&timespan=12h&sort=datedesc&format=json',
  mlit:'https://www.mlit.go.jp/pressrelease.rdf',
  meti:'https://www.meti.go.jp/ml_index_release_atom.xml',
  digital:'https://www.digital.go.jp/rss/news.xml',
  yahoo_domestic:'https://news.yahoo.co.jp/rss/topics/domestic.xml',
  yahoo_entertainment:'https://news.yahoo.co.jp/rss/topics/entertainment.xml',
  yahoo_sports:'https://news.yahoo.co.jp/rss/topics/sports.xml',
  google_japan:'https://news.google.com/rss?hl=ja&gl=JP&ceid=JP:ja',
  google_entertainment:'https://news.google.com/rss/headlines/section/topic/ENTERTAINMENT?hl=ja&gl=JP&ceid=JP:ja',
  google_business:'https://news.google.com/rss/headlines/section/topic/BUSINESS?hl=ja&gl=JP&ceid=JP:ja',
});
export const TOKYO_EVENT_SOURCE_IDS=Object.freeze(Object.keys(TOKYO_EVENT_URLS));
export const NEWS_SOURCE_IDS=Object.freeze(Object.keys(NEWS));
const RSS_NEWS_IDS=new Set(['mlit','meti','digital','yahoo_domestic','yahoo_entertainment','yahoo_sports','google_japan','google_entertainment','google_business']);
// One fixed, non-personal AniList request. No caller-supplied GraphQL, URL or credentials.
const ANILIST_URL='https://graphql.anilist.co/';
const ANILIST_BODY=JSON.stringify({query:'query { Page(page:1,perPage:6) { media(type:ANIME,sort:TRENDING_DESC,isAdult:false) { id title { native romaji } siteUrl format nextAiringEpisode { airingAt episode } } } }'});
const TTL=30*60_000;
const MAX_BYTES=350_000;
// Kawasaki official 100-record pages exceed the generic cap due to unneeded prose.
// Only this fixed allowlisted source may be received up to 900k, then projected
// to strictly bounded public fields before leaving Gateway.
const KAWASAKI_INPUT_MAX_BYTES=900_000;
const KAWASAKI_OUTPUT_MAX_BYTES=340_000;
const TOKYO_INPUT_MAX_BYTES=1_400_000;
const TOKYO_OUTPUT_MAX_BYTES=340_000;
const JAPAN_EVENT_INPUT_MAX_BYTES=8_000_000;
const JAPAN_EVENT_OUTPUT_MAX_BYTES=335_000;
const HOUR=3_600_000;
const day=ms=>new Date(ms+9*HOUR).toISOString().slice(0,10);
const parseTime=x=>typeof x==='string'?Date.parse(x):NaN;

const publicText=(value,max)=>typeof value==='string'?value.trim().slice(0,max):'';
const publicCoord=value=>(typeof value==='number'&&Number.isFinite(value))||
  (typeof value==='string'&&/^-?\d{1,3}(?:\.\d{1,12})?$/.test(value))?value:null;
// Transport-only public field projection: Activity owns locale/date parsing.
const TOKYO_PUBLIC_FIELDS=Object.freeze([
  'イベント名','イベント名称','名称','行事名','title',
  '開始日','開催日','開催年月日','イベント開始日','開催開始日',
  '終了日','開催終了日','イベント終了日','開始時間','開催開始時間',
  '終了時間','開催終了時間','緯度','開催場所_緯度','施設緯度','latitude',
  '経度','開催場所_経度','施設経度','longitude',
  '場所名称','開催場所','開催場所名称','施設名',
  '住所','開催場所住所','開催地住所','URL','ホームページ','関連URL','イベントURL',
  'イベント種類','ジャンル','分類','料金（基本）','料金(基本)','参加費','料金',
  // Big Sight 2026 official public exhibition dataset fields; exclude TEL and contact PII.
  '展示会名','会期(開始)','会期(終了)','利用施設','開催時間','来場対象者','入場料について','内容'
]);
export function projectTokyoEventHit(hit){
  if(!hit||typeof hit!=='object'||Array.isArray(hit))throw Error('invalid-tokyo-hit');
  const row=hit._source&&typeof hit._source==='object'&&!Array.isArray(hit._source)
    ?hit._source:hit.row&&typeof hit.row==='object'&&!Array.isArray(hit.row)
      ?hit.row:hit;
  const cleaned={};
  for(const field of TOKYO_PUBLIC_FIELDS){
    const value=row[field];
    if(typeof value==='string')cleaned[field]=value.slice(0,300);
    else if(typeof value==='number'&&Number.isFinite(value))cleaned[field]=value;
  }
  return {_source:cleaned};
}
export function projectKawasakiEvent(row){
  if(!row||typeof row!=='object'||Array.isArray(row))throw Error('invalid-kawasaki-row');
  // Transport-layer field minimization only. Activity alone interprets times,
  // categorizes events, validates locations and deduplicates the feed.
  const date_list=Array.isArray(row.date_list)?row.date_list.slice(0,40)
    .filter(x=>x&&typeof x==='object'&&!Array.isArray(x))
    .map(x=>({date:publicText(x.date,18),time_from:publicText(x.time_from,12),
      time_to:publicText(x.time_to,12)})):[];
  const event_location=Array.isArray(row.event_location)?row.event_location.slice(0,8)
    .filter(x=>x&&typeof x==='object'&&!Array.isArray(x))
    .map(x=>({latitude:publicCoord(x.latitude),longitude:publicCoord(x.longitude),
      place:publicText(x.place,120),venue_address:publicText(x.venue_address,240)})):[];
  return {title:publicText(row.title,160),date_list,event_location,
    place_lat:publicCoord(row.place_lat),place_lon:publicCoord(row.place_lon),
    place:publicText(row.place,120),place_adr:publicText(row.place_adr,240),
    open_url:publicText(row.open_url,500),
    rel_list:Array.isArray(row.rel_list)?row.rel_list.slice(0,1)
      .filter(x=>x&&typeof x==='object'&&!Array.isArray(x))
      .map(x=>({rel_url:publicText(x.rel_url,500)})):[],
    type1:publicText(row.type1,80),cost_ext:publicText(row.cost_ext,120)};
}

const validDay=value=>typeof value==='string'&&/^\d{4}-\d{2}-\d{2}$/.test(value)
  &&Number.isFinite(Date.parse(value))&&new Date(value+'T00:00:00Z').toISOString().slice(0,10)===value;
export function validateEventQuery(input,now=Date.now()){
  if(!input||typeof input!=='object'||Array.isArray(input))return null;
  const {from,to,page}=input;
  if(!validDay(from)||!validDay(to)||!Number.isInteger(page)||page<1||page>3)return null;
  const today=day(now), earliest=day(now-7*24*HOUR),latest=day(now+45*24*HOUR);
  if(from<earliest||to>latest||to<from||(Date.parse(to)-Date.parse(from))/86400000>45)return null;
  return {from,to,page};
}
export function createActivityAcquisition({fetchImpl=fetch,clock=Date.now,risk=null}={}){
  const cache=new Map(),pending=new Map(),cooldowns=new Map();
  let gdeltThrottleStreak=0;
  async function read(url,signal,{html=false,bytes=false,anilist=false,tokyo=false,maxBytes=MAX_BYTES}={}){
    const u=new URL(url);
    if(u.protocol!=='https:'||u.username||u.password||
       !([HOSTS.swiss,HOSTS.fellowship,HOSTS.redlook,...Object.values(NEWS)].includes(u.href)||
         anilist&&u.href===ANILIST_URL||
         tokyo&&Object.values(TOKYO_EVENT_URLS).includes(u.href)||u.href===JAPAN_EVENT_URL||
         u.hostname==='api.tvmaze.com'&&(
           /^\/schedule$/.test(u.pathname)&&/^country=JP&date=\d{4}-\d{2}-\d{2}$/.test(u.search.slice(1))||
           /^\/(?:episodes|shows)\/[0-9]+\/(?:guestcast|cast)$/.test(u.pathname)&&!u.search
         )||u.origin==='https://eventapp.city.kawasaki.jp'&&
           u.pathname==='/data/api/v1/events'&&
           [...u.searchParams.keys()].sort().join(',')==='format,from,page,to'&&
           u.searchParams.get('format')==='JSON'&&
           /^[1-3]$/.test(u.searchParams.get('page')||'')&&
           /^\d{4}-\d{2}-\d{2}$/.test(u.searchParams.get('from')||'')&&
           /^\d{4}-\d{2}-\d{2}$/.test(u.searchParams.get('to')||'')
         ))throw Error('upstream-not-allowed');
    if(risk?.blockedSource(u.hostname))throw Error('source-risk-blocked');
    const response=await fetchImpl(u.href,{method:anilist||tokyo?'POST':'GET',redirect:'manual',credentials:'omit',
      headers:{Accept:html?'text/html':RSS_NEWS_IDS.has(Object.keys(NEWS).find(id=>NEWS[id]===u.href))?'application/rss+xml, application/xml, text/xml':'application/json',...((anilist||tokyo)?{'Content-Type':'application/json'}:{})},
      ...(anilist?{body:ANILIST_BODY}:tokyo?{body:'{}'}:{}),signal});
    if(!response.ok||response.status>=300&&response.status<400){
      risk?.observeSource(u.hostname,response.status>=300&&response.status<400?'redirect-refused':
        response.status===401||response.status===403?'auth-refused':'failure');
      const error=new Error('upstream-unavailable');
      if((anilist||u.href===NEWS.gdelt)&&response.status===429){
        if(u.href===NEWS.gdelt)error.message='gdelt-throttled';
        const retry=response.headers?.get?.('retry-after')||'';
        const ms=/^\d{1,6}$/.test(retry)?Number(retry)*1000:Date.parse(retry)-clock();
        error.cooldownMs=Math.min(24*HOUR,Math.max(HOUR,Number.isFinite(ms)?ms:0));
      }
      throw error;
    }
    const declared=Number(response.headers?.get?.('content-length'));
    if(Number.isFinite(declared)&&declared>maxBytes)throw Error('upstream-too-large');
    const buf=await response.arrayBuffer();
    if(buf.byteLength>maxBytes){risk?.observeSource(u.hostname,'response-too-large');throw Error('upstream-too-large');}
    if(u.href===NEWS.gdelt){
      // GDELT can return a throttle/usage notice as HTTP 200 text.
      // Reject and back off rather than caching malformed headlines.
      let document;
      const text=new TextDecoder('utf-8',{fatal:true}).decode(buf);
      try{document=JSON.parse(text);}
      catch{
        // GDELT occasionally sends an HTTP 200 text/plain usage notice. Never
        // cache or publish it as JSON; progressively cool this fixed source.
        const throttle=/^Please limit requests to one every 5 seconds\b/i.test(text.trimStart());
        const error=new Error(throttle?'gdelt-throttled':'invalid-gdelt-json');
        error.cooldownMs=HOUR;throw error;
      }
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
    if(bytes){risk?.successSource(u.hostname);return {encoding:'base64url',body:Buffer.from(buf).toString('base64url')};}
    const text=new TextDecoder('utf-8',{fatal:true}).decode(buf);
    if(html){risk?.successSource(u.hostname);return text;}
    // 壊れたJSON・形の違う応答は、危険の兆候として点数にする（空き状況の揺れとは分ける）。
    let data;
    try{data=JSON.parse(text);}catch{risk?.observeSource(u.hostname,'invalid-json-shape');throw Error('bad-provider-json');}
    if(!data||typeof data!=='object'){risk?.observeSource(u.hostname,'invalid-json-shape');throw Error('bad-provider-json');}
    risk?.successSource(u.hostname);
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
  async function events(signal,query){
    // Only a server-validated public date window and bounded page number.
    // No user identity, coordinates, arbitrary URL, credentials or custom filters.
    const {from,to,page}=query;
    const url=new URL(KAWASAKI);
    url.search=new URLSearchParams({format:'JSON',page:String(page),from,to}).toString();
    const raw=await read(url.href,signal,{maxBytes:KAWASAKI_INPUT_MAX_BYTES});
    const totalPages=Number(raw?.total_pages);
    if(!Array.isArray(raw?.event_data)||raw.event_data.length>100||
       !Number.isInteger(totalPages)||totalPages<1||totalPages>3||
       page>totalPages||raw.event_data.some(row=>!row||typeof row!=='object'||Array.isArray(row)))
      throw Error('invalid-kawasaki-events');
    // Activity owns the multi-page merge, date/venue parsing and publication.
    const projected=raw.event_data.map(projectKawasakiEvent);
    if(Buffer.byteLength(JSON.stringify(projected),'utf8')>KAWASAKI_OUTPUT_MAX_BYTES)
      throw Error('kawasaki-projection-too-large');
    return {kawasaki:{event_data:projected,from,to,page,total_pages:totalPages},
      providers:[{id:'kawasaki',state:'ok',count:projected.length}]};
  }
  async function tokyoEvents(source,signal){
    // Two fixed Tokyo open-data datasets, no caller-provided URL or filters.
    const raw=await read(TOKYO_EVENT_URLS[source],signal,
      {tokyo:true,maxBytes:TOKYO_INPUT_MAX_BYTES});
    if(!Array.isArray(raw?.hits)||raw.hits.length>250)
      throw Error('invalid-tokyo-events');
    const hits=raw.hits.map(projectTokyoEventHit);
    if(Buffer.byteLength(JSON.stringify(hits),'utf8')>TOKYO_OUTPUT_MAX_BYTES)
      throw Error('tokyo-projection-too-large');
    return {tokyo:{datasetId:source.replace(/_events$/,''),hits,complete:true},
      providers:[{id:source.replace(/_events$/,''),state:'ok',count:hits.length}]};
  }
  async function japanEvents(signal){
    // One pinned GET per 30m per Gateway instance, no caller-provided city,
    // coordinates, query, headers or credentials. Source license permits factual
    // event reuse with attribution; images and body copy are excluded.
    const raw=await read(JAPAN_EVENT_URL,signal,{maxBytes:JAPAN_EVENT_INPUT_MAX_BYTES});
    if(!Array.isArray(raw?.results)||raw.results.length>1000||
      !Number.isSafeInteger(raw?.count)||raw.count<0)
      throw Error('invalid-japan-events');
    const safeUrl=value=>{
      if(typeof value!=='string')return '';
      try{const u=new URL(value);return u.protocol==='https:'&&!u.username&&!u.password?u.href.slice(0,500):'';}
      catch{return '';}
    };
    const now=clock();
    const records=raw.results.flatMap(row=>{
      const data=row?.structured,dt=data?.datetime,venue=data?.venue;
      const title=publicText(row?.title,160);
      const start=Date.parse(dt?.start),end=Date.parse(dt?.end);
      if(row?.type!=='event'||row?.locale!=='ja'||!title||
        !Number.isFinite(start)||start>now+370*24*HOUR||
        (Number.isFinite(end)?end<now:start<now)||
        data?.date_synthetic===true||data?.event_status==='cancelled')return [];
      const slug=typeof row?.slug==='string'&&/^[a-z0-9][a-z0-9-]{0,140}$/.test(row.slug)
        ?row.slug:'';
      const sourcePage=slug?'https://japan-event.info/ja/articles/'+slug:'';
      const original=safeUrl(data?.external_url)||safeUrl(data?.experience_url);
      const address=publicText(venue?.address,240);
      const place=publicText(venue?.name,100);
      // Address or verified publisher city needed for city-specific attribution.
      const city=publicText(data?.city,50).toLowerCase();
      if(!sourcePage||!(address||city&&city!=='nationwide')||!place)return [];
      return [{
        id:row.id,sourceId:'japan_event',title,startsAt:dt.start,
        endsAt:Number.isFinite(end)?dt.end:null,venue:place,address,city,
        url:original||sourcePage,sourcePage,
        category:publicText(data?.event_type,60),
        price:publicText(data?.price_text||data?.ticket?.price,90),
        // No copyrighted article prose, pictures or unlicensed ticketing assets.
      }];
    }).sort((a,b)=>Date.parse(a.startsAt)-Date.parse(b.startsAt)).slice(0,400);
    const output={japan:{events:records,total:raw.count,
      sourceUrl:'https://japan-event.info/ja/articles/data-japan-festival-calendar-2026',
      attribution:'Japan-Event Festival Calendar Database, Japan-Event (japan-event.info)'},
      providers:[{id:'japan_event',state:'ok',count:records.length}]};
    if(Buffer.byteLength(JSON.stringify(output),'utf8')>JAPAN_EVENT_OUTPUT_MAX_BYTES)
      throw Error('japan-events-projection-too-large');
    return output;
  }
  async function get(source,selector=null){
    if(!['tv','online',...NEWS_SOURCE_IDS,'events','anilist',...TOKYO_EVENT_SOURCE_IDS,'japan_event_events'].includes(source))throw Error('invalid-source');
    const now=clock();
    const query=source==='events'
      ?validateEventQuery(selector??{from:day(now),to:day(now+14*24*HOUR),page:1},now):null;
    if(source==='events'&&!query)throw Error('invalid-event-query');
    const key=query?['events',query.from,query.to,query.page].join(':'):source;
    const hit=cache.get(key);
    if(hit&&now<hit.until)return {...hit.value,cached:true};
    if(pending.has(key))return pending.get(key);
    if(now<(cooldowns.get(key)||0))throw Error('upstream-cooldown');
    const promise=(async()=>{
      const controller=new AbortController();
      const timer=setTimeout(()=>controller.abort(),18000);
      try{
        const data=source==='tv'?await tv(controller.signal):source==='online'?await online(controller.signal)
          :source==='events'?await events(controller.signal,query)
          :TOKYO_EVENT_URLS[source]?await tokyoEvents(source,controller.signal)
          :source==='japan_event_events'?await japanEvents(controller.signal)
          :source==='anilist'?{data:await read(ANILIST_URL,controller.signal,{bytes:true,anilist:true})}
          : {data:await read(NEWS[source],controller.signal,{bytes:true})};
        const value={schema:'gateway.activity-raw/1',source,fetchedAt:new Date(clock()).toISOString(),
          personalDataCollected:false,...data};
        cache.set(key,{until:clock()+TTL,value});cooldowns.delete(key);
        if(source==='gdelt')gdeltThrottleStreak=0;
        return value;
      }catch(e){
        if(source==='gdelt'&&e.message==='gdelt-throttled'){
          gdeltThrottleStreak=Math.min(6,gdeltThrottleStreak+1);
          e.cooldownMs=Math.min(24*HOUR,Math.max(e.cooldownMs||HOUR,HOUR*2**(gdeltThrottleStreak-1)));
        }
        cooldowns.set(key,clock()+((source==='anilist'||source==='gdelt')&&Number.isFinite(e.cooldownMs)?e.cooldownMs:source==='gdelt'?15*60_000:60_000));
        throw e;
      }
      finally{clearTimeout(timer);}
    })().finally(()=>pending.delete(key));
    pending.set(key,promise);
    return promise;
  }
  return {get};
}
