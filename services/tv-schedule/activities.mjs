// Public, read-only external online events. No user input or personalized upstream requests.
// Calendar suggestions require an independently published start and end (or clearly estimated duration).
const SWISS='https://swissdataevents.ch/events.json';
const FELLOWSHIP='https://rmxirzudhsautnsrdvib.supabase.co/functions/v1/public-events?format=json';
const REDLOOK='https://red-look.com/ja/online.html';
const FIXED=new Set([SWISS,FELLOWSHIP,REDLOOK]);
const MAX_BYTES=350000;
const DAY=86400000;
const clean=(v,n=130)=>typeof v==='string'?v.replace(/<[^>]+>/g,'').replace(/[\u0000-\u001f]/g,' ').trim().slice(0,n):'';
const iso=ms=>new Date(ms).toISOString();
const validUrl=(v,host)=>{
  try{const u=new URL(v);return u.protocol==='https:'&&u.hostname===host&&!u.username&&!u.password?u.href:null;}catch{return null;}
};
const future=(s,e,now)=>{
  const start=Date.parse(s||''),end=Date.parse(e||'');
  return Number.isFinite(start)&&Number.isFinite(end)&&start>now&&
    start<now+45*DAY&&end>start&&end-start<=8*3600000;
};
export function normalizeSwissEvents(raw,now=Date.now()){
  return (Array.isArray(raw?.events)?raw.events:[]).filter(x=>x?.online===true&&x.allDay!==true)
    .flatMap(e=>{
      if(!future(e.start,e.end,now))return [];
      const url=validUrl(e.url,'swissdataevents.ch');
      const title=clean(e.title);
      if(!url||!title)return [];
      return [{id:'swiss:'+clean(String(e.id||''),90),category:'webinar',
        title,url,startsAt:iso(Date.parse(e.start)),endsAt:iso(Date.parse(e.end)),
        endBasis:'published',sourceName:'Swiss Data Events',sourceId:'swiss-data-events',
        attribution:'Swiss Data Events (link to original event)',
        detail:clean(e.description,160),organizer:clean(e.organiser,90),
        isOnline:true,priceLabel:clean(e.cost,60),registrationRequired:true}];
    }).slice(0,12);
}
export function normalizeFellowshipEvents(raw,now=Date.now()){
  return (Array.isArray(raw?.events)?raw.events:[]).filter(e=>
    ['online','virtual','livestream'].includes(String(e?.format||'').toLowerCase()))
    .flatMap(e=>{
      const url=validUrl(e.url,'theaifellowship.ca');
      const start=Date.parse(e.startTime||''),end=Date.parse(e.endTime||'');
      if(!url||!clean(e.title)||!Number.isFinite(start)||start<=now||start>now+45*DAY)return [];
      // Many organizers publish only the start. Keep those as discovery links,
      // NEVER guess a calendar interval from an absent official finish time.
      return [{id:'fellowship:'+clean(String(e.id||''),90),category:'webinar',
        title:clean(e.title),url,startsAt:iso(start),
        ...(future(e.startTime,e.endTime,now)?{endsAt:iso(end),endBasis:'published'}:{}),
        sourceName:'AI Fellowship',sourceId:'ai-fellowship',
        attribution:'AI Fellowship (public events feed)',detail:clean(e.description,160),
        isOnline:true,registrationRequired:true}];
    }).slice(0,10);
}
export function normalizeRedLookEvents(html,now=Date.now()){
  if(typeof html!=='string'||html.length>MAX_BYTES)return [];
  // Match only a prominently announced ONLINE date on the official page.
  // There may be no next date: then we return zero, not a recurring invented session.
  const area=html.slice(0,Math.min(24000,html.length));
  const normalized=area.replace(/<[^>]*>/g,' ').replace(/&nbsp;/g,' ').replace(/\s+/g,' ');
  const marker=normalized.search(/(?:次はいつ会える|直近の日程|次回の開催)/);
  if(marker<0)return [];
  const section=normalized.slice(marker,marker+2000);
  const m=section.match(/オンライン\s*(\d{1,2})\s*\/\s*(\d{1,2})[^0-9]{0,40}(\d{1,2})\s*:\s*(\d{2})/);
  if(!m)return [];
  const [,mm,dd,hh,minute]=m.map(String);
  const year=new Date(now+9*3600000).getUTCFullYear();
  const start=Date.parse(`${year}-${String(mm).padStart(2,'0')}-${String(dd).padStart(2,'0')}T${String(hh).padStart(2,'0')}:${minute}:00+09:00`);
  if(!Number.isFinite(start)||start<=now||start>now+35*DAY)return [];
  // Official site states ~45 minutes, not a published end clock.
  return [{id:'redlook:'+iso(start).slice(0,16),category:'english-exchange',
    title:'無料オンライン英会話・日本語交流（Red Look）',url:REDLOOK,
    startsAt:iso(start),endsAt:iso(start+45*60000),endBasis:'estimated-duration',
    sourceId:'red-look',sourceName:'NPO Red Look',attribution:'NPO Red Look official event page',
    detail:'参加登録と開始時刻は主催者のMeetupで要確認',isOnline:true,
    priceLabel:'無料',registrationRequired:true}];
}
export function createOnlineActivitiesCollector(fetchImpl=fetch,clock=Date.now()){
  let cache=null,pending=null,failedUntil=0;
  async function read(url,signal){
    if(!FIXED.has(url))throw Error('unapproved-provider');
    const r=await fetchImpl(url,{signal,redirect:'error',headers:{Accept:url===REDLOOK?'text/html':'application/json'}});
    if(!r.ok)throw Error('provider-status-'+r.status);
    if(Number(r.headers?.get?.('content-length'))>MAX_BYTES)throw Error('oversized');
    const buf=await r.arrayBuffer();
    if(buf.byteLength>MAX_BYTES)throw Error('oversized');
    const text=new TextDecoder().decode(buf);
    return url===REDLOOK?text:JSON.parse(text);
  }
  async function refresh(){
    const ac=new AbortController();
    const timer=setTimeout(()=>ac.abort(),18000);
    try{
      const now=clock();
      const defs=[
        ['swiss-data-events',SWISS,normalizeSwissEvents],
        ['ai-fellowship',FELLOWSHIP,normalizeFellowshipEvents],
        ['red-look',REDLOOK,normalizeRedLookEvents],
      ];
      const results=await Promise.allSettled(defs.map(async([id,url,normalize])=>
        ({id,url,items:normalize(await read(url,ac.signal),now)})));
      const status=results.map((r,i)=>({id:defs[i][0],
        state:r.status==='fulfilled'?'ok':'unavailable',
        count:r.status==='fulfilled'?r.value.items.length:0}));
      if(!status.some(x=>x.state==='ok'))throw Error('all-providers-unavailable');
      const seen=new Set();
      const items=results.flatMap(r=>r.status==='fulfilled'?r.value.items:[])
        .filter(x=>x.id&&!seen.has(x.id)&&seen.add(x.id))
        .sort((a,b)=>Date.parse(a.startsAt)-Date.parse(b.startsAt)).slice(0,20);
      return {schema:'federation.online-activities/1',fetchedAt:iso(clock()),timezone:'JST',
        personalDataCollected:false,providers:status,count:items.length,items};
    }finally{clearTimeout(timer);}
  }
  async function get(){
    const now=clock();
    if(cache&&now<cache.until)return cache.value;
    if(pending)return pending;
    if(now<failedUntil)throw Error('provider-cooldown');
    pending=refresh().then(value=>{cache={value,until:clock()+30*60000};failedUntil=0;return value;})
      .catch(err=>{failedUntil=clock()+60000;throw err;}).finally(()=>{pending=null;});
    return pending;
  }
  return {get,providerUrls:[...FIXED]};
}
