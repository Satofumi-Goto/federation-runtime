// G4 step 1 (japan-holidays only): compare the Gateway packet with the legacy
// provider response and decide what is allowed. This module never switches a
// route; it only reports. Rollback target is always the legacy direct route.
import {createHash} from 'node:crypto';

export const HOLIDAY_ROUTE='japan-holidays';
export const HOLIDAY_SOURCE='https://holidays-jp.github.io/api/v1/date.json';
// Every gate must carry evidence before a cutover PR may even be proposed.
export const REQUIRED_EVIDENCE=Object.freeze([
 'ownerAuthenticated','activityHmacSignedE2e','dataParity','uiVerified',
 'rollbackProved','stabilityProved','networkWafVerified','distributedStore',
]);

function normalize(data){
 if(!data||typeof data!=='object'||Array.isArray(data))throw Error('invalid-holidays');
 const entries=Object.entries(data);
 if(entries.length<1||entries.length>500||entries.some(([d,n])=>
   !/^\d{4}-\d{2}-\d{2}$/.test(d)||typeof n!=='string'||!n.trim()||n.length>120))
  throw Error('invalid-holidays');
 return Object.fromEntries(entries.sort(([a],[b])=>a.localeCompare(b)));
}
const sha=v=>createHash('sha256').update(JSON.stringify(v)).digest('hex');

export function compareHolidays({gatewayPacket,legacyData,now=Date.now()}){
 const base={routeId:HOLIDAY_ROUTE,cutover:false,legacyRetained:true,rollbackTarget:'legacy-direct'};
 const age=now-Date.parse(String(gatewayPacket?.fetchedAt||''));
 if(gatewayPacket?.ok!==true||gatewayPacket.routeId!==HOLIDAY_ROUTE||gatewayPacket.mode!=='shadow-only'
   ||gatewayPacket.sourceUrl!==HOLIDAY_SOURCE||!Number.isFinite(age)||age< -60000||age>900000)
  return {...base,matched:false,reason:'gateway-packet-untrusted'};
 let viaGateway,legacy;
 try{viaGateway=normalize(gatewayPacket.data);}catch{return {...base,matched:false,reason:'gateway-data-invalid'};}
 try{legacy=normalize(legacyData);}catch{return {...base,matched:false,reason:'legacy-data-invalid'};}
 const g=sha(viaGateway),l=sha(legacy);
 const gk=Object.keys(viaGateway),lk=Object.keys(legacy);
 const missing=lk.filter(d=>!(d in viaGateway)).length,extra=gk.filter(d=>!(d in legacy)).length;
 const renamed=lk.filter(d=>d in viaGateway&&viaGateway[d]!==legacy[d]).length;
 return {...base,matched:g===l,records:{gateway:gk.length,legacy:lk.length},
  diff:{missing,extra,renamed},hashes:{gateway:g.slice(0,16),legacy:l.slice(0,16)},
  reason:g===l?'parity-passed-pending-other-gates':'parity-mismatch-no-cutover'};
}

// Reads the migration config and evidence; returns the only permitted action.
// It cannot return "cutover": a cutover is a separate user-approved PR.
export function holidayRouteDecision(migration,evidence={}){
 const route=(migration?.candidateRoutes||[]).find(r=>r.id===HOLIDAY_ROUTE);
 if(!route)return {action:'hold',reason:'route-missing'};
 if(route.legacy!==true)return {action:'rollback',reason:'legacy-disabled-restore-direct',set:{legacy:true,gateway:false,state:'HOLD'}};
 const missing=REQUIRED_EVIDENCE.filter(k=>evidence[k]!==true);
 if(route.gateway===true&&missing.length)
  return {action:'rollback',reason:'gateway-enabled-without-evidence',missing,set:{legacy:true,gateway:false,state:'HOLD'}};
 if(missing.length)return {action:'hold',reason:'evidence-incomplete',missing};
 return {action:'propose-cutover-pr',reason:'all-gates-evidenced',routeOnly:HOLIDAY_ROUTE,legacyRetained:true};
}
