import {AMENITY_CANDIDATES} from './amenityCandidates.mjs';
// Immutable allowlist. Shadow mode only: no existing consumer is rerouted.
export const ROUTES=Object.freeze({
  'japan-holidays':Object.freeze({
    id:'japan-holidays',label:'日本の祝日',owner:'activity',provider:'holidays-jp',
    url:'https://holidays-jp.github.io/api/v1/date.json',
    consumers:['activity','seneschal','federation'],
    ttlMs:900000,maxBytes:131072,maxRecords:500,phase:'shadow-hold',
  }),
  'jma-earthquake-list':Object.freeze({
    id:'jma-earthquake-list',label:'気象庁地震情報',owner:'activity',provider:'jma',
    url:'https://www.jma.go.jp/bosai/quake/data/list.json',
    consumers:['activity','urban','fleet','seneschal','federation'],
    ttlMs:180000,maxBytes:262144,maxRecords:500,phase:'shadow-hold',
  }),
  'open-meteo-tokyo':Object.freeze({
    id:'open-meteo-tokyo',label:'東京都の公開天気サンプル',owner:'activity',provider:'open-meteo',
    url:'https://api.open-meteo.com/v1/forecast?latitude=35.68&longitude=139.69&current=temperature_2m,wind_speed_10m&forecast_days=1&timezone=Asia%2FTokyo',
    consumers:['activity','seneschal','fleet','urban','federation'],
    ttlMs:900000,maxBytes:131072,maxRecords:500,phase:'shadow-hold',
  }),
});
export const DIRECT_EXCEPTIONS=Object.freeze([
 {id:'google-maps-js',owner:'seneschal',reason:'Browser Maps SDK'},
 {id:'google-places',owner:'seneschal',reason:'Place identity and provider terms'},
 {id:'personal-calendar-auth',owner:'seneschal',reason:'Personal calendar and identity'},
 {id:'fleet-dispatch-control',owner:'fleet',reason:'Safety-critical vehicle commands'},
 {id:'booking-payment',owner:'service-owner',reason:'Payment and authorization boundary'},
 {id:'map-24h-forecast',owner:'seneschal',reason:'Existing forecast granularity'},
]);
export const SECURITY_POLICY=Object.freeze({
 version:'federation-firewall-policy/1',mode:'shadow-hold',defaultCutoverEnabled:false,
 defaultEgressEnabled:false,anonymousProxyAllowed:false,arbitraryDestinationAllowed:false,
 userDataForwardingAllowed:false,paidProviderCallsAllowed:false,dualWritesAllowed:false,
 legacyRoutesStayEnabled:true,maxConcurrentPerWorker:2,
 maxNewRequestsPerMinutePerWorker:20,requiresRealCanaryProof:true,
 requiresUiParity:true,requiresRollbackProof:true,requiresExplicitRetirementReview:true,
});
export function publicCatalog(){
 return {policy:SECURITY_POLICY,
 routes:Object.values(ROUTES).map(({id,label,owner,provider,phase,consumers,ttlMs})=>({
  id,label,owner,provider,phase,consumers,ttlMs,switched:false,liveVerified:false,
 })),
 // Metadata only; these never join ROUTES or create authorized egress.
 directExceptions:DIRECT_EXCEPTIONS,amenityCandidates:AMENITY_CANDIDATES};
}
