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
 // Default false. Only /api/v1/assistant/ask may send the app-supplied question and
 // character profile to a paid AI provider, and only while armed with budget, expiry and app list.
 userDataForwardingAllowed:'assistant-armed-only',paidProviderCallsAllowed:'assistant-armed-only',dualWritesAllowed:false,
 legacyRoutesStayEnabled:true,maxConcurrentPerWorker:2,
 maxNewRequestsPerMinutePerWorker:20,requiresRealCanaryProof:true,
 requiresUiParity:true,requiresRollbackProof:true,requiresExplicitRetirementReview:true,
});
// Ten independent apps: nine signed consumer clients plus this gateway itself.
// Registration here is identity metadata only. A client may authenticate only
// after its key is set server-side; routes come solely from ROUTES.consumers.
export const GATEWAY_APP_ID='firewall-gateway';
const CLIENT_DEFS=[
 ['activity','活動コンソール','Satofumi-Goto/life-transaction-console','FIREWALL_ACTIVITY_HMAC_KEY'],
 ['seneschal','Seneschal','Satofumi-Goto/seneschal','FIREWALL_SENESCHAL_HMAC_KEY'],
 ['fleet','フリート運行','Satofumi-Goto/fleet-operations-console','FIREWALL_FLEET_HMAC_KEY'],
 ['urban','都市運行','Satofumi-Goto/urban-operation-console','FIREWALL_URBAN_HMAC_KEY'],
 ['service','サービス拠点','Satofumi-Goto/service-hub-console','FIREWALL_SERVICE_HMAC_KEY'],
 ['federation','Federation','Satofumi-Goto/federation-portal','FIREWALL_FEDERATION_HMAC_KEY'],
 ['simulator','事業性シミュレータ','Satofumi-Goto/mobility-business-lab','FIREWALL_SIMULATOR_HMAC_KEY'],
 ['remote-monitoring','遠隔監視','Satofumi-Goto/federation-portal','FIREWALL_REMOTE_MONITORING_HMAC_KEY'],
 ['administration','行政サービス','Satofumi-Goto/federation-portal','FIREWALL_ADMINISTRATION_HMAC_KEY'],
];
export const CLIENT_REGISTRY=Object.freeze(CLIENT_DEFS.map(([id,label,repository,clientSecretName])=>Object.freeze({
 id,label,repository,clientSecretName,gatewayKeyField:'FIREWALL_CLIENT_KEYS_JSON.'+id,
 routes:Object.freeze(Object.values(ROUTES).filter(r=>r.consumers.includes(id)).map(r=>r.id)),
})));
export const CLIENT_IDS=Object.freeze(CLIENT_REGISTRY.map(c=>c.id));
export const SIGNING_CONTRACT=Object.freeze({
 version:'federation-firewall-hmac/1',algorithm:'HMAC-SHA256',keyFormat:'32 random bytes, base64url without padding (43 chars)',
 endpoint:'/api/v1/shadow/probe',method:'POST',contentType:'application/json',maxBodyBytes:512,
 body:'{"routeId":"<route id>"} (exactly one key)',
 headers:['x-fw-client','x-fw-time','x-fw-nonce','x-fw-signature'],
 canonicalString:['federation-firewall-hmac/1','<client>','POST','/api/v1/shadow/probe','<x-fw-time ms, 13 digits>','<x-fw-nonce UUIDv4>','<sha256 hex of exact body>'].join('\n'),
 signature:'lowercase hex HMAC-SHA256 of canonicalString with the client key',
 maxClockSkewMs:60000,nonceReuse:'rejected (409) within 60s per process',
 forbiddenHeaders:['origin','cookie','authorization'],callerSide:'server-only; never from a browser',
 responses:{'200':'ok:true, data, provider, sourceUrl, fetchedAt','400':'unsupported-command','401':'signature-required|signature-invalid',
  '403':'server-to-server-only|route-not-enabled|route-not-permitted','409':'replay-refused','413':'request-too-large',
  '429':'upstream-budget-exhausted','502':'provider-unavailable','503':'service-auth-unconfigured|egress-disabled|egress-expired'},
 fallback:'callers keep their legacy route; any non-200 must fall back without retry storms',
});
export function publicClients(configured=new Set()){
 return {gatewayAppId:GATEWAY_APP_ID,appCount:CLIENT_REGISTRY.length+1,
  clients:CLIENT_REGISTRY.map(c=>({...c,keyConfigured:configured.has(c.id),
   gatewayEgressActive:false}))};
}
export function publicCatalog(){
 return {policy:SECURITY_POLICY,
 routes:Object.values(ROUTES).map(({id,label,owner,provider,phase,consumers,ttlMs})=>({
  id,label,owner,provider,phase,consumers,ttlMs,switched:false,liveVerified:false,
 })),
 // Metadata only; these never join ROUTES or create authorized egress.
 directExceptions:DIRECT_EXCEPTIONS,amenityCandidates:AMENITY_CANDIDATES,
 clientIds:CLIENT_IDS};
}
