import {CLIENT_REGISTRY,GATEWAY_APP_ID} from './policy.mjs';
// Independent origins of the 10 apps (9 signed clients + this gateway).
// Reviewed source constants, never environment-supplied. null = not assigned.
// Listing an origin is a plan, NOT evidence of deployment, DNS or signed E2E.
export const INDEPENDENT_ORIGINS=Object.freeze({
 'activity':null,
 'seneschal':'https://seneschal-runtime.com',
 'fleet':null,
 'urban':null,
 'service':null,
 'federation':'https://federation-runtime.com',
 'simulator':null,
 'remote-monitoring':null,
 'administration':null,
 [GATEWAY_APP_ID]:'https://federation-firewall-gateway.onrender.com',
});
// Per-process state only. productionE2EVerified is always false here:
// production E2E needs external receipts (deploy SHA, live signed call, parity).
export function connectionState(id,configured,signed){
 if(id===GATEWAY_APP_ID)return 'self';
 if(!INDEPENDENT_ORIGINS[id])return 'origin-unassigned';
 if(!configured.has(id))return 'not-connected';
 if(!signed.has(id))return 'key-configured-no-signed-request';
 return 'signed-request-verified-this-process';
}
export function independentApps(configured=new Set(),signed=new Set()){
 const rows=[...CLIENT_REGISTRY.map(c=>({id:c.id,label:c.label})),
  {id:GATEWAY_APP_ID,label:'ファイアーウォールゲートウェイ'}];
 const apps=rows.map(({id,label})=>({id,label,independentOrigin:INDEPENDENT_ORIGINS[id]??null,
  connection:connectionState(id,configured,signed),productionE2EVerified:false}));
 return {appCount:apps.length,originsAssigned:apps.filter(a=>a.independentOrigin).length,
  keysConfigured:apps.filter(a=>configured.has(a.id)).length,productionE2EVerified:0,apps};
}
