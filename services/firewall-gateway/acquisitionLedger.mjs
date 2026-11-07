import {readFileSync} from 'node:fs';
// Canonical ledger of Seneschal's external acquisition routes (owner: firewall-gateway).
// Activity and Seneschal display copies of acquisition-routes.json; edit it here only.
// Read-only metadata: nothing here opens egress or reroutes any existing consumer.
const raw=JSON.parse(readFileSync(new URL('./acquisition-routes.json',import.meta.url),'utf8'));
const STATES=new Set(['確認済み','未確認','接続なし']);
// Keys pasted on one service only. The gateway cannot see them, so it reports null.
export const SERVICE_SCOPED_KEYS=Object.freeze({VITE_GOOGLE_MAPS_API_KEY:'seneschal',GEOAPIFY_API_KEY:'seneschal',GOOGLE_ENVIRONMENT_API_KEY:'seneschal'});
const KEY_NAME=/^[A-Z][A-Z0-9_]{2,63}$/;

export function validateLedger(ledger){
 const ids=new Set();
 for(const r of ledger.routes){
  if(typeof r.id!=='string'||ids.has(r.id))throw Error('ledger-duplicate-id:'+r.id);
  ids.add(r.id);
  if(!STATES.has(r.state))throw Error('ledger-state:'+r.id);
  if(r.state==='確認済み'&&(!r.verifiedAt||!r.evidence))throw Error('ledger-evidence:'+r.id);
  if(r.state!=='確認済み'&&(r.verifiedAt!==null||r.evidence!==null))throw Error('ledger-evidence:'+r.id);
  if(!Array.isArray(r.requiredKeys)||!r.requiredKeys.every(k=>KEY_NAME.test(k)))throw Error('ledger-keys:'+r.id);
 }
 const placed=ledger.categories.flatMap(c=>c.ids);
 if(placed.length!==ids.size||new Set(placed).size!==ids.size||!placed.every(id=>ids.has(id)))
  throw Error('ledger-categories');
 return ledger;
}
export const ACQUISITION_LEDGER=Object.freeze(validateLedger(raw));

// Key presence only (true/false/null). Values are never read into the response.
export function publicAcquisitionLedger(env={}){
 const keyState=name=>SERVICE_SCOPED_KEYS[name]
  ?{name,scope:'service',service:SERVICE_SCOPED_KEYS[name],configured:null}
  :{name,scope:'shared',configured:typeof env[name]==='string'&&env[name].length>0};
 const routes=ACQUISITION_LEDGER.routes.map(r=>({...r,keys:r.requiredKeys.map(keyState)}));
 const count=s=>routes.filter(r=>r.state===s).length;
 return {...ACQUISITION_LEDGER,routes,
  summary:{total:routes.length,verified:count('確認済み'),unverified:count('未確認'),unconnected:count('接続なし'),
   keysMissing:[...new Set(routes.flatMap(r=>r.keys).filter(k=>k.configured===false).map(k=>k.name))].sort()},
  egressChanged:false};
}
