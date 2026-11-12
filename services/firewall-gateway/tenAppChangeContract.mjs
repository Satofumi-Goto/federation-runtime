// Fixed change-hint scope only. Contains no business data, browser credentials or arbitrary URL.
import {createHash,createHmac} from 'node:crypto';
export const CHANGE_SCHEMA='federation.ten-app-change/1';
export const CHANGE_PATH='/api/sync/ten-apps/changes/firewall-gateway';
export const CHANGE_URL='https://federation-api-standalone-staging.onrender.com'+CHANGE_PATH;
export const changeDigest=body=>createHash('sha256').update(body).digest('hex');
export const changeMessage=(body,stamp)=>[CHANGE_SCHEMA,'firewall-gateway','POST',CHANGE_PATH,String(stamp),changeDigest(body)].join('\n');
export function signChange(body,key,stamp=Date.now()){return {'Content-Type':'application/json','x-ten-app-time':String(stamp),'x-ten-app-signature':createHmac('sha256',Buffer.from(key,'base64url')).update(changeMessage(body,stamp)).digest('hex')};}
export function validChange(command){return command?.schema===CHANGE_SCHEMA&&command.source==='firewall-gateway'&&/^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/.test(command.eventId||'')&&/^[a-z0-9-]{1,40}$/.test(command.kind||'')&&command.kind!=='audit-export'&&Object.keys(command).every(k=>['schema','source','eventId','kind'].includes(k));}
