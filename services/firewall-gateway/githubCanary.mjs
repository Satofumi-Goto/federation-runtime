// Short-lived, repository-scoped GitHub OIDC identity for a ONE-ROUTE, read-only canary.
// Never use this identity for customer requests, administration, or API writes.
import {createPublicKey, verify as verifyRsa} from 'node:crypto';

const ISSUER='https://token.actions.githubusercontent.com';
const AUDIENCE='federation-firewall-holidays-canary/1';
const REPOSITORY='Satofumi-Goto/federation-runtime';
const REPOSITORY_ID='1248370969';
const WORKFLOW=REPOSITORY+'/.github/workflows/firewall-holidays-canary-once.yml@refs/heads/main';
const SUBJECT='repo:'+REPOSITORY+':ref:refs/heads/main';

function parseSegment(value){
 if(typeof value!=='string'||value.length<3||value.length>8192
    ||!/^[A-Za-z0-9_-]+$/.test(value))throw Error('invalid-jwt');
 const decoded=Buffer.from(value,'base64url').toString('utf8');
 return JSON.parse(decoded);
}
export function createGithubCanaryVerifier({fetchImpl=fetch,clock=Date.now,env=process.env}={}){
 const enabled=env.FIREWALL_GITHUB_CANARY_OIDC==='true';
 const seen=new Map();
 let cachedKeys=null,cachedAt=0;
 async function keys(){
  if(cachedKeys&&clock()-cachedAt<300000)return cachedKeys;
  const response=await fetchImpl(ISSUER+'/.well-known/jwks',{
   method:'GET',headers:{Accept:'application/json'},redirect:'manual',
   signal:AbortSignal.timeout(4500),
  });
  if(response.status>=300&&response.status<400||!response.ok
    ||Number(response.headers.get('content-length'))>65536)
   throw Error('jwks-unavailable');
  // Bound both a declared length and the actual streamed size.
  const reader=response.body?.getReader();
  if(!reader)throw Error('jwks-invalid');
  const parts=[];let size=0;
  try{
   for(;;){
    const {done,value}=await reader.read();
    if(done)break;
    size+=value.byteLength;
    if(size>65536){await reader.cancel().catch(()=>{});throw Error('jwks-too-large');}
    parts.push(value);
   }
  }finally{reader.releaseLock();}
  const data=Buffer.concat(parts.map(p=>Buffer.from(p)),size);
  const parsed=JSON.parse(data.toString('utf8'));
  if(!Array.isArray(parsed.keys)||parsed.keys.length<1||parsed.keys.length>30)
   throw Error('jwks-invalid');
  cachedKeys=parsed.keys;cachedAt=clock();
  return cachedKeys;
 }
 async function verify(token){
  if(!enabled)return{ok:false,status:503,reason:'github-canary-disabled'};
  if(typeof token!=='string'||token.length>12000)return{ok:false,status:401,reason:'github-identity-required'};
  const parts=token.split('.');
  if(parts.length!==3||parts[2].length<50||!/^[A-Za-z0-9_-]+$/.test(parts[2]))
   return{ok:false,status:401,reason:'github-identity-required'};
  try{
   const header=parseSegment(parts[0]),claims=parseSegment(parts[1]),now=clock()/1000;
   if(header.alg!=='RS256'||typeof header.kid!=='string'||header.kid.length>180||
      claims.iss!==ISSUER||claims.aud!==AUDIENCE||
      claims.sub!==SUBJECT||claims.repository!==REPOSITORY||
      String(claims.repository_id)!==REPOSITORY_ID||
      claims.ref!=='refs/heads/main'||claims.workflow_ref!==WORKFLOW||
      claims.event_name!=='push'||String(claims.actor_id)!=='281488838'||
      !Number.isInteger(claims.exp)||!Number.isInteger(claims.iat)||
      claims.exp<=now-10||claims.iat>now+30||claims.iat<now-600||
      claims.exp-claims.iat>600||
      !/^[0-9a-f]{40}$/.test(claims.sha||'')||
      typeof claims.jti!=='string'||claims.jti.length<12||claims.jti.length>160)
     return{ok:false,status:403,reason:'github-identity-rejected'};
   if(claims.nbf&&Number(claims.nbf)>now+30)
     return{ok:false,status:403,reason:'github-identity-rejected'};
   const jwks=await keys();
   const jwk=jwks.find(k=>k.kid===header.kid&&k.kty==='RSA'&&(!k.use||k.use==='sig'));
   if(!jwk)return{ok:false,status:403,reason:'github-identity-rejected'};
   const signature=Buffer.from(parts[2],'base64url');
   const verified=verifyRsa('RSA-SHA256',
     Buffer.from(parts[0]+'.'+parts[1]),
     createPublicKey({key:jwk,format:'jwk'}),signature);
   if(!verified)return{ok:false,status:403,reason:'github-identity-rejected'};
   for(const [jti,at] of seen)if(now-at>600)seen.delete(jti);
   if(seen.has(claims.jti))return{ok:false,status:409,reason:'github-identity-replayed'};
   if(seen.size>=500)return{ok:false,status:503,reason:'github-replay-store-full'};
   seen.set(claims.jti,now);
   return{ok:true,client:'federation'};
  }catch{
   return{ok:false,status:503,reason:'github-verification-unavailable'};
  }
 }
 return{verify,enabled};
}
export const GITHUB_CANARY_AUDIENCE=AUDIENCE;
