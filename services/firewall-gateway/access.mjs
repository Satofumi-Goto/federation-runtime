import {createPublicKey,verify as verifySignature} from 'node:crypto';

function decodePart(part){
 if(!/^[A-Za-z0-9_-]+$/.test(part)||part.length>6000)throw Error('invalid-access-token');
 return JSON.parse(Buffer.from(part,'base64url').toString('utf8'));
}
export function createAccessVerifier({env=process.env,fetchImpl=fetch,clock=Date.now}={}){
 const team=env.FIREWALL_ACCESS_TEAM,expectedAud=env.FIREWALL_ACCESS_AUD;
 const owner=env.FIREWALL_OWNER_EMAIL;
 const configured=typeof team==='string'&&/^[a-z0-9-]{2,60}$/.test(team)
   &&typeof expectedAud==='string'&&/^[A-Za-z0-9_-]{16,128}$/.test(expectedAud)
   &&typeof owner==='string'&&/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(owner);
 const issuer=configured?'https://'+team+'.cloudflareaccess.com':null;
 let cache=null;
 async function getKeys(){
  if(cache&&clock()-cache.at<300000)return cache.keys;
  const resp=await fetchImpl(issuer+'/cdn-cgi/access/certs',{
   redirect:'manual',credentials:'omit',signal:AbortSignal.timeout(4000),
   headers:{Accept:'application/json'}});
  if(resp.status>=300&&resp.status<400||!resp.ok||
    Number(resp.headers.get('content-length'))>65536)throw Error('access-issuer-unavailable');
  const text=await resp.text();
  if(text.length>65536)throw Error('access-issuer-unavailable');
  const parsed=JSON.parse(text);
  if(!Array.isArray(parsed.keys)||parsed.keys.length>20)throw Error('access-issuer-invalid');
  cache={at:clock(),keys:parsed.keys};
  return cache.keys;
 }
 async function verify(token){
  if(!configured)return{ok:false,status:503,reason:'admin-access-unconfigured'};
  if(typeof token!=='string'||token.length>12000)return{ok:false,status:401,reason:'access-denied'};
  const parts=token.split('.');
  if(parts.length!==3)return{ok:false,status:401,reason:'access-denied'};
  try{
   const head=decodePart(parts[0]),claims=decodePart(parts[1]);
   if(head.alg!=='RS256'||typeof head.kid!=='string'||head.kid.length>180||
      claims.iss!==issuer||!(Array.isArray(claims.aud)?claims.aud.includes(expectedAud):claims.aud===expectedAud)||
      typeof claims.exp!=='number'||claims.exp*1000<=clock()||
      claims.exp*1000>clock()+24*3600_000||
      claims.nbf&&claims.nbf*1000>clock()+30000||
      typeof claims.sub!=='string'||!claims.sub||
      typeof claims.email!=='string'||claims.email.toLowerCase()!==owner.toLowerCase())
    return{ok:false,status:403,reason:'access-denied'};
   const keys=await getKeys(),jwk=keys.find(k=>k.kid===head.kid&&k.kty==='RSA'&&(!k.use||k.use==='sig'));
   if(!jwk)return{ok:false,status:403,reason:'access-denied'};
   const signed=Buffer.from(parts[0]+'.'+parts[1]);
   const signature=Buffer.from(parts[2],'base64url');
   if(!verifySignature('RSA-SHA256',signed,createPublicKey({key:jwk,format:'jwk'}),signature))
    return{ok:false,status:403,reason:'access-denied'};
   return{ok:true,subject:claims.sub};
  }catch{return{ok:false,status:403,reason:'access-denied'};}
 }
 return{verify,configured};
}
