// Bounded acceptance using existing server credentials; never prints a key,
// management response, design input, file payload, owner identity or OAuth token.
import {randomUUID,createHash} from 'node:crypto';
import {signHeaders} from '../../services/firewall-gateway/auth.mjs';
import {ENGINEERING_PATH} from '../../services/firewall-gateway/engineering.mjs';
const api='https://api.render.com/v1';
const gateway='https://federation-firewall-gateway.onrender.com';
const json=async(url,init={})=>{
 const response=await fetch(url,{...init,redirect:'manual',signal:AbortSignal.timeout(30000)});
 if(!response.ok)throw Error('http-'+response.status);
 const chunks=[];let size=0;
 for await(const part of response.body){size+=part.length;if(size>10*1024*1024)throw Error('response-limit');chunks.push(part);}
 return JSON.parse(Buffer.concat(chunks).toString('utf8'));
};
async function existingKey(){
 const token=process.env.RENDER_API_KEY;if(!token)throw Error('render-credential-unavailable');
 const headers={Authorization:'Bearer '+token};
 const rows=await json(api+'/services?name=federation-api-standalone-staging&limit=20',{headers});
 const matches=rows.map(r=>r.service||r).filter(s=>s.name==='federation-api-standalone-staging');
 if(matches.length!==1)throw Error('service-not-unique');
 let cursor='';
 for(let page=0;page<10;page++){
  const vars=await json(api+'/services/'+encodeURIComponent(matches[0].id)+'/env-vars?limit=100'+(cursor?'&cursor='+encodeURIComponent(cursor):''),{headers});
  if(!Array.isArray(vars))throw Error('invalid-environment-response');
  const match=vars.map(r=>r.envVar||r).find(e=>e.key==='FIREWALL_FEDERATION_HMAC_KEY');
  if(match){const raw=match.value;if(typeof raw!=='string'||!/^[A-Za-z0-9_-]{43}$/.test(raw))throw Error('engineering-credential-unavailable');const key=Buffer.from(raw,'base64url');if(key.length!==32||key.toString('base64url')!==raw)throw Error('invalid-engineering-credential');return key;}
  const next=vars.at(-1)?.cursor;if(!next||next===cursor)break;cursor=next;
 }
 throw Error('engineering-credential-unavailable');
}
try{
 const key=await existingKey();
 const invoke=async packet=>{const body=JSON.stringify(packet);return json(gateway+ENGINEERING_PATH,{method:'POST',headers:{'Content-Type':'application/json',...signHeaders({client:'federation',key,path:ENGINEERING_PATH,body})},body});};
 const request={service:'simulation',request:{requestId:'gateway-engineering-live-'+randomUUID(),kind:'unit-conversion',input:{value:1,fromUnit:'kWh',toUnit:'J'}}};
 const a=await invoke(request);
 if(a.result?.convertedValue!==3600000||a.schema!=='federation.simulation-comparison/1')throw Error('simulation-mismatch');
 const again=await invoke(request);
 if(again.id!==a.id||again.inputSha256!==a.inputSha256)throw Error('saved-readback-mismatch');
 const cad=await invoke({service:'cad',request:{template:'box',dimensions:{length:10,width:20,height:30}}});
 if(cad.schema!=='federation.cad-template/1'||Math.abs(cad.volumeMm3-6000)>1e-7||!cad.savedAt)throw Error('cad-mismatch');
 const artifacts={};
 for(const ext of ['step','stl','svg']){const f=cad.files?.[ext];if(f?.encoding!=='base64')throw Error('cad-artifact-missing');const bytes=Buffer.from(f.data,'base64');if(!bytes.length||bytes.length!==f.bytes)throw Error('cad-artifact-invalid');artifacts[ext]={bytes:bytes.length,sha256:createHash('sha256').update(bytes).digest('hex')};}
 console.log(JSON.stringify({schema:'federation.engineering-live-acceptance/1',at:new Date().toISOString(),gateway,simulation:{id:a.id,convertedValue:a.result.convertedValue,savedReadback:true},cad:{id:cad.id,volumeMm3:cad.volumeMm3,artifacts},oauthClientRoundtrip:'not-tested-by-this-server-credential-check'}));
}catch(error){console.error('engineering-live-acceptance-failed:',/^[-a-z0-9]{1,80}$/.test(error.message)?error.message:'redacted-failure');process.exitCode=1;}
