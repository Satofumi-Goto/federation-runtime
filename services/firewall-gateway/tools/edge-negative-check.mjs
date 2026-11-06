// Read-only negative checks against a deployed Gateway. Sends no secrets and
// no valid signatures; every request is expected to be refused.
// Usage: node tools/edge-negative-check.mjs <edgeOrigin> [directOrigin]
//   edgeOrigin   : public hostname behind Cloudflare (Access/WAF)
//   directOrigin : Render origin (*.onrender.com). If it still answers the
//                  app, the WAF can be bypassed (reported, not hidden).
const ORIGIN=/^https:\/\/[a-z0-9.-]+$/;
const NONCE='00000000-0000-4000-8000-000000000000';

async function call(fetchImpl,origin,path,init={}){
 try{
  const r=await fetchImpl(origin+path,{redirect:'manual',credentials:'omit',signal:AbortSignal.timeout(10000),...init});
  const cfRay=r.headers.get('cf-ray');
  await r.body?.cancel?.().catch(()=>{});
  return {status:r.status,edge:Boolean(cfRay)};
 }catch{return {status:0,edge:false};}
}

export async function runEdgeNegativeChecks({edgeOrigin,directOrigin,fetchImpl=fetch,expectEdge=true}){
 if(!ORIGIN.test(edgeOrigin||''))throw Error('invalid-edge-origin');
 if(directOrigin&&!ORIGIN.test(directOrigin))throw Error('invalid-direct-origin');
 const probe='/api/v1/shadow/probe';
 const json={'content-type':'application/json'};
 const body='{"routeId":"japan-holidays"}';
 const cases=[
  ['admin-without-access-jwt','/admin',{},s=>s===401||s===403||s===503||s===302],
  ['admin-with-forged-jwt','/admin',{headers:{'cf-access-jwt-assertion':'a.b.c'}},s=>s===401||s===403||s===503||s===302],
  ['probe-unsigned','/api/v1/shadow/probe',{method:'POST',headers:json,body},s=>s===401||s===503||s===403],
  ['probe-bad-signature',probe,{method:'POST',headers:{...json,'x-fw-client':'activity','x-fw-time':String(Date.now()),
    'x-fw-nonce':NONCE,'x-fw-signature':'0'.repeat(64)},body},s=>s===401||s===503||s===403],
  ['probe-browser-origin',probe,{method:'POST',headers:{...json,origin:'https://evil.example'},body},s=>s===403],
  ['probe-with-cookie',probe,{method:'POST',headers:{...json,cookie:'session=x'},body},s=>s===403],
  ['probe-get',probe,{},s=>s===405||s===403],
  ['unknown-path','/api/v1/proxy?url=http://169.254.169.254/',{},s=>s===404||s===403],
  ['oversized-body',probe,{method:'POST',headers:{...json,'x-fw-client':'activity'},body:'x'.repeat(4096)},s=>s===413||s===401||s===403],
 ];
 const results=[];
 for(const [id,path,init,ok] of cases){
  const r=await call(fetchImpl,edgeOrigin,path,init);
  results.push({id,status:r.status,refused:ok(r.status),viaEdge:r.edge});
 }
 const health=await call(fetchImpl,edgeOrigin,'/healthz');
 let directBypass=null;
 if(directOrigin){
  const d=await call(fetchImpl,directOrigin,'/healthz');
  directBypass={status:d.status,reachable:d.status===200};
 }
 const allRefused=results.every(r=>r.refused);
 const edgeVerified=!expectEdge||results.every(r=>r.viaEdge)&&health.edge;
 return {stage:'firewall-edge-negative-check',health:health.status,allRefused,edgeVerified,
  directOriginBypass:directBypass,
  pass:allRefused&&edgeVerified&&!(directBypass?.reachable),results};
}

if(import.meta.url===`file://${process.argv[1]}`){
 const [edgeOrigin,directOrigin]=process.argv.slice(2);
 const out=await runEdgeNegativeChecks({edgeOrigin,directOrigin});
 console.log(JSON.stringify(out));
 process.exitCode=out.pass?0:1;
}
