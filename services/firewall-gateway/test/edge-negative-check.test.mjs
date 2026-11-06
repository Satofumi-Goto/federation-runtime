import test from 'node:test';
import assert from 'node:assert/strict';
import {createGatewayServer} from '../server.mjs';
import {runEdgeNegativeChecks} from '../tools/edge-negative-check.mjs';

test('negative edge checks: local gateway refuses every forged/unsigned/browser call without upstream egress',async()=>{
 let upstream=0;
 const app=createGatewayServer({env:{FIREWALL_CANARY_EGRESS:'false'},auditSink:()=>{},
  fetchImpl:async()=>{upstream++;throw Error('no egress');}});
 await new Promise(r=>app.server.listen(0,'127.0.0.1',r));
 const local='http://127.0.0.1:'+app.server.address().port;
 // The tool only accepts https origins; map a fake https origin onto the local server.
 const fetchImpl=(url,init)=>fetch(url.replace('https://gateway.test',local),init);
 try{
  const out=await runEdgeNegativeChecks({edgeOrigin:'https://gateway.test',fetchImpl,expectEdge:false});
  assert.equal(out.health,200);
  assert.equal(out.allRefused,true,JSON.stringify(out.results));
  assert.equal(out.pass,true);
  assert.equal(upstream,0);
 }finally{await new Promise(r=>app.server.close(r));}
});

test('missing Cloudflare edge or reachable direct origin is reported as failure',async()=>{
 const fetchImpl=async url=>new Response(url.endsWith('/healthz')?'{}':'{}',{status:url.endsWith('/healthz')?200:403});
 const noEdge=await runEdgeNegativeChecks({edgeOrigin:'https://gateway.test',fetchImpl});
 assert.equal(noEdge.edgeVerified,false);
 assert.equal(noEdge.pass,false);
 const edge=async url=>new Response('{}',{status:url.endsWith('/healthz')?200:403,headers:{'cf-ray':'x'}});
 const bypass=await runEdgeNegativeChecks({edgeOrigin:'https://gateway.test',directOrigin:'https://x.onrender.com',fetchImpl:edge});
 assert.equal(bypass.edgeVerified,true);
 assert.equal(bypass.directOriginBypass.reachable,true);
 assert.equal(bypass.pass,false);
 await assert.rejects(runEdgeNegativeChecks({edgeOrigin:'http://plain.test'}),/invalid-edge-origin/);
});
