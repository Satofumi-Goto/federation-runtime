// Fixed, free OSS engineering operations. The gateway is a signed relay, not a
// Python runtime or a proxy to arbitrary user-selected destinations.
import {signHeaders} from './auth.mjs';
export const ENGINEERING_PATH='/api/v1/engineering/run';
export const ENGINEERING_UPSTREAM_PATH='/api/internal/engineering/run';
export const ENGINEERING_UPSTREAM='https://federation-api-standalone-staging.onrender.com';
export const ENGINEERING_MAX_BODY=65536;
export const ENGINEERING_MAX_OUTPUT=10*1024*1024;
const item=(service,id,label,engine,source,input)=>Object.freeze({service,id,label,engine,source,example:service==='cad'?{template:id,dimensions:input}:{requestId:'example-'+id+'-001',kind:id,input}});
export const ENGINEERING_CATALOG=Object.freeze([
 item('cad','box','直方体CAD・STEP/STL/SVG','CadQuery','https://cadquery.readthedocs.io/en/latest/',{length:100,width:50,height:20}),
 item('cad','tube','中空管CAD・STEP/STL/SVG','CadQuery','https://cadquery.readthedocs.io/en/latest/',{outerDiameter:40,wall:3,length:100}),
 item('simulation','assignment','車両割当最適化','OR-Tools','https://developers.google.com/optimization/assignment/linear_assignment',{costMinutes:[[5,9],[8,4]]}),
 item('simulation','queue','待ち行列','SimPy','https://simpy.readthedocs.io/en/latest/',{vehicles:2,arrivalsMinutes:[0,1,2],serviceMinutes:[3,3,3]}),
 item('simulation','properties','水・水素・空気の物性','CoolProp','https://coolprop.org/coolprop/HighLevelAPI.html',{fluid:'Water',temperatureK:300,pressurePa:101325}),
 item('simulation','pipe-loss','直管の圧損','fluids','https://fluids.readthedocs.io/fluids.friction.html',{densityKgM3:1000,viscosityPaS:.001,velocityMps:1,diameterM:.05,lengthM:10,roughnessM:.00001}),
 item('simulation','heat-exchanger','向流熱交換器','ht','https://ht.readthedocs.io/en/latest/ht.hx.html',{hotCapacityWK:2000,coldCapacityWK:1000,uaWK:1000,hotInletK:360,coldInletK:300}),
 item('simulation','unit-conversion','工学単位換算','Pint','https://pint.readthedocs.io/en/stable/getting/tutorial.html',{value:1,fromUnit:'kWh',toUnit:'J'}),
 item('simulation','graph-path','有向グラフ最短経路','NetworkX','https://networkx.org/documentation/stable/reference/algorithms/shortest_paths.html',{nodeCount:4,edges:[[0,1,2],[1,3,3],[0,2,1],[2,3,8]],start:0,end:3}),
 item('simulation','mesh-box','形状・質量・慣性','Trimesh','https://trimesh.org/trimesh.creation.html',{extentsM:[.1,.05,.02],densityKgM3:2700}),
 item('simulation','linear-system','連立一次方程式','SciPy','https://docs.scipy.org/doc/scipy/reference/generated/scipy.linalg.solve.html',{matrix:[[3,1],[1,2]],rhs:[9,8]}),
 item('simulation','signal-spectrum','振動信号FFT','SciPy','https://docs.scipy.org/doc/scipy/reference/generated/scipy.fft.rfft.html',{samples:[0,1,0,-1,0,1,0,-1],sampleRateHz:8}),
 item('simulation','interpolation','性能曲線補間','SciPy','https://docs.scipy.org/doc/scipy/reference/generated/scipy.interpolate.PchipInterpolator.html',{x:[0,1,2,3],y:[0,2,3,3.5],queryX:[.5,1.5,2.5]}),
]);
const exact=(obj,keys)=>obj&&typeof obj==='object'&&!Array.isArray(obj)&&Object.keys(obj).sort().join()===keys.slice().sort().join();
const fail=(status,code)=>Object.assign(Error(code),{status,code});
const allowedStrings=new Set(['Water','Hydrogen','Air','mm','m','km','Pa','kPa','MPa','bar','J','kJ','kWh','W','kW','kg','g','s','min','hour','kelvin','degC']);
export function parseEngineeringCommand(body){
 let c;try{c=JSON.parse(body);}catch{throw fail(400,'engineering-invalid-json');}
 if(!exact(c,['service','request']))throw fail(400,'engineering-invalid-input');
 const r=c.request;
 if(c.service==='cad'){
  if(!exact(r,['template','dimensions']))throw fail(400,'engineering-invalid-input');
  const keys=r.template==='box'?['length','width','height']:r.template==='tube'?['outerDiameter','wall','length']:null;
  if(!keys||!exact(r.dimensions,keys)||keys.some(k=>typeof r.dimensions[k]!=='number'||!Number.isFinite(r.dimensions[k])||r.dimensions[k]<1||r.dimensions[k]>1000)||r.template==='tube'&&r.dimensions.wall*2>=r.dimensions.outerDiameter)throw fail(400,'engineering-invalid-input');
 }else if(c.service==='simulation'){
  const def=ENGINEERING_CATALOG.find(x=>x.service==='simulation'&&x.id===r?.kind);
  if(!def||!exact(r,['requestId','kind','input'])||typeof r.requestId!=='string'||!/^[A-Za-z0-9_-]{8,80}$/.test(r.requestId)||!exact(r.input,Object.keys(def.example.input)))throw fail(400,'engineering-invalid-input');
  let count=0;
  const safe=(v,depth=0)=>{
   if(++count>5000||depth>6)return false;
   if(Array.isArray(v))return v.length<=1024&&v.every(x=>safe(x,depth+1));
   return typeof v==='number'?Number.isFinite(v):typeof v==='string'&&allowedStrings.has(v);
  };
  if(!Object.values(r.input).every(v=>safe(v)))throw fail(400,'engineering-invalid-input');
 }else throw fail(400,'engineering-unsupported-service');
 return c;
}
export function publicEngineeringCatalog(configured=false){
 return {schema:'federation.engineering-gateway/1',endpoint:ENGINEERING_PATH,
  auth:'federation-firewall-hmac/1',allowedClients:['federation'],keyConfigured:configured,
  runtimeState:configured?'configured-not-live-verified':'authentication-unconfigured',
  freeSoftware:true,newPaidProviderCalls:false,arbitraryCodeAllowed:false,arbitraryDestinationAllowed:false,
  units:'CAD:mm; simulation: declared SI units',operations:ENGINEERING_CATALOG,
  gatewayRoundTripVerified:false,workTools:['engineering.catalog','engineering.run']};
}
export function createEngineeringRelay({key,fetchImpl=fetch,clock=Date.now}={}){
 let active=0;const starts=[];
 return {async run(command){
  if(!Buffer.isBuffer(key)||key.length!==32)throw fail(503,'engineering-authentication-unconfigured');
  const now=clock();while(starts.length&&now-starts[0]>=60000)starts.shift();
  if(active>=2||starts.length>=6)throw fail(429,'engineering-rate-limited');
  active++;starts.push(now);
  const timer=new AbortController();const timeout=setTimeout(()=>timer.abort(),25000);
  try{
   const body=JSON.stringify(command);
   const response=await fetchImpl(ENGINEERING_UPSTREAM+ENGINEERING_UPSTREAM_PATH,{method:'POST',redirect:'manual',signal:timer.signal,
    headers:{'Content-Type':'application/json',...signHeaders({client:'federation',key,body,path:ENGINEERING_UPSTREAM_PATH,time:clock()})},body});
   if(!response.ok){
    // Never forward upstream error bodies, redirects, cookies or headers.
    if(response.body)await response.body.cancel();
    throw fail([400,401,403,409,413,422,429,503,504].includes(response.status)?response.status:502,'engineering-upstream-rejected');
   }
   if(!/^application\/json(?:;|$)/i.test(response.headers.get('content-type')||'')||Number(response.headers.get('content-length'))>ENGINEERING_MAX_OUTPUT){await response.body?.cancel();throw fail(502,'engineering-invalid-upstream');}
   if(!response.body)throw fail(502,'engineering-invalid-upstream');
   const chunks=[];let size=0;
   for await(const part of response.body){size+=part.byteLength;if(size>ENGINEERING_MAX_OUTPUT){timer.abort();throw fail(502,'engineering-result-too-large');}chunks.push(part);}
   let result;try{result=JSON.parse(Buffer.concat(chunks).toString('utf8'));}catch{throw fail(502,'engineering-invalid-upstream');}
   const expected=command.service==='cad'?'federation.cad-template/1':'federation.simulation-comparison/1';
   if(result?.schema!==expected)throw fail(502,'engineering-invalid-upstream');
   return result;
  }catch(e){if(e?.code&&Number.isInteger(e.status))throw e;throw fail(timer.signal.aborted?504:502,timer.signal.aborted?'engineering-timeout':'engineering-upstream-unavailable');}
  finally{clearTimeout(timeout);active--;}
 }};
}
