// Gateway-wide hardening shared by every signed entrance.
// 1) Signed-header precheck: malformed or stale signature headers are refused
//    BEFORE the request body is read, so unsigned traffic cannot make the
//    gateway buffer up to 64 KB per connection.
// 2) Outbound secret guard: text forwarded to an external AI provider is
//    refused when it contains a credential-shaped value. The gateway never
//    echoes, logs or stores the matched value; only the category id is used.
const UUID4=/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const CLIENT=/^[a-z][a-z-]{0,31}$/;
export function precheckSignedHeaders(req,clock=Date.now){
 const h=req.headers;
 const client=h['x-fw-client'],time=h['x-fw-time'],nonce=h['x-fw-nonce'],signature=h['x-fw-signature'];
 if(typeof client!=='string'||!CLIENT.test(client)||typeof time!=='string'||!/^[0-9]{13}$/.test(time)
  ||Math.abs(clock()-Number(time))>60000||typeof nonce!=='string'||!UUID4.test(nonce)
  ||typeof signature!=='string'||!/^[0-9a-f]{64}$/.test(signature))
  return {ok:false,status:401,reason:'signature-required'};
 return {ok:true};
}
export function declaredTooLarge(req,max){
 const raw=req.headers['content-length'];
 return raw!==undefined&&Number(raw)>max;
}
// Credential shapes only (prefix + length). Ordinary prose, code and IDs pass.
export const SECRET_PATTERNS=Object.freeze([
 ['private-key',/-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY-----/],
 ['github-token',/\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{22,})/],
 ['aws-access-key',/\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/],
 ['google-api-key',/\bAIza[0-9A-Za-z_-]{35}\b/],
 ['openai-or-anthropic-key',/\bsk-(?:proj-|ant-|svcacct-)?[A-Za-z0-9_-]{32,}/],
 ['stripe-secret',/\b(?:sk|rk)_live_[A-Za-z0-9]{16,}/],
 ['slack-token',/\bxox[abprs]-[A-Za-z0-9-]{10,}/],
 ['render-api-key',/\brnd_[A-Za-z0-9]{24,}/],
 ['jwt',/\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{16,}/],
 ['groq-key',/\bgsk_[A-Za-z0-9]{40,}/],
 ['nvidia-key',/\bnvapi-[A-Za-z0-9_-]{40,}/],
 ['cerebras-key',/\bcsk-[A-Za-z0-9]{32,}/],
 ['url-credentials',/\b[a-z][a-z0-9+.-]{1,20}:\/\/[^\s/:@'"]{1,128}:[^\s/@'"]{3,256}@[^\s/]/i],
]);
// The gateway's own configured secrets (provider keys, client HMAC keys,
// tokens, passwords), matched by exact value whatever their format. Used for
// every outbound AI lane, including anonymous and volunteer-run providers.
const SECRET_ENV=/(?:_KEY|_KEYS_JSON|_TOKEN|_SECRET|_PASSWORD|_API_KEY)$/;
export function gatewaySecretValues(env={}){
 const out=new Set();
 const add=v=>{if(typeof v==='string'&&v.length>=16)out.add(v);};
 for(const [name,value] of Object.entries(env)){
  if(!SECRET_ENV.test(name)||typeof value!=='string'||!value)continue;
  if(name.endsWith('_JSON')){
   try{
    const walk=x=>{if(typeof x==='string')add(x);else if(x&&typeof x==='object')Object.values(x).forEach(walk);};
    walk(JSON.parse(value));
   }catch{add(value);}
  }else add(value);
 }
 return [...out];
}
export function containsSecretValue(texts,values){
 if(!values?.length)return false;
 return texts.some(t=>typeof t==='string'&&t&&values.some(v=>t.includes(v)));
}
export function findSecret(texts){
 for(const text of texts){
  if(typeof text!=='string'||!text)continue;
  for(const [id,re] of SECRET_PATTERNS)if(re.test(text))return id;
 }
 return null;
}
// Personal contact data (e-mail, Japanese phone numbers). Providers that may
// log prompts (publicPrompts) are skipped when a message contains these.
export const PERSONAL_PATTERNS=Object.freeze([
 ['email',/[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}/],
 ['phone-jp',/(?<![0-9])(?:0[789]0-?[0-9]{4}-?[0-9]{4}|0[1-9][0-9]{0,3}-[0-9]{1,4}-[0-9]{4}|\+81[-\s]?[1-9][0-9]{0,3}[-\s]?[0-9]{1,4}[-\s]?[0-9]{4})(?![0-9])/],
 ['postal-jp',/〒\s?[0-9]{3}-?[0-9]{4}/],
 // A street address down to the block/house number (an area name alone passes).
 ['address-jp',/(?:都|道|府|県)[^\s、。,]{0,12}?[市区町村郡][^\s、。,]{0,16}?[0-9一二三四五六七八九十]+\s?(?:丁目|番地|番|号|-)\s?[0-9一二三四五六七八九十]*/],
]);
const digitsOnly=t=>t.replace(/[\s-]/g,'');
function luhn(d){let sum=0;for(let i=0;i<d.length;i++){let n=+d[d.length-1-i];if(i%2){n*=2;if(n>9)n-=9;}sum+=n;}return sum%10===0;}
// Japanese My Number (12 digits, check digit per the official formula).
function myNumber(d){
 if(d.length!==12)return false;
 let sum=0;for(let n=1;n<=11;n++){const q=n<=6?n+1:n-5;sum+=Number(d[11-n])*q;}
 const r=sum%11,check=r<=1?0:11-r;return check===Number(d[11]);
}
function numericIds(text){
 for(const m of text.matchAll(/(?<![0-9])[0-9](?:[0-9 -]{10,22})[0-9](?![0-9])/g)){
  const d=digitsOnly(m[0]);
  if(d.length>=13&&d.length<=19&&/^[3-6]/.test(d)&&luhn(d))return 'card-number';
  if(myNumber(d))return 'my-number';
 }
 return null;
}
// Owner-configured words (own name, home address, etc.), comma separated,
// set once at startup from FIREWALL_PERSONAL_TERMS. Never logged or echoed.
let personalTerms=[];
export function configurePersonalTerms(raw){
 personalTerms=typeof raw==='string'
  ?[...new Set(raw.split(',').map(t=>t.normalize('NFKC').trim()).filter(t=>t.length>=2))].slice(0,50):[];
 return personalTerms.length;
}
export function findPersonalData(texts){
 for(const raw of texts){
  if(typeof raw!=='string'||!raw)continue;
  const t=raw.normalize('NFKC');
  for(const [id,re] of PERSONAL_PATTERNS)if(re.test(t))return id;
  const id=numericIds(t);if(id)return id;
  if(personalTerms.some(term=>t.includes(term)))return 'owner-term';
 }
 return null;
}
export function hasPersonalData(texts){return findPersonalData(texts)!==null;}
// Answers from external AI (including volunteer-run workers) are untrusted:
// credential-shaped strings are replaced before they reach any app or
// implementing AI, so they cannot be committed or reused downstream.
export function redactSecrets(text){
 if(typeof text!=='string'||!text)return {text,redacted:0};
 let out=text,redacted=0;
 // A private key is removed as a whole block, not only its header line.
 out=out.replace(/-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY-----[\s\S]*?(?:-----END (?:[A-Z0-9]+ )*PRIVATE KEY-----|$)/g,
  ()=>{redacted++;return '[REDACTED:private-key]';});
 for(const [id,re] of SECRET_PATTERNS){
  out=out.replace(new RegExp(re.source,re.flags.includes('g')?re.flags:re.flags+'g'),()=>{redacted++;return `[REDACTED:${id}]`;});
 }
 return {text:out,redacted};
}
