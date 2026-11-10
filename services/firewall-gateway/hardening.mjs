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
 ['url-credentials',/\b[a-z][a-z0-9+.-]{1,20}:\/\/[^\s/:@'"]{1,128}:[^\s/@'"]{3,256}@[^\s/]/i],
]);
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
]);
export function hasPersonalData(texts){
 return texts.some(t=>typeof t==='string'&&PERSONAL_PATTERNS.some(([,re])=>re.test(t)));
}
