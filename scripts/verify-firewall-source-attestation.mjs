// Prevent accidental changes to the independently deployed public distribution
// that have not been reviewed and mirrored from the canonical private repository.
// This checks exactly 40 pinned canonical files; it does NOT fetch private upstream at CI time.
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {readFileSync,readdirSync,lstatSync} from 'node:fs';
import {resolve,join,relative,sep} from 'node:path';
import {fileURLToPath,pathToFileURL} from 'node:url';

const here=resolve(fileURLToPath(new URL('..',import.meta.url)));
const root=resolve(here,'services/firewall-gateway');
const MANIFEST_NAME='source-attestation.json';

export function gitBlobSha(text){
 const value=Buffer.from(text,'utf8');
 return createHash('sha1').update('blob '+value.length+'\0').update(value).digest('hex');
}
export function verifyAttestation(manifest,files){
 assert.equal(manifest.schema,'federation.firewall-source-attestation/1');
 assert.equal(manifest.canonicalRepository,'Satofumi-Goto/federation-portal');
 assert.match(manifest.canonicalCommit,/^[a-f0-9]{40}$/);
 assert.equal(manifest.sourcePath,'services/firewall-gateway');
 assert.equal(manifest.distributionRepository,'Satofumi-Goto/federation-runtime');
 assert.equal(manifest.verification,'full-file-Git-blob-sha1');
 const expected=manifest.files;
 assert.ok(expected&&typeof expected==='object'&&!Array.isArray(expected));
 const names=Object.keys(expected).sort();
 assert.equal(names.length,40,'unexpected canonical source count');
 assert.deepEqual([...files.keys()].sort(),names,'unreviewed additions or deletions');
 for(const name of names){
  assert.ok(name===name.replaceAll('\\','/')&&!name.includes('..')&&!name.startsWith('/'),
   'unsafe pinned path');
  assert.match(expected[name],/^[a-f0-9]{40}$/);
  const value=files.get(name);
  assert.equal(typeof value,'string','missing canonical source content: '+name);
  assert.equal(gitBlobSha(value),expected[name],'unreviewed blob change: '+name);
 }
 return {ok:true,canonicalCommit:manifest.canonicalCommit,verifiedFiles:names.length,
  distributionOnlyMetadata:MANIFEST_NAME};
}
function walkFiles(dir,base=root,out=new Map()){
 for(const name of readdirSync(dir).sort()){
  const full=join(dir,name),stats=lstatSync(full);
  assert.equal(stats.isSymbolicLink(),false,'symlink not permitted in Firewall code tree');
  if(stats.isDirectory()){walkFiles(full,base,out);continue;}
  assert.ok(stats.isFile(),'unexpected special file type');
  const path=relative(base,full).split(sep).join('/');
  if(path===MANIFEST_NAME)continue;
  assert.ok(!path.startsWith('../')&&!path.startsWith('/'),'path escaped the source tree');
  out.set(path,readFileSync(full,'utf8'));
 }
 return out;
}
// Canonical files outside the service tree that the mirrored tests read.
export const SUPPORTING_FILES=Object.freeze(['config/firewall-gateway-migration.json']);
export function verifySupporting(manifest,read){
 const expected=manifest.supportingFiles;
 assert.ok(expected&&typeof expected==='object'&&!Array.isArray(expected),'missing supporting attestation');
 assert.deepEqual(Object.keys(expected).sort(),[...SUPPORTING_FILES].sort(),'unreviewed supporting file set');
 for(const name of SUPPORTING_FILES){
  assert.match(expected[name],/^[a-f0-9]{40}$/);
  assert.equal(gitBlobSha(read(name)),expected[name],'unreviewed blob change: '+name);
 }
 return SUPPORTING_FILES.length;
}
export function verifyOnDisk(){
 const manifest=JSON.parse(readFileSync(join(root,MANIFEST_NAME),'utf8'));
 const result=verifyAttestation(manifest,walkFiles(root));
 const supportingFiles=verifySupporting(manifest,name=>readFileSync(join(here,name),'utf8'));
 return {...result,supportingFiles};
}
if(process.argv[1]&&import.meta.url===pathToFileURL(resolve(process.argv[1])).href){
 try{console.log(JSON.stringify(verifyOnDisk()));}
 catch(e){console.error('firewall-canonical-source-drift:',String(e.message).slice(0,200));process.exitCode=1;}
}
