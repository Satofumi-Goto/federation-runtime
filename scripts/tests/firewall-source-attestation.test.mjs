import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {verifyAttestation,verifyOnDisk,gitBlobSha} from '../verify-firewall-source-attestation.mjs';

const manifest=JSON.parse(readFileSync(new URL('../../services/firewall-gateway/source-attestation.json',import.meta.url),'utf8'));
const files=new Map(Object.keys(manifest.files).map(name=>[
 name,readFileSync(new URL('../../services/firewall-gateway/'+name,import.meta.url),'utf8')
]));

test('pinned canonical source includes all 30 reviewed files verbatim',()=>{
 assert.equal(verifyOnDisk().ok,true);
 assert.equal(verifyAttestation(manifest,files).verifiedFiles,30);
});

test('Git content-object hash calculation is stable',()=>{
 assert.equal(gitBlobSha('hello\n'),'ce013625030ba8dba906f756967f9e9ca394464a');
});

test('deny any source alteration, even when route remains the same',()=>{
 const bad=new Map(files);
 bad.set('egress.mjs',bad.get('egress.mjs')+'// unreviewed change\n');
 assert.throws(()=>verifyAttestation(manifest,bad),/unreviewed blob change/);
});

test('deny omitted or injected files, unknown source names and invalid provenance',()=>{
 const noServer=new Map(files);noServer.delete('server.mjs');
 assert.throws(()=>verifyAttestation(manifest,noServer),/additions or deletions/);
 const malicious=new Map(files);malicious.set('new-secret.txt','not allowed');
 assert.throws(()=>verifyAttestation(manifest,malicious),/additions or deletions/);
 assert.throws(()=>verifyAttestation({...manifest,canonicalCommit:'latest'},files));
 assert.throws(()=>verifyAttestation({...manifest,canonicalRepository:'untrusted/repo'},files));
});

test('deny path traversal even if attacker invents a matching blob hash',()=>{
 const hashes={...manifest.files};
 delete hashes['ui.mjs'];
 hashes['../other/ui.mjs']=gitBlobSha(files.get('ui.mjs'));
 const values=new Map(files);
 values.delete('ui.mjs');
 values.set('../other/ui.mjs',files.get('ui.mjs'));
 assert.throws(()=>verifyAttestation({...manifest,files:hashes},values),/unsafe pinned path/);
});

test('supporting canonical config is pinned by exact blob and cannot drift',async()=>{
 const {verifySupporting}=await import('../verify-firewall-source-attestation.mjs');
 const text=readFileSync(new URL('../../config/firewall-gateway-migration.json',import.meta.url),'utf8');
 assert.equal(verifySupporting(manifest,()=>text),1);
 assert.throws(()=>verifySupporting(manifest,()=>text+' '),/unreviewed blob change/);
 assert.throws(()=>verifySupporting({...manifest,supportingFiles:{}},()=>text),/supporting file set/);
});
