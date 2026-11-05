import test from 'node:test';
import assert from 'node:assert/strict';
import {createEgress} from '../egress.mjs';
test('the initial gateway leaves the upstream disconnected',async()=>{
 const gateway=createEgress({env:{}});
 const result=await gateway.probe('activity','japan-holidays');
 assert.equal(result.status,503);
 assert.equal(gateway.info().egressEnabled,false);
});
