import test from 'node:test';
import assert from 'node:assert/strict';
import {SPECS, validateSpec, createBody} from './render-create.mjs';

test('全specが検査を通る（秘密値・Base44宛先なし）', () => {
  for (const [app, spec] of Object.entries(SPECS)) assert.deepEqual(validateSpec(spec), [], app);
});

test('秘密値とBase44宛先は拒否する', () => {
  const bad = {...SPECS.seneschal, envVars: {GEMINI_API_KEY: 'x', X: 'https://a.base44.app'}};
  assert.equal(validateSpec(bad).length, 2);
});

test('作成本文は free・singapore・autoDeploy no・/healthz', () => {
  const b = createBody(SPECS.seneschal, 'own-1');
  assert.equal(b.type, 'web_service');
  assert.equal(b.autoDeploy, 'no');
  assert.equal(b.serviceDetails.plan, 'free');
  assert.equal(b.serviceDetails.region, 'singapore');
  assert.equal(b.serviceDetails.healthCheckPath, '/healthz');
  assert.equal(b.ownerId, 'own-1');
});
