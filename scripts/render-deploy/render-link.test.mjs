import test from 'node:test';
import assert from 'node:assert/strict';
import {SERVICES, GATEWAY_CLIENTS, FEDERATION_LINK_APPS, plan, newKey} from './render-link.mjs';

const urls = Object.fromEntries(Object.entries(SERVICES).map(([a, n]) => [a, `https://${n}.onrender.com`]));
const KEY = /^[A-Za-z0-9_-]{43}$/;

test('鍵は43字で、送る側と受ける側が同じ値になる', () => {
  assert.match(newKey(), KEY);
  const env = plan(urls);
  const gw = JSON.parse(env.gateway.FIREWALL_CLIENT_KEYS_JSON);
  for (const c of GATEWAY_CLIENTS) { assert.match(gw[c], KEY); assert.equal(env[c].ASSISTANT_GATEWAY_KEY, gw[c]); }
  for (const a of FEDERATION_LINK_APPS) assert.equal(env.federation[`INDEPENDENT_LINK_${a.toUpperCase()}_KEY`], env[a].INDEPENDENT_FEDERATION_LINK_KEY);
  assert.equal(env.federation.INDEPENDENT_SIMULATOR_LINK_KEY, env.simulator.FEDERATION_LINK_SIMULATOR_KEY);
  assert.equal(new Set(Object.values(gw)).size, GATEWAY_CLIENTS.length);
});

test('Origin は全アプリに実URLで入り、Base44 を含まない', () => {
  const env = plan(urls);
  assert.equal(env.fleet.INDEPENDENT_FEDERATION_ORIGIN, urls.federation);
  assert.equal(env.federation.INDEPENDENT_SIMULATOR_ORIGIN, urls.simulator);
  assert.equal(env.seneschal.ASSISTANT_GATEWAY_URL, `${urls.gateway}/api/v1/assistant/ask`);
  assert.doesNotMatch(JSON.stringify(env), /base44/i);
});

test('既存の鍵は変えず、同じ値は書き込まない', () => {
  const k = 'A'.repeat(43);
  const existing = {
    gateway: {FIREWALL_CLIENT_KEYS_JSON: JSON.stringify({fleet: k, other: 'B'.repeat(43)})},
    federation: {INDEPENDENT_LINK_URBAN_KEY: k},
    simulator: {FEDERATION_LINK_SIMULATOR_KEY: k},
  };
  const env = plan(urls, existing);
  const gw = JSON.parse(env.gateway.FIREWALL_CLIENT_KEYS_JSON);
  assert.equal(gw.fleet, k); assert.equal(gw.other, 'B'.repeat(43));
  assert.equal(env.fleet.ASSISTANT_GATEWAY_KEY, k);
  assert.equal(env.urban.INDEPENDENT_FEDERATION_LINK_KEY, k);
  assert.equal(env.federation.INDEPENDENT_LINK_URBAN_KEY, undefined);
  assert.equal(env.federation.INDEPENDENT_SIMULATOR_LINK_KEY, k);
  assert.equal(env.simulator.FEDERATION_LINK_SIMULATOR_KEY, undefined);
  const again = plan(urls, Object.fromEntries(Object.entries(plan(urls)).map(([a, v]) => [a, v])));
  for (const v of Object.values(again)) assert.deepEqual(v, {});
});
