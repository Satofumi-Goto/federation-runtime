#!/usr/bin/env node
// 独立版10サービスを相互に接続する（Node 24、依存なし）。
// - 各サービスの実URLを Render から取得し、全サービスに相手の Origin を設定する。
// - 署名用の鍵（32バイト乱数、base64url 43字）をこの場で生成し、送る側と受ける側に同じ値を設定する。
//   既にどちらかの側に正しい形の鍵があればその値を使い、既存の鍵は変えない。鍵はログ・成果物に出さない（::add-mask::）。
// - 設定後に全サービスを再配備する。削除・DNS 切替・外部サービスの鍵の設定はしない。
import {randomBytes} from 'node:crypto';
import {appendFileSync} from 'node:fs';
import {pathToFileURL} from 'node:url';
import {API, pickService, classifyDeploy, serviceUrl} from './render-deploy.mjs';

export const SERVICES = Object.freeze({
  gateway: 'federation-firewall-gateway',
  seneschal: 'seneschal-independent-staging',
  federation: 'federation-independent',
  simulator: 'mobility-lab-independent',
  fleet: 'fleet-independent',
  urban: 'urban-independent',
  service: 'service-independent',
  activity: 'activity-independent',
  'remote-monitoring': 'remote-monitoring-standalone-staging',
  administration: 'administration-standalone-staging',
});

// 全アプリに配る Origin 変数（値は各サービスの実URL）
export const ORIGIN_VARS = Object.freeze({
  INDEPENDENT_FEDERATION_ORIGIN: 'federation',
  REMOTE_MONITORING_FEDERATION_ORIGIN: 'federation',
  VITE_FEDERATION_PARENT_ORIGIN: 'federation',
  INDEPENDENT_SIMULATOR_ORIGIN: 'simulator',
  INDEPENDENT_SENESCHAL_ORIGIN: 'seneschal',
  INDEPENDENT_LIFE_ORIGIN: 'activity',
  INDEPENDENT_ACTIVITY_ORIGIN: 'activity',
  INDEPENDENT_FLEET_ORIGIN: 'fleet',
  VITE_FLEET_ORIGIN: 'fleet',
  INDEPENDENT_SERVICE_HUB_ORIGIN: 'service',
  INDEPENDENT_URBAN_ORIGIN: 'urban',
  INDEPENDENT_REMOTE_MONITORING_ORIGIN: 'remote-monitoring',
  INDEPENDENT_ADMINISTRATION_ORIGIN: 'administration',
  FIREWALL_GATEWAY_ORIGIN: 'gateway',
});

export const GATEWAY_CLIENTS = Object.freeze(['seneschal', 'federation', 'simulator', 'activity', 'fleet', 'urban', 'service', 'administration', 'remote-monitoring']);
export const FEDERATION_LINK_APPS = Object.freeze(['activity', 'fleet', 'service', 'urban', 'seneschal']);

export const newKey = () => randomBytes(32).toString('base64url');

const KEY_RE = /^[A-Za-z0-9_-]{43}$/;
const pick = (...vals) => vals.find((v) => typeof v === 'string' && KEY_RE.test(v));
function parseClientKeys(v) {
  try { const o = JSON.parse(v || ''); return o && typeof o === 'object' && !Array.isArray(o) ? o : {}; } catch { return {}; }
}

// サービスごとの設定値を組み立てる（純粋関数。テスト対象）。existing[app] は既存の環境変数。
export function plan(urls, existing = {}, keyFn = newKey) {
  const ex = (app, k) => existing[app] && existing[app][k];
  const env = Object.fromEntries(Object.keys(SERVICES).map((app) => [app, {}]));
  for (const app of Object.keys(SERVICES)) {
    if (app === 'gateway') continue;
    for (const [v, target] of Object.entries(ORIGIN_VARS)) env[app][v] = urls[target];
    env[app].ASSISTANT_GATEWAY_URL = `${urls.gateway}/api/v1/assistant/ask`;
  }
  const current = parseClientKeys(ex('gateway', 'FIREWALL_CLIENT_KEYS_JSON'));
  const clientKeys = {...current};
  for (const client of GATEWAY_CLIENTS) {
    const k = pick(current[client], ex(client, 'ASSISTANT_GATEWAY_KEY')) || keyFn();
    clientKeys[client] = k;
    env[client].ASSISTANT_GATEWAY_KEY = k;
  }
  env.gateway.FIREWALL_CLIENT_KEYS_JSON = JSON.stringify(clientKeys);
  for (const app of FEDERATION_LINK_APPS) {
    const name = `INDEPENDENT_LINK_${app.toUpperCase()}_KEY`;
    const k = pick(ex('federation', name), ex(app, 'INDEPENDENT_FEDERATION_LINK_KEY')) || keyFn();
    env.federation[name] = k;
    env[app].INDEPENDENT_FEDERATION_LINK_KEY = k;
  }
  const sim = pick(ex('federation', 'INDEPENDENT_SIMULATOR_LINK_KEY'), ex('simulator', 'FEDERATION_LINK_SIMULATOR_KEY')) || keyFn();
  env.federation.INDEPENDENT_SIMULATOR_LINK_KEY = sim;
  env.simulator.FEDERATION_LINK_SIMULATOR_KEY = sim;
  // 既存と同じ値は書き込まない（再配備の対象にもしない）
  for (const app of Object.keys(env)) for (const k of Object.keys(env[app])) if (ex(app, k) === env[app][k]) delete env[app][k];
  return env;
}

export const SECRET_VAR = /KEY|JSON/;

async function call(key, method, path, body) {
  const res = await fetch(API + path, {
    method,
    headers: {Authorization: `Bearer ${key}`, Accept: 'application/json', ...(body ? {'Content-Type': 'application/json'} : {})},
    body: body ? JSON.stringify(body) : undefined,
    signal: AbortSignal.timeout(30_000),
  });
  const text = await res.text();
  let json = null;
  try { json = text ? JSON.parse(text) : null; } catch { json = null; }
  return {status: res.status, json};
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

export async function main(env = process.env) {
  const out = (s) => { process.stdout.write(s + '\n'); if (env.GITHUB_STEP_SUMMARY) appendFileSync(env.GITHUB_STEP_SUMMARY, s + '\n'); };
  const key = String(env.RENDER_API_KEY || '').trim();
  out('## 独立版サービスの相互接続');
  if (!key) { out('RENDER_API_KEY 未設定'); return 1; }
  process.stdout.write(`::add-mask::${key}\n`);

  const ids = {}, urls = {};
  for (const [app, name] of Object.entries(SERVICES)) {
    const f = await call(key, 'GET', `/services?name=${encodeURIComponent(name)}&limit=20`);
    const s = f.status === 200 ? pickService(f.json, name) : null;
    if (!s || s.ambiguous || !serviceUrl(s)) { out(`失敗: ${name} が見つからない`); return 1; }
    ids[app] = s.id; urls[app] = serviceUrl(s);
  }
  const existing = {};
  for (const [app, id] of Object.entries(ids)) {
    const r = await call(key, 'GET', `/services/${id}/env-vars?limit=100`);
    if (r.status !== 200 || !Array.isArray(r.json)) { out(`失敗: ${app} の環境変数を読めない（HTTP ${r.status}）`); return 1; }
    existing[app] = Object.fromEntries(r.json.map((row) => (row && row.envVar) || row).filter((e) => e && e.key).map((e) => [e.key, e.value]));
    for (const [k, v] of Object.entries(existing[app])) if (SECRET_VAR.test(k) && v) process.stdout.write(`::add-mask::${v}\n`);
  }
  const vars = plan(urls, existing);
  for (const per of Object.values(vars)) for (const [k, v] of Object.entries(per)) if (SECRET_VAR.test(k)) process.stdout.write(`::add-mask::${v}\n`);

  out('| アプリ | URL | 設定した変数 | 結果 |');
  out('|---|---|---|---|');
  const deploys = {};
  let failed = false;
  for (const [app, per] of Object.entries(vars)) {
    if (!Object.keys(per).length) { out(`| ${app} | ${urls[app]} | 0件 | 変更なし |`); continue; }
    let ok = 0, ng = [];
    for (const [k, v] of Object.entries(per)) {
      const r = await call(key, 'PUT', `/services/${ids[app]}/env-vars/${k}`, {value: v});
      if (r.status === 200) ok++; else ng.push(`${k}:${r.status}`);
    }
    const d = await call(key, 'POST', `/services/${ids[app]}/deploys`, {clearCache: 'do_not_clear'});
    deploys[app] = d.json && d.json.id;
    if (ng.length || !deploys[app]) failed = true;
    out(`| ${app} | ${urls[app]} | ${ok}件 | ${ng.length ? '失敗 ' + ng.join(' ') : '再配備 ' + (deploys[app] || `HTTP ${d.status}`)} |`);
  }

  out('', '### 再配備の結果');
  const until = Date.now() + Number(env.RENDER_TIMEOUT_MS || 25 * 60_000);
  const done = {};
  while (Date.now() < until && Object.keys(done).length < Object.keys(deploys).length) {
    await sleep(Number(env.RENDER_POLL_MS || 20_000));
    for (const [app, id] of Object.entries(deploys)) {
      if (done[app] || !id) { if (!id) done[app] = 'no-deploy'; continue; }
      const s = await call(key, 'GET', `/services/${ids[app]}/deploys/${id}`);
      const st = s.json && s.json.status;
      if (st && classifyDeploy(st) !== 'pending') done[app] = st;
    }
  }
  for (const app of Object.keys(deploys)) {
    const st = done[app] || 'timeout';
    let health = '—';
    if (st === 'live') {
      try { const r = await fetch(urls[app] + '/healthz', {signal: AbortSignal.timeout(60_000)}); health = `HTTP ${r.status}`; } catch (e) { health = e && e.name; }
    }
    if (st !== 'live' || health !== 'HTTP 200') failed = true;
    out(`- ${app}: ${st} /healthz ${health}`);
  }
  out(failed ? '判定: 一部失敗（Render の Logs を確認）' : '判定: 成功');
  return failed ? 1 : 0;
}

if (import.meta.url === pathToFileURL(process.argv[1] || '').href) {
  main().then((code) => { process.exitCode = code; }, (e) => { console.error(e && e.name); process.exitCode = 1; });
}
