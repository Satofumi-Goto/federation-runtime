#!/usr/bin/env node
// Render に独立版アプリの Web Service を1つ作成し、初回配備と公開確認をする（Node 24、依存なし）。
// - 作成するのは SPECS にある独立版サービスだけ。既に同名サービスがあれば作成せず確認だけする。
// - 秘密値（鍵・トークン）は設定しない。後から Render 画面で設定する。
// - 削除・既存サービスの設定変更・DNS 切替はしない。
import {appendFileSync} from 'node:fs';
import {pathToFileURL} from 'node:url';
import {API, pickService, classifyDeploy, serviceUrl} from './render-deploy.mjs';

const GW = 'https://federation-firewall-gateway.onrender.com/api/v1/assistant/ask';

const NODE_BUILD = 'npm ci && npm run test:independent && npm run build:independent';
const NODE_START = 'npm run start:independent';
const ADMIN = 'https://administration-standalone-staging.onrender.com';
const base = (name, client, db, extra = {}) => ({
  NODE_VERSION: '24',
  APP_RUNTIME: 'independent',
  INDEPENDENT_HOST: '0.0.0.0',
  INDEPENDENT_TRUST_PROXY: 'true',
  INDEPENDENT_DATABASE: db,
  INDEPENDENT_ORIGIN: `https://${name}.onrender.com`,
  ASSISTANT_GATEWAY_URL: GW,
  ASSISTANT_GATEWAY_CLIENT: client,
  ...extra,
});
const spec = (name, repo, client, db, extra, build = NODE_BUILD, start = NODE_START) => ({
  name, repo: `https://github.com/Satofumi-Goto/${repo}`, buildCommand: build, startCommand: start, envVars: base(name, client, db, extra),
});

export const SPECS = Object.freeze({
  seneschal: spec('seneschal-independent-staging', 'seneschal', 'seneschal', '/tmp/seneschal-independent/runtime.sqlite', {
    INDEPENDENT_UPLOAD_DIR: '/tmp/seneschal-independent/uploads',
    INDEPENDENT_ADMINISTRATION_ORIGIN: ADMIN,
    INDEPENDENT_SAMPLE_CALENDAR_DAILY: 'false',
  }),
  federation: spec('federation-independent', 'federation-portal', 'federation', '/tmp/federation-independent.sqlite', {
    FEDERATION_RUNTIME: 'independent',
    INDEPENDENT_ADMINISTRATION_ORIGIN: ADMIN,
    INDEPENDENT_APP_CREDENTIAL_LINK_ENABLED: 'false',
  }, "npm ci && node --test 'runtime/independent/*.test.mjs' && npm run build:independent", 'node runtime/independent/server.mjs'),
  simulator: spec('mobility-lab-independent', 'mobility-business-lab', 'simulator', '/tmp/simulator-independent.sqlite', {
    INDEPENDENT_REGISTRATION_MODE: 'off',
  }),
  fleet: spec('fleet-independent', 'fleet-operations-console', 'fleet', '/tmp/fleet-operations-console-independent.sqlite', {
    FEDERATION_OPERATIONAL_TARGET: 'independent', REMOTE_CONSOLE_EXCHANGE_ENABLED: 'false', INDEPENDENT_ADMINISTRATION_ORIGIN: ADMIN,
  }),
  urban: spec('urban-independent', 'urban-operation-console', 'urban', '/tmp/urban-operation-console-independent.sqlite', {
    FEDERATION_OPERATIONAL_TARGET: 'independent', REMOTE_CONSOLE_EXCHANGE_ENABLED: 'false', INDEPENDENT_ADMINISTRATION_ORIGIN: ADMIN,
  }),
  'service-hub': spec('service-independent', 'service-hub-console', 'service', '/tmp/service-hub-console-independent.sqlite', {
    FEDERATION_OPERATIONAL_TARGET: 'independent', REMOTE_CONSOLE_EXCHANGE_ENABLED: 'false', INDEPENDENT_ADMINISTRATION_ORIGIN: ADMIN,
  }),
  life: spec('activity-independent', 'life-transaction-console', 'activity', '/tmp/life-transaction-console-independent.sqlite', {
    FEDERATION_OPERATIONAL_TARGET: 'independent', INDEPENDENT_ADMINISTRATION_ORIGIN: ADMIN,
    FIREWALL_GATEWAY_ORIGIN: 'https://federation-firewall-gateway.onrender.com',
  }),
  'remote-monitoring': spec('remote-monitoring-standalone-staging', 'federation-portal', 'remote-monitoring', '/tmp/remote-monitoring.sqlite', {},
    "npm ci && node --test 'apps/remote-monitoring/server/*.test.mjs' && node apps/remote-monitoring/server/build.mjs", 'node apps/remote-monitoring/server/server.mjs'),
  administration: spec('administration-standalone-staging', 'federation-portal', 'administration', '/tmp/administration.sqlite', {},
    "npm ci && node --test 'apps/administration/server/*.test.mjs' && node apps/administration/server/build.mjs", 'node apps/administration/server/server.mjs'),
});

export function validateSpec(spec) {
  const errors = [];
  if (!spec || typeof spec !== 'object') return ['spec がない'];
  if (!/^[a-z0-9-]{3,60}$/.test(spec.name || '')) errors.push('name が不正');
  if (!/^https:\/\/github\.com\/Satofumi-Goto\/[A-Za-z0-9._-]+$/.test(spec.repo || '')) errors.push('repo が不正');
  if (!spec.buildCommand || !spec.startCommand) errors.push('build/start がない');
  for (const [k, v] of Object.entries(spec.envVars || {})) {
    if (/KEY|TOKEN|SECRET|PASSWORD/i.test(k)) errors.push(`秘密値は spec に置かない: ${k}`);
    if (/base44\.(app|com)/i.test(String(v))) errors.push(`Base44 の宛先は置かない: ${k}`);
  }
  return errors;
}

export function createBody(spec, ownerId) {
  return {
    type: 'web_service',
    name: spec.name,
    ownerId,
    repo: spec.repo,
    branch: 'main',
    autoDeploy: 'no',
    envVars: Object.entries(spec.envVars).map(([key, value]) => ({key, value})),
    serviceDetails: {
      runtime: 'node',
      plan: 'free',
      region: 'singapore',
      healthCheckPath: '/healthz',
      envSpecificDetails: {buildCommand: spec.buildCommand, startCommand: spec.startCommand},
    },
  };
}

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
  return {status: res.status, json, text: text.slice(0, 500)};
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

export async function main(env = process.env) {
  const out = (s) => { process.stdout.write(s + '\n'); if (env.GITHUB_STEP_SUMMARY) appendFileSync(env.GITHUB_STEP_SUMMARY, s + '\n'); };
  const key = String(env.RENDER_API_KEY || '').trim();
  const app = String(env.RENDER_APP || '').trim();
  const spec = SPECS[app];
  out('## Render 独立版サービス作成');
  if (!key) { out('RENDER_API_KEY 未設定のため作成しない'); return 1; }
  process.stdout.write(`::add-mask::${key}\n`);
  if (!spec) { out(`対象アプリが不正: ${app}`); return 1; }
  const errors = validateSpec(spec);
  if (errors.length) { out('spec 不正: ' + errors.join(' / ')); return 1; }

  const found = await call(key, 'GET', `/services?name=${encodeURIComponent(spec.name)}&limit=20`);
  if (found.status !== 200) { out(`失敗（サービス検索 HTTP ${found.status}）`); return 1; }
  let service = pickService(found.json, spec.name);
  if (service && service.ambiguous) { out('失敗（同名サービスが複数）'); return 1; }
  let deployId = null;
  if (!service) {
    const owners = await call(key, 'GET', '/owners?limit=20');
    const list = Array.isArray(owners.json) ? owners.json.map((r) => (r && r.owner) || r) : [];
    if (owners.status !== 200 || list.length !== 1) { out(`失敗（所有者の特定 HTTP ${owners.status}、件数 ${list.length}）`); return 1; }
    const created = await call(key, 'POST', '/services', createBody(spec, list[0].id));
    if (created.status !== 201 || !created.json) { out(`失敗（作成 HTTP ${created.status}）: ${created.text}`); return 1; }
    service = created.json.service || created.json;
    deployId = created.json.deployId || null;
    out(`作成: ${spec.name}（${service.id}）`);
  } else {
    out(`既存: ${spec.name}（${service.id}）。作成しない`);
    if (String(env.RENDER_REDEPLOY || '') === 'true') {
      const dep = await call(key, 'POST', `/services/${service.id}/deploys`, {clearCache: 'do_not_clear'});
      if ((dep.status !== 201 && dep.status !== 200) || !dep.json || !dep.json.id) { out(`失敗（再配備開始 HTTP ${dep.status}）`); return 1; }
      out(`再配備を開始: main の最新（${dep.json.id}）`);
      await sleep(Number(env.RENDER_POLL_MS || 20_000));
    }
  }

  let status = null;
  const until = Date.now() + Number(env.RENDER_TIMEOUT_MS || 25 * 60_000);
  while (Date.now() < until) {
    const deps = await call(key, 'GET', `/services/${service.id}/deploys?limit=1`);
    const d = Array.isArray(deps.json) && deps.json[0] ? (deps.json[0].deploy || deps.json[0]) : null;
    if (d) { status = d.status; deployId = d.id; }
    if (status && classifyDeploy(status) !== 'pending') break;
    await sleep(Number(env.RENDER_POLL_MS || 20_000));
  }
  const svc = await call(key, 'GET', `/services/${service.id}`);
  const url = serviceUrl(svc.json) || serviceUrl(service);
  out(`配備状態: ${status}（${deployId}）`);
  out(`公開URL: ${url || '—'}`);
  if (url && spec.envVars.INDEPENDENT_ORIGIN !== url) {
    const put = await call(key, 'PUT', `/services/${service.id}/env-vars/INDEPENDENT_ORIGIN`, {value: url});
    out(`INDEPENDENT_ORIGIN を実URLに合わせる: ${url}（HTTP ${put.status}）`);
    if (put.status === 200) {
      const dep = await call(key, 'POST', `/services/${service.id}/deploys`, {clearCache: 'do_not_clear'});
      out(`再配備（Origin反映）: HTTP ${dep.status}`);
      const until2 = Date.now() + Number(env.RENDER_TIMEOUT_MS || 25 * 60_000);
      while (Date.now() < until2) {
        await sleep(Number(env.RENDER_POLL_MS || 20_000));
        const s2 = await call(key, 'GET', `/services/${service.id}/deploys/${dep.json && dep.json.id}`);
        if (s2.json && classifyDeploy(s2.json.status) !== 'pending') { status = s2.json.status; break; }
      }
    }
  }
  if (classifyDeploy(status) !== 'live' || !url) { out('判定: 失敗（Render の Logs を確認）'); return 1; }
  for (const p of ['/healthz', '/git-head.json', '/_status/identity']) {
    let line = '';
    for (let i = 0; i < 3 && !line; i++) {
      try {
        const r = await fetch(url + p, {signal: AbortSignal.timeout(60_000)});
        line = `${p}: HTTP ${r.status} ${(await r.text()).slice(0, 300).replace(/\s+/g, ' ')}`;
      } catch (e) { if (i === 2) line = `${p}: 取得失敗 ${e && e.name}`; }
    }
    out(line);
  }
  out('判定: 成功');
  return 0;
}

if (import.meta.url === pathToFileURL(process.argv[1] || '').href) {
  main().then((code) => { process.exitCode = code; }, (e) => { console.error(e && e.name); process.exitCode = 1; });
}
