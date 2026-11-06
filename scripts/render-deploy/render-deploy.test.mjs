import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtempSync, writeFileSync, readFileSync} from 'node:fs';
import {tmpdir} from 'node:os';
import path from 'node:path';
import {parseServiceNames, pickService, classifyDeploy, shaMatches, serviceUrl, summaryMarkdown, main} from './render-deploy.mjs';

const SHA = 'a'.repeat(40);

test('render.yaml からサービス名だけを取り出す', () => {
  const yaml = `# c\nservices:\n  - type: web\n    name: svc-a\n    envVars:\n      - key: X\n        value: "1"\n    headers:\n      - path: /x\n        name: Content-Type\n        value: text/plain\n  # second\n  - type: web\n    runtime: docker\n    name: "svc-b"\n`;
  assert.deepEqual(parseServiceNames(yaml), ['svc-a', 'svc-b']);
  assert.deepEqual(parseServiceNames('services:\n  - name: first\n    type: web\n'), ['first']);
  assert.deepEqual(parseServiceNames('databases:\n  - name: db\n'), []);
});

test('同名のサービスだけを選ぶ', () => {
  const list = [{service: {id: 'srv-1', name: 'a-x'}}, {service: {id: 'srv-2', name: 'a'}}];
  assert.equal(pickService(list, 'a').id, 'srv-2');
  assert.equal(pickService(list, 'b'), null);
  assert.deepEqual(pickService([{service: {id: '1', name: 'a'}}, {service: {id: '2', name: 'a'}}], 'a'), {ambiguous: ['1', '2']});
  assert.equal(pickService(null, 'a'), null);
});

test('配備状態の判定', () => {
  assert.equal(classifyDeploy('live'), 'live');
  assert.equal(classifyDeploy('build_in_progress'), 'pending');
  assert.equal(classifyDeploy('update_in_progress'), 'pending');
  for (const s of ['build_failed', 'update_failed', 'canceled', 'deactivated', undefined]) assert.equal(classifyDeploy(s), 'failed');
});

test('SHA一致とURL', () => {
  assert.equal(shaMatches({sha: SHA.toUpperCase()}, SHA), true);
  assert.equal(shaMatches({sha: 'b'.repeat(40)}, SHA), false);
  assert.equal(shaMatches({sha: null}, SHA), false);
  assert.equal(shaMatches(null, SHA), false);
  assert.equal(serviceUrl({serviceDetails: {url: 'https://x.onrender.com/'}}), 'https://x.onrender.com');
  assert.equal(serviceUrl({serviceDetails: {url: 'http://x'}}), null);
  assert.equal(serviceUrl({}), null);
});

test('Summary の表', () => {
  const md = summaryMarkdown({sha: SHA, results: [{name: 'a|b', url: 'https://x', deploy: 'live', health: 'HTTP 200', head: 'sha (一致)', verdict: '成功', readiness: '{"ok":false}'}]});
  assert.match(md, /\| a\\\|b \| https:\/\/x \|/);
  assert.match(md, /"ok":false/);
});

function envFor(dir, extra = {}) {
  return {GITHUB_STEP_SUMMARY: path.join(dir, 'summary.md'), RENDER_BLUEPRINT: path.join(dir, 'render.yaml'), DEPLOY_SHA: SHA, RENDER_POLL_MS: '1', RENDER_VERIFY_TRIES: '2', ...extra};
}

function setup() {
  const dir = mkdtempSync(path.join(tmpdir(), 'rd-'));
  writeFileSync(path.join(dir, 'render.yaml'), 'services:\n  - type: web\n    name: svc-a\n');
  writeFileSync(path.join(dir, 'summary.md'), '');
  return dir;
}

function mockFetch(routes) {
  const calls = [];
  const original = globalThis.fetch;
  globalThis.fetch = async (url, init = {}) => {
    calls.push({url, method: init.method || 'GET', body: init.body, auth: init.headers && init.headers.Authorization});
    const hit = routes.find(([m, re]) => (init.method || 'GET') === m && re.test(url));
    const [status, body] = hit ? hit[2](url) : [404, ''];
    return new Response(typeof body === 'string' ? body : JSON.stringify(body), {status});
  };
  return {calls, restore: () => { globalThis.fetch = original; }};
}

test('キーが空なら配備せず成功で終える', async () => {
  const dir = setup();
  const m = mockFetch([]);
  try {
    assert.equal(await main(envFor(dir, {RENDER_API_KEY: ''})), 0);
    assert.equal(m.calls.length, 0);
    assert.match(readFileSync(path.join(dir, 'summary.md'), 'utf8'), /RENDER_API_KEY 未設定のため未公開/);
  } finally { m.restore(); }
});

test('サービス未作成なら作成せず成功で終える', async () => {
  const dir = setup();
  const m = mockFetch([['GET', /\/v1\/services\?name=svc-a&limit=20$/, () => [200, []]]]);
  try {
    assert.equal(await main(envFor(dir, {RENDER_API_KEY: 'k'})), 0);
    assert.ok(m.calls.every((c) => c.method === 'GET'));
    assert.match(readFileSync(path.join(dir, 'summary.md'), 'utf8'), /Blueprintの初回作成が必要/);
  } finally { m.restore(); }
});

function liveRoutes({headSha = SHA, deployStatus = 'live', health = 200, accepted = false, listed = true}) {
  let polls = 0;
  return [
    ['GET', /\/v1\/services\?name=svc-a/, () => [200, [{service: {id: 'srv-1', name: 'svc-a', serviceDetails: {url: 'https://svc-a.onrender.com'}}}]]],
    ['POST', /\/v1\/services\/srv-1\/deploys$/, () => accepted ? [202, null] : [201, {id: 'dep-1', status: 'build_in_progress'}]],
    ['GET', /\/v1\/services\/srv-1\/deploys\?limit=20$/, () => [200, listed ? [{deploy: {id: 'dep-0', status: 'live', commit: {id: 'c'.repeat(40)}}}, {deploy: {id: 'dep-1', status: 'build_in_progress', commit: {id: SHA}}}] : []]],
    ['GET', /\/v1\/services\/srv-1\/deploys\/dep-1$/, () => [200, {id: 'dep-1', status: ++polls < 2 ? 'build_in_progress' : deployStatus}]],
    ['GET', /svc-a\.onrender\.com\/healthz$/, () => [health, 'ok']],
    ['GET', /svc-a\.onrender\.com\/git-head\.json$/, () => [200, {sha: headSha}]],
    ['GET', /svc-a\.onrender\.com\/_status\/readiness$/, () => [200, {productionReady: false}]],
  ];
}

test('live・/healthz 200・SHA一致なら成功', async () => {
  const dir = setup();
  const m = mockFetch(liveRoutes({}));
  try {
    assert.equal(await main(envFor(dir, {RENDER_API_KEY: 'k'})), 0);
    const post = m.calls.find((c) => c.method === 'POST');
    assert.deepEqual(JSON.parse(post.body), {commitId: SHA});
    assert.equal(post.auth, 'Bearer k');
    const md = readFileSync(path.join(dir, 'summary.md'), 'utf8');
    assert.match(md, /\| svc-a \| https:\/\/svc-a\.onrender\.com \|/);
    assert.match(md, /"productionReady":false/);
    assert.doesNotMatch(md, /Bearer|\| k \|/);
  } finally { m.restore(); }
});

test('build_failed は失敗', async () => {
  const dir = setup();
  const m = mockFetch(liveRoutes({deployStatus: 'build_failed'}));
  try { assert.equal(await main(envFor(dir, {RENDER_API_KEY: 'k'})), 1); } finally { m.restore(); }
});

test('SHA不一致は失敗', async () => {
  const dir = setup();
  const m = mockFetch(liveRoutes({headSha: 'b'.repeat(40)}));
  try {
    assert.equal(await main(envFor(dir, {RENDER_API_KEY: 'k'})), 1);
    assert.match(readFileSync(path.join(dir, 'summary.md'), 'utf8'), /SHA不一致/);
  } finally { m.restore(); }
});

test('/healthz が200でなければ失敗', async () => {
  const dir = setup();
  const m = mockFetch(liveRoutes({health: 503}));
  try { assert.equal(await main(envFor(dir, {RENDER_API_KEY: 'k'})), 1); } finally { m.restore(); }
});

test('render.yaml が無ければ RENDER_SERVICE_NAMES を使う', async () => {
  const dir = setup();
  const m = mockFetch([['GET', /\/v1\/services\?name=gw&limit=20$/, () => [200, []]]]);
  try {
    assert.equal(await main(envFor(dir, {RENDER_API_KEY: 'k', RENDER_BLUEPRINT: path.join(dir, 'none.yaml'), RENDER_SERVICE_NAMES: 'gw'})), 0);
    assert.equal(m.calls.length, 1);
  } finally { m.restore(); }
});

test('配備開始 HTTP 202（本文なし）は対象コミットの配備を一覧から追跡し、/healthz・/git-head.json まで確認して成功', async () => {
  const dir = setup();
  const m = mockFetch(liveRoutes({accepted: true}));
  try {
    assert.equal(await main(envFor(dir, {RENDER_API_KEY: 'k'})), 0);
    assert.ok(m.calls.some((c) => /\/deploys\?limit=20$/.test(c.url)));
    assert.ok(m.calls.some((c) => /\/healthz$/.test(c.url)));
    assert.ok(m.calls.some((c) => /\/git-head\.json$/.test(c.url)));
    assert.match(readFileSync(path.join(dir, 'summary.md'), 'utf8'), /live（dep-1）.*成功/);
  } finally { m.restore(); }
});

test('配備開始 HTTP 202 で対象コミットの配備が見つからなければ失敗（別コミットの配備を成功扱いしない）', async () => {
  const dir = setup();
  const m = mockFetch(liveRoutes({accepted: true, listed: false}));
  try {
    assert.equal(await main(envFor(dir, {RENDER_API_KEY: 'k', RENDER_TIMEOUT_MS: '50'})), 1);
    assert.match(readFileSync(path.join(dir, 'summary.md'), 'utf8'), /対象コミットの配備が見つからない/);
  } finally { m.restore(); }
});

test('RENDER_BLUEPRINT に複数指定すると全ファイルのサービス名を配備対象にする', async () => {
  const dir = setup();
  writeFileSync(path.join(dir, 'b.yaml'), 'services:\n  - type: web\n    name: svc-b\n  - type: web\n    name: svc-a\n');
  const m = mockFetch([['GET', /\/v1\/services\?name=svc-[ab]&limit=20$/, () => [200, []]]]);
  try {
    const files = [path.join(dir, 'render.yaml'), path.join(dir, 'b.yaml'), path.join(dir, 'none.yaml')].join(' ');
    assert.equal(await main(envFor(dir, {RENDER_API_KEY: 'k', RENDER_BLUEPRINT: files})), 0);
    assert.deepEqual(m.calls.map((c) => new URL(c.url).searchParams.get('name')), ['svc-a', 'svc-b']);
  } finally { m.restore(); }
});
