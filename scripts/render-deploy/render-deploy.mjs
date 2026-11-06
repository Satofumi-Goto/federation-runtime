#!/usr/bin/env node
// Render 配備と公開確認（Node 24、依存なし）。
// - RENDER_API_KEY が空なら配備せず skip（終了コード0）。
// - 配備対象は render.yaml のサービス名（render.yaml が無いrepoは RENDER_SERVICE_NAMES）だけ。
// - サービスの作成・削除・環境変数変更・DNS切替はしない。
import {readFileSync, appendFileSync, existsSync} from 'node:fs';
import {pathToFileURL} from 'node:url';

export const API = 'https://api.render.com/v1';
export const LIVE = 'live';
export const IN_PROGRESS = new Set(['created', 'queued', 'build_in_progress', 'update_in_progress', 'pre_deploy_in_progress']);

// render.yaml の services 直下の各サービスの name だけを取り出す（envVars・headers の name は無視）。
export function parseServiceNames(yaml) {
  const names = [];
  let inServices = false;
  let itemIndent = -1;
  for (const raw of String(yaml).split(/\r?\n/)) {
    const line = raw.replace(/\s+#.*$/, '').replace(/^\s*#.*$/, '');
    if (!line.trim()) continue;
    const indent = line.length - line.trimStart().length;
    if (indent === 0) {
      inServices = /^services:\s*$/.test(line);
      itemIndent = -1;
      continue;
    }
    if (!inServices) continue;
    const item = /^(\s*)-\s+(.*)$/.exec(line);
    if (item && (itemIndent < 0 || item[1].length === itemIndent)) {
      itemIndent = item[1].length;
      const m = /^name:\s*(.+)$/.exec(item[2]);
      if (m) names.push(unquote(m[1]));
      continue;
    }
    if (itemIndent >= 0 && indent === itemIndent + 2) {
      const m = /^\s*name:\s*(.+)$/.exec(line);
      if (m) names.push(unquote(m[1]));
    }
  }
  return [...new Set(names)];
}

function unquote(v) {
  return v.trim().replace(/^(['"])(.*)\1$/, '$2');
}

// GET /v1/services?name= の応答から、名前が完全一致するサービスを選ぶ。
export function pickService(list, name) {
  const rows = Array.isArray(list) ? list : [];
  const found = rows.map((r) => (r && r.service) || r).filter((s) => s && s.name === name);
  return found.length === 1 ? found[0] : found.length > 1 ? {ambiguous: found.map((s) => s.id)} : null;
}

export function classifyDeploy(status) {
  if (status === LIVE) return 'live';
  if (IN_PROGRESS.has(status)) return 'pending';
  return 'failed';
}

export function shaMatches(gitHead, sha) {
  const got = gitHead && typeof gitHead.sha === 'string' ? gitHead.sha.toLowerCase() : null;
  return Boolean(got) && got === String(sha).toLowerCase();
}

export function serviceUrl(service) {
  const url = service && service.serviceDetails && service.serviceDetails.url;
  return typeof url === 'string' && /^https:\/\//.test(url) ? url.replace(/\/+$/, '') : null;
}

const cell = (v) => String(v ?? '').replace(/\|/g, '\\|').replace(/\r?\n/g, ' ');

export function summaryMarkdown({sha, results, note}) {
  const out = ['## Render 配備', ''];
  if (note) out.push(note, '');
  if (results.length) {
    out.push('| サービス | 公開URL | 配備SHA | 配備状態 | /healthz | /git-head.json | 判定 |');
    out.push('|---|---|---|---|---|---|---|');
    for (const r of results) {
      out.push(`| ${cell(r.name)} | ${cell(r.url || '—')} | ${cell(sha)} | ${cell(r.deploy || '—')} | ${cell(r.health || '—')} | ${cell(r.head || '—')} | ${cell(r.verdict)} |`);
    }
    for (const r of results) {
      if (r.readiness === undefined) continue;
      out.push('', `### ${r.name} /_status/readiness`, '');
      out.push(r.readiness === null ? 'なし' : '```json\n' + r.readiness + '\n```');
    }
  }
  return out.join('\n') + '\n';
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
  return {status: res.status, json};
}

async function get(url) {
  try {
    const res = await fetch(url, {headers: {'Cache-Control': 'no-cache'}, signal: AbortSignal.timeout(30_000), redirect: 'follow'});
    return {status: res.status, text: await res.text()};
  } catch (e) {
    return {status: 0, text: String(e && e.name || 'error')};
  }
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function deployOne({key, name, sha, pollMs, timeoutMs, verifyTries}) {
  const r = {name, verdict: ''};
  const found = await call(key, 'GET', `/services?name=${encodeURIComponent(name)}&limit=20`);
  if (found.status !== 200) { r.verdict = `失敗（サービス検索 HTTP ${found.status}）`; r.failed = true; return r; }
  const service = pickService(found.json, name);
  if (!service) { r.verdict = 'Renderにサービス未作成（Blueprintの初回作成が必要）'; r.missing = true; return r; }
  if (service.ambiguous) { r.verdict = `失敗（同名サービスが複数: ${service.ambiguous.join(', ')}）`; r.failed = true; return r; }
  r.url = serviceUrl(service);

  const dep = await call(key, 'POST', `/services/${service.id}/deploys`, {commitId: sha});
  if (dep.status !== 201 && dep.status !== 200 || !dep.json || !dep.json.id) {
    r.verdict = `失敗（配備開始 HTTP ${dep.status}）`; r.failed = true; return r;
  }
  let status = dep.json.status;
  const until = Date.now() + timeoutMs;
  while (classifyDeploy(status) === 'pending' && Date.now() < until) {
    await sleep(pollMs);
    const s = await call(key, 'GET', `/services/${service.id}/deploys/${dep.json.id}`);
    if (s.status === 200 && s.json) status = s.json.status;
  }
  r.deploy = `${status}（${dep.json.id}）`;
  if (classifyDeploy(status) !== 'live') {
    r.verdict = classifyDeploy(status) === 'pending' ? '失敗（15分以内に live にならない）' : `失敗（${status}）`;
    r.failed = true; return r;
  }
  if (!r.url) { r.verdict = '失敗（serviceDetails.url なし）'; r.failed = true; return r; }

  let health, head, headJson;
  for (let i = 0; i < verifyTries; i++) {
    health = await get(r.url + '/healthz');
    head = await get(r.url + '/git-head.json');
    try { headJson = JSON.parse(head.text); } catch { headJson = null; }
    if (health.status === 200 && head.status === 200 && shaMatches(headJson, sha)) break;
    if (i < verifyTries - 1) await sleep(pollMs);
  }
  r.health = `HTTP ${health.status}`;
  const servedSha = headJson && typeof headJson.sha === 'string' ? headJson.sha : null;
  r.head = head.status === 200 ? `sha ${servedSha ?? 'null'}${shaMatches(headJson, sha) ? '（一致）' : '（不一致）'}` : `HTTP ${head.status}`;
  const ready = await get(r.url + '/_status/readiness');
  r.readiness = ready.status === 200 && /^\s*[{[]/.test(ready.text) ? ready.text.trim() : null;
  if (health.status !== 200) { r.verdict = '失敗（/healthz が200でない）'; r.failed = true; return r; }
  if (!shaMatches(headJson, sha)) { r.verdict = '失敗（/git-head.json のSHA不一致）'; r.failed = true; return r; }
  r.verdict = '成功';
  return r;
}

export async function main(env = process.env) {
  const summaryPath = env.GITHUB_STEP_SUMMARY;
  const write = (md) => { process.stdout.write(md); if (summaryPath) appendFileSync(summaryPath, md); };
  const key = String(env.RENDER_API_KEY || '').trim();
  const sha = String(env.DEPLOY_SHA || env.GITHUB_SHA || '').trim().toLowerCase();
  if (!key) { write(summaryMarkdown({sha, results: [], note: 'RENDER_API_KEY 未設定のため未公開（配備をスキップ）'})); return 0; }
  process.stdout.write(`::add-mask::${key}\n`);
  if (!/^[0-9a-f]{40}$/.test(sha)) { write(summaryMarkdown({sha, results: [], note: '失敗：配備するSHAが不正'})); return 1; }

  let names = [];
  const file = env.RENDER_BLUEPRINT || 'render.yaml';
  if (existsSync(file)) names = parseServiceNames(readFileSync(file, 'utf8'));
  else names = String(env.RENDER_SERVICE_NAMES || '').split(/[\s,]+/).filter(Boolean);
  if (!names.length) { write(summaryMarkdown({sha, results: [], note: '失敗：配備対象のサービス名が無い'})); return 1; }

  const opts = {key, sha, pollMs: Number(env.RENDER_POLL_MS || 15_000), timeoutMs: Number(env.RENDER_TIMEOUT_MS || 15 * 60_000), verifyTries: Number(env.RENDER_VERIFY_TRIES || 8)};
  const results = [];
  for (const name of names) {
    try { results.push(await deployOne({...opts, name})); }
    catch (e) { results.push({name, verdict: `失敗（${e && e.name || 'error'}）`, failed: true}); }
  }
  const missing = results.filter((r) => r.missing).map((r) => r.name);
  const note = missing.length ? `Renderにサービス未作成（Blueprintの初回作成が必要）: ${missing.join(', ')}` : '';
  write(summaryMarkdown({sha, results, note}));
  return results.some((r) => r.failed) ? 1 : 0;
}

if (import.meta.url === pathToFileURL(process.argv[1] || '').href) {
  main().then((code) => { process.exitCode = code; }, () => { process.exitCode = 1; });
}
