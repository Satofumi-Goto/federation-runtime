# Federation Firewall Gateway — isolated Render distribution

This repository contains a **read-only deploy distribution** of the gateway originally reviewed in the private `Satofumi-Goto/federation-portal` repository.

- Canonical upstream source SHA: `045c8a9e77ecdab1f434ffbfdfd0dbbca3a26479`.
- Mirrored path: `services/firewall-gateway/`. Review code changes upstream before refreshing this distribution in a separate PR.
- No credentials, secrets, user records, private integrations, or paid calls are included. This repo is public.
- Render setup: Node 22, branch `main`, Singapore, **free**, auto-deploy **OFF**.
- Build command: `node --test services/firewall-gateway/test/*.test.mjs`
- Start command: `node services/firewall-gateway/server.mjs`
- Environment: `NODE_VERSION=22`, `HOST=0.0.0.0`, `FIREWALL_CANARY_EGRESS=false`.
- Keep `FIREWALL_CLIENT_KEYS_JSON`, `FIREWALL_ACCESS_TEAM`, `FIREWALL_ACCESS_AUD`, and `FIREWALL_OWNER_EMAIL` unset until separate protected configuration. No tokens or real user data should be committed or displayed.
- Initial public read-only endpoints: `/`, `/healthz`, `/api/status`, `/api/catalog`. `/admin` and unsigned `/api/v1/shadow/probe` must fail closed.
- Existing Base44 sites, Google Maps, calendars, bookings, vehicle dispatch, provider URLs and keys remain unchanged. Production traffic cutover is **not** enabled.
- A running service is **not** a network-layer WAF or evidence of signed application-to-firewall E2E. Distributed replay/rate limits, immutable audit and owner access are not configured.
- Verify the Render deployed Git SHA, HTTPS security headers, desktop/mobile UI, `/healthz`, `/api/status`, `/api/catalog`, `/admin` rejection and unsigned POST rejection. Do not trigger provider egress during the Phase-0 initial publish.
- Rollback: disable this dedicated Render service only. Never modify other services or DNS for this staging release.

## Phase 1 security audit (2026-11-05)

- Source PR: `Satofumi-Goto/federation-portal#971`, canonical merged SHA `045c8a9e77ecdab1f434ffbfdfd0dbbca3a26479`.
- `server.mjs` and `test/audit.test.mjs` were mirrored with identical Git Blob SHA from the canonical repository.
- Browser-origin, Cookie and Authorization-bearing shadow requests are rejected before any signed egress. Probe audit records only fixed route ID, authenticated client label, method, status and time; never record secrets, signatures, raw response, IP or request body.
- Logs are local process stdout, **not immutable or distributed audit storage**. Live HMAC app-to-Render E2E and data-parity are still required before changing any incumbent route.

## Phase 1.1: pinned, single-route holiday OIDC canary

- Canonical upstream main SHA: `843d5aa5c7475b04d7a7cebd4a7df657a740c7fd` (PR [#976](https://github.com/Satofumi-Goto/federation-portal/pull/976)). Source files in `services/firewall-gateway/` were mirrored as byte-identical Git blobs.
- Two-step deny-by-default upstream gate: `FIREWALL_CANARY_EGRESS=true` and `FIREWALL_CANARY_ROUTE_IDS=japan-holidays` are both required. No JMA, Open-Meteo, arbitrary URL, customer data or cutover.
- An additional `FIREWALL_GITHUB_CANARY_OIDC=true` gate enables a one-purpose `POST /api/v1/canary/github` only from the pinned GitHub owner push workflow (signed JWT, issuer, audience, repo-id, ref, workflow-ref, actor-id, expiry, nonce). GitHub ID tokens are never printed or stored.
- This is only source preparation. Do not arm egress or claim verified parity without deployment, a successful one-shot GitHub-signed live request, and independent legacy-source full-data comparison.
- The Activity application HMAC secret is still not configured in Base44. A successful GitHub canary is *not* Activity signed E2E; the incumbent must remain active.


## Phase 1.3 (2026-11-06) — time-boxed canary safety gate

- Canonical source: `Satofumi-Goto/federation-portal@be6a7e033d5a622f41569ff4a1a330662ee95d8f` (PR #1005); `egress.mjs`, `test/github-canary.test.mjs`, `test/canary-expiry.test.mjs` and `README.md` are mirrored bit-for-bit.
- Upstream egress requires **all three**: `FIREWALL_CANARY_EGRESS=true`, `FIREWALL_CANARY_ROUTE_IDS=japan-holidays`, and `FIREWALL_CANARY_EXPIRES_AT` in strict UTC ISO8601 with milliseconds between the process startup time and 10 minutes later. This is *not* a production route cutover.
- Expired requests, expired cached responses, and upstream responses returning after expiration are rejected. A restart with an old timestamp cannot reopen traffic.
- Render is initially configured for egress OFF. Publishing this source does not require altering secrets or arming a canary. Any time-boxed future test also requires signed authorization and a post-test OFF verification.
- The local replay cache, stdout audit, single instance budget and Render routing are not a production WAF or shared immutable ledger. Separate security work remains required before any permanent switching.


## Immutable full-source release gate

- `services/firewall-gateway/source-attestation.json` pins **all 19** code, UI, policy, package and unit-test files to their canonical Git Blob SHA from `Satofumi-Goto/federation-portal@4245e43058b36f8b7da973c4ab57dcc2994d59ef`.
- `node scripts/verify-firewall-source-attestation.mjs` refuses any source-body change, missing file, newly introduced file, path traversal, or altered provenance. CI executes this gate alongside the existing Firewall security regression suite.
- When a new canonical upstream PR has been reviewed and merged, refresh the 19-file manifest from the **exact approved upstream commit** and mirror the corresponding Git Blobs in the **same reviewed PR**. Never just update expected hashes to make a modified distribution pass.
- This gate does not have access to the private canonical repository at runtime. It verifies the local distribution against the reviewed upstream source pin, and **cannot detect newer unmirrored upstream commits without a fresh cross-repository inspection**.

## 26 Seneschal amenity candidates (2026-11-06)

- Canonical reviewed commit: `c8380d701ebf197ed8a9e8c213b4fb533ff3c768` (federation-portal PR #1004). The 17-file attestation now covers `amenityCandidates.mjs` and `test/amenity-candidates.test.mjs` plus the updated `policy.mjs`.
- All 26 entries remain read-only catalog metadata. No upstream proxy, price data, HMAC, DNS, provider credential or traffic cutover is enabled. Render staging publication is a separate gated operation.

## 10-app client registry (2026-11-06)

- Canonical reviewed commit: `6b8ad3a957d73edd487a4dea6bda1a491c0d887d` (federation-portal PR #1013). All 17 attested files mirrored as exact Git blobs.
- Nine signed clients (`activity`, `seneschal`, `fleet`, `urban`, `service`, `federation`, `simulator`, `remote-monitoring`, `administration`) plus this gateway = 10 apps. `GET /api/clients` publishes ids, repositories, permitted routes and key presence only; `/api/status` adds `configuredClientIds` and `registeredApps`.
- No route, egress, canary or cutover change. Live QA accepts either the pre-deploy state (`/api/clients` 404) or the deployed registry, and fails if any 43-char key-like value is published.
- Render (`srv-dbm40fp42hec73djn4cg`, auto-deploy OFF) must be manually deployed to this commit before the registry is live. Client keys are added only in Render's secret `FIREWALL_CLIENT_KEYS_JSON` and in each app's server secret `FIREWALL_<APP>_HMAC_KEY`.

## Shared signed assistant route, default OFF (2026-11-06)

- Canonical reviewed commit: `4245e43058b36f8b7da973c4ab57dcc2994d59ef` (federation-portal PR #1015). All 19 files under `services/firewall-gateway/` are mirrored as byte-identical Git blobs; the attestation count moves from 17 to 19 (`assistant.mjs`, `test/assistant.test.mjs`).
- `POST /api/v1/assistant/ask` requires `federation-firewall-hmac/1` signed server-to-server calls from a registered client and rejects Origin, Cookie and Authorization headers. Body: `{"characterId","question","locale"?,"persona"?,"screen"?}` up to 4096 bytes.
- Provider calls stay **OFF** unless both `FIREWALL_ASSISTANT_ENABLED=true` and `FIREWALL_ASSISTANT_GEMINI_KEY` are set on Render; otherwise 503 `assistant-disabled`. Keep both unset until the owner explicitly arms them. The provider key is never returned or logged.
- Audit records only type, time, method, status, client and characterId. `/api/status` reports `assistantEnabled:false` by default. This is not a production cutover or WAF.

## Independent origin status + full-tree mirror (2026-11-06)

- Canonical reviewed commit: `5459b4162466dee7347a4480ad5a109d8c594538` (federation-portal PR #1021, on top of #1022). All **27** files under `services/firewall-gateway/` are mirrored as exact Git blobs; `config/firewall-gateway-migration.json` (read by the mirrored tests) is pinned as an attested supporting file.
- New read-only endpoints: `/git-head.json` (served SHA from `RENDER_GIT_COMMIT` only), `/_status/parent`, `/_status/readiness` (productionReady/storage/E2E/DNS all false), and `independentApps` on `/healthz`, `/api/status`, `/api/catalog`.
- Live QA accepts the pre-deploy 404 or the deployed endpoints, and fails if readiness ever claims productionReady, independent storage, authenticated E2E, DNS or a cutover.
- Render (`srv-dbm40fp42hec73djn4cg`, auto-deploy OFF) must be manually deployed to the merge commit of this distribution PR.

## Assistant cost guard and answer-contract fields (2026-11-06)

- Canonical reviewed commit: `8f76d282d93646d5e11a4c5b31c1c8d1665dc074` (federation-portal PR #1029 + #1038). All **27** files under `services/firewall-gateway/` are mirrored as exact Git blobs; the supporting `config/firewall-gateway-migration.json` blob is unchanged.
- `POST /api/v1/assistant/ask` fields follow Seneschal `docs/qa/assistant-answer-contract.md`: request `{appId,question,language,history,context,character,page,requestId?}` (32KB), response `{ok,status,answer,provider,error,requestId}`. The first #1015 relay shape is still accepted as a transitional mapping.
- Provider calls stay **OFF** unless all of `FIREWALL_ASSISTANT_ENABLED=true`, `FIREWALL_ASSISTANT_PROVIDER` (gemini default / openai), the matching `FIREWALL_ASSISTANT_GEMINI_KEY`/`FIREWALL_ASSISTANT_OPENAI_KEY`, `FIREWALL_ASSISTANT_MODEL`, `FIREWALL_ASSISTANT_BUDGET_MICROS` (≤5,000,000), `FIREWALL_ASSISTANT_MAX_CALL_MICROS` (≤100,000), `FIREWALL_ASSISTANT_EXPIRES_AT` (≤24h after boot) and `FIREWALL_ASSISTANT_CLIENT_IDS` are valid. Keep them unset on Render; do not arm without the owner.
- Public policy `paidProviderCallsAllowed`/`userDataForwardingAllowed` read `assistant-armed-only`. Live QA accepts that value (or the pre-deploy `false`) and fails on any wider value or on `assistantEnabled:true`.
- Render (`srv-dbm40fp42hec73djn4cg`, auto-deploy OFF) must be manually deployed to the merge commit of this distribution PR.

## Shared family status contract (2026-11-06)

- Canonical reviewed commit: `aa02c084a977adce1c80189c2fb5463abbd552c6` (federation-portal PR #1048). `README.md`, `server.mjs` and `test/server.test.mjs` are mirrored as exact Git blobs; the other 24 files and the supporting migration config are unchanged.
- `/_status/readiness` now uses `federation.independent-readiness/1` with `app:"firewall"` and `frontendHostIndependent:true` (evidence recorded); every other readiness value is unchanged and still false where unproven.
- `/_status/parent` reports `service:"firewall-standalone"` plus `gatewayService:"federation-firewall-gateway"`. `/api/status` and `/healthz` keep `service:"federation-firewall-gateway"`.
