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
