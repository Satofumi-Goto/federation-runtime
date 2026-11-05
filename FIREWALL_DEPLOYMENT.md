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
