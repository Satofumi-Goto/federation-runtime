# Recommendation API architecture — Gateway → Activity → Seneschal (2026-11-07)

User-confirmed target ownership for tentative-schedule recommendations.

```text
External APIs (events, municipality, dining, travel, weather)
    ↓ fixed provider routes, auth, key isolation, size/rate/cost budgets
Federation Firewall Gateway (external egress owner)
    ↓ signed service-to-service provider data with provenance
Activity Console / life-transaction-console (transform, normalize, dedupe)
    ↓ read-only public recommendation feed
Seneschal (combine with user's preferences, calendar and travel time)
    ↓
Unsaved tentative events — no automatic booking or payment
```

## Grounded current state, not a production cutover

- The deployment distribution is `Satofumi-Goto/federation-runtime`, but its **immutable canonical source** is `Satofumi-Goto/federation-portal/services/firewall-gateway/`. This document is *outside* that attested source tree and does not modify its 38 pinned files or protected migration config.
- `config/firewall-gateway-migration.json` currently declares `mode: "shadow-hold"`, `autoCutover: false`, `legacyRoutesEnabled: true`, and zero verified live cutovers. Merely documenting the target does not authorize provider egress or migration.
- `life-transaction-console/base44/functions/publicEvents/entry.ts` still makes legacy provider calls directly. Do not copy its provider fetch logic to new paths. Protect the incumbent until signed Gateway E2E, provider parity, UI proof, failure recovery, budget and reviewed retirement gates pass.
- New provider API credentials, external calls, fixed-URL allowlists, provider commercial contracts and costs belong at Gateway. Activity only consumes Gateway-approved provider data and prepares the public recommendation feed. Seneschal never requires raw provider API keys.
- Exception handling: existing direct ownership for Google Maps/Places, personal calendar/auth, dispatch/vehicles, booking/payment and separately governed map forecast stays per the canonical Gateway policy. This rule targets new **recommendation information sources**, not those protected operations.
- No user calendar data, contacts or detailed personal location may be forwarded to new external providers. Send only provider-safe bounded public filters if contractually authorized.
- Provider inclusion in a catalog means *candidate*, not *connected*, until evidenced. Record `gatewayRouteId`, `provider`, `authConfigured` (Boolean only), `sourceUrl`, `fetchedAt`, `verifiedAt`, `rateAndCostLimit`, `contractStatus`, `cutoverState`. Activity additionally records transformed feed freshness and schema.

## Activation path (separate reviewed PRs)

1. Register each new provider in **canonical Gateway repository**, with reviewed terms, static allowlist and explicit limits. Test denial by default.
2. Mirror exact reviewed canonical files and source attestation to distribution through its formal process, not by editing distribution files directly.
3. Verify one signed Gateway response with sanitized provenance while leaving legacy live traffic untouched.
4. Add Activity normalization adapter to transform that result into `publicEvents` / a read-only recommendation feed with distinct provider and transformation status.
5. Verify Seneschal draft-only recommendation contract and production screenshot plus source SHA.
6. After parity, rollback and stability evidence, request explicit cutover and separately retire that legacy route. Never auto-cutover.

Follow-up task: https://github.com/Satofumi-Goto/seneschal/issues/979
