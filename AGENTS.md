# AGENTS.md

Guidance for agents/devs editing this repo. Keep changes small, validated, and aligned with Cloudflare best practices. See [README.md](README.md) for full setup.

## What it is
A Cloudflare Worker that collects phishing reports, runs optional scanner APIs, stores them in D1, and runs a human-in-the-loop Discord approval Workflow that appends approved hostnames to a Cloudflare One Gateway list and files abuse reports.

## Layout
- `src/index.ts` — Worker routes + `PhishingHostnameWorkflow`.
- `src/approval.ts` — Discord verify/interactions + Cloudflare One list.
- `src/provider-reporting.ts` — Netcraft / Cloudflare Abuse / Microsoft MSRC.
- `src/hostname.ts` — URL/hostname normalization + validation.
- `src/shared.ts` — shared HTTP helpers (headers, body, errors, config). **Reuse these; don't re-duplicate.**
- `migrations/` — canonical D1 schema (`wrangler d1 migrations`); `databases/` is historical only.
- `public/` — static frontend; `_headers` is authoritative for page security headers.

## Commands
- `npm run check` — typegen + typecheck + asset syntax. Run before every commit.
- `npm test` — unit tests (`tests/*.test.mjs`, compiled via `tsconfig.test.json`).
- `npm run deploy:dry-run` — bundle without deploying.
- `npm run deploy` / `npm run deploy:staging` — deploy.
- Validate every change with: `npm run check && npm test && npm run deploy:dry-run`.

## Project rules
- **Tests/ESM**: runtime (value) imports between test-compiled `src` modules MUST use a `.js` extension (e.g. `from './shared.js'`); `import type` may omit it. Add new shared modules to `tsconfig.test.json` `include`.
- **Workflows**: one `step.do` per external/non-idempotent call; keep step returns small (<1 MiB — see `capProviderResult`); throw `NonRetryableError` for terminal/config errors; provider fns throw on transient errors (step retries) and return on skip.
- **D1**: prepared statements with `?`; batch writes via `db.batch`; validate UUIDv4 before querying; schema changes go through `migrations/`.
- **Security headers**: edit `public/_headers` AND `SECURITY_HEADERS`/`HTML_CSP` in `src` together. `index` needs no `style-src 'unsafe-inline'`; `/report` requires it (inline `<style>`/`style=`).
- **Secrets**: never in `wrangler.jsonc`/source — use `wrangler secret put`. Don't hand-edit `worker-configuration.d.ts` (run `npm run cf-typegen`).

## References
- Workers best practices — https://developers.cloudflare.com/workers/best-practices/workers-best-practices/
- Rules of Workflows — https://developers.cloudflare.com/workflows/build/rules-of-workflows/
- Workflows retries — https://developers.cloudflare.com/workflows/build/sleeping-and-retrying/
- D1 best practices — https://developers.cloudflare.com/d1/best-practices/query-d1/
- D1 migrations — https://developers.cloudflare.com/d1/reference/migrations/
- Turnstile server validation — https://developers.cloudflare.com/turnstile/get-started/server-side-validation/

## Roadmap / to discuss (not yet decided)
Deferred or optional improvements — discuss before implementing; none are committed to.
- **Scanner enrichment in `/submit`** — currently synchronous in the request path. Moving it into the Workflow would speed up submit and add retries, but loses the instant scan links in the success panel. _Decision so far: leave as-is._
- **`report.html` inline styles** — has an inline `<style>` block + `style=` attrs, so `/report` still needs `style-src 'unsafe-inline'`. Move them into `styles.css` to drop it (`index` already dropped it).
- **Observability sampling** — `head_sampling_rate` is `0.1`; consider raising toward `1.0` for this low-volume security tool so individual submissions are reliably logged.
- **Rate limiting** — add a Cloudflare Rate Limiting rule for `/submit` (keep outside app code).
- **Discord message idempotency** — the "send Discord approval request" step retries without an idempotency key; a retry after a lost response could post a duplicate approval message.
- **`getReportFromDB` read batching** — its two reads are intentionally left unbatched to preserve the graceful fallback when `provider_reports` is absent; batch via `db.batch` once that table is guaranteed present.
- **Admin dashboard** — no UI for pending/expired approvals (status lives in D1 only).
- **`/api/report/:id` auth** — unauthenticated by design (UUIDv4 entropy); projection already minimized. Revisit if enumeration ever matters.
