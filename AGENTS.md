# AGENTS.md

Guidance for agents/devs editing this repo. Keep changes small, validated, and aligned with Cloudflare best practices. See [README.md](README.md) for full setup.

## What it is
A Cloudflare Worker that collects phishing reports, runs optional scanner APIs, stores them in D1, and runs a human-in-the-loop Discord approval Workflow that appends approved hostnames to a Cloudflare One Gateway list and files abuse reports.

## Layout
- `src/index.ts` — Worker routes + `PhishingHostnameWorkflow`.
- `src/approval.ts` — Discord verify/interactions + Cloudflare One list.
- `src/provider-reporting.ts` — post-approval reporting: Netcraft / Cloudflare Abuse / Microsoft MSRC.
- `src/abuse-contacts.ts` — submission-time registrar/host abuse-contact lookup (reporter CTA, display-only).
- `src/rdap.ts` — shared DoH + RDAP primitives used by the two above. **Reuse these; don't re-duplicate.**
- `src/hostname.ts` — URL/hostname normalization + validation.
- `src/shared.ts` — shared HTTP helpers (headers, body, errors, config). **Reuse these; don't re-duplicate.**
- `migrations/` — canonical D1 schema (`wrangler d1 migrations`); `databases/` is historical only.
- `public/` — static frontend; `_headers` is authoritative for page security headers.

## Commands
- `npm run check` — typegen + typecheck (src and tests) + asset syntax. Run before every commit.
- `npm test` — Vitest via `@cloudflare/vitest-pool-workers` (`tests/*.test.ts`, run inside workerd with the bindings from `wrangler.jsonc`; see `vitest.config.mts`).
- `npm run test:watch` — Vitest watch mode.
- `npm run deploy:dry-run` — bundle without deploying.
- `npm run migrate` / `npm run migrate:staging` — apply pending D1 migrations to the remote (prod/staging) database. **Run this before/with any deploy that adds a migration** — `wrangler deploy` does NOT apply migrations, so shipping code that reads a new column without migrating first throws `D1_ERROR: no such column` at runtime (this is what broke `approval_error`).
- `npm run deploy` / `npm run deploy:staging` — deploy.
- Validate every change with: `npm run check && npm test && npm run deploy:dry-run`.

## Project rules
- **Tests**: TypeScript, typechecked via `tests/tsconfig.json`. They execute in workerd, so Node APIs are limited to what `nodejs_compat` provides (`node:assert`, `node:buffer`, ...). Integration tests use `SELF` from `cloudflare:test`. The test D1 is seeded by applying `migrations/` in `tests/apply-migrations.ts` (injected as the `TEST_MIGRATIONS` binding), so read-path tests run against the real schema.
- **Workflows**: one `step.do` per external/non-idempotent call; keep step returns small (<1 MiB — see `capProviderResult`); throw `NonRetryableError` for terminal/config errors; provider fns throw on transient errors (step retries) and return on skip. Validate `waitForEvent` payloads at runtime (type parameters are not enforced) and use `WorkflowStepContext.attempt` to keep retried non-idempotent steps idempotent (see the Discord send step).
- **D1**: prepared statements with `?`; batch writes via `db.batch`; validate UUIDv4 before querying; schema changes go through `migrations/`. Every column named in SQL — the `saveReportToDB` INSERT list and read projections like `REPORT_COLUMNS` — must exist in `migrations/` **and be applied to the remote DB** (`npm run migrate` — `wrangler deploy` won't do it); a non-existent column 500s every write/read of a row (e.g. an unapplied `approval_error` migration crashed the approval Workflow's `record approval decision` step before it could add the hostname to the Gateway list). The test DB applies all of `migrations/`, so an orphaned/un-applied migration there can mask schema drift that breaks prod (this happened with a stray `abuse_contacts` migration). Abuse contacts are display-only and intentionally not persisted. Inside Workflow steps, do not add in-function retries — `step.do` already retries the whole step; the fetch handler uses `runD1WriteWithRetry`.
- **Security headers**: edit `public/_headers` AND `SECURITY_HEADERS`/`HTML_CSP` in `src` together. `index` needs no `style-src 'unsafe-inline'`; `/report` requires it (inline `<style>`/`style=`).
- **Secrets**: never in `wrangler.jsonc`/source — use `wrangler secret put`. Don't hand-edit `worker-configuration.d.ts` (run `npm run cf-typegen`).
- **Install scripts**: npm 11 blocks package lifecycle (postinstall) scripts by default; the `allowScripts` allowlist in `package.json` permits only the ones the toolchain needs — `esbuild`/`workerd` (native binaries for the bundler and the workerd test runtime) and `fsevents` (macOS file-watching). Keep it: removing it breaks `npm install` (and therefore check/test/deploy) on a clean checkout. `sharp` is intentionally left out (the toolchain works without it) — don't add scripts we don't need. When a dependency bump changes a pinned version npm warns again; review, then re-approve with `npm approve-scripts <pkg>`.
- **Edge protection / verify**: staging is behind Cloudflare Access (`302` to login), production behind a WAF rule (`403` to bots) — you can't `curl`-verify a deploy anonymously. Confirm via `wrangler deployments list` + D1 queries, or an allowed/authenticated browser. `POST /discord/interactions` needs an Access bypass / WAF skip (Discord can't authenticate through Access).

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
- **`getReportFromDB` read batching** — its two reads are intentionally left unbatched to preserve the graceful fallback when `provider_reports` is absent; batch via `db.batch` once that table is guaranteed present.
- **Admin dashboard** — no UI for pending/expired approvals (status lives in D1 only).
- **`/api/report/:id` auth** — unauthenticated by design (UUIDv4 entropy); projection already minimized. Revisit if enumeration ever matters.
