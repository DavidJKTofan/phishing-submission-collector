# Phishing Submission Collector

A simple tool built on the [Cloudflare Developer Platform](https://developers.cloudflare.com/products/?product-group=Developer+platform) to collect and analyze phishing submissions using various APIs for enhanced threat detection, reporting, and storage.

## Project Structure

```
project/
│
├── src/
│   └── index.js                # Cloudflare Workers script
│
├── databases/
│   ├── 001_create_table.sql    # SQL to set up D1 database
│   └── 002_seed_data.sql       # Optional: Test data for development
│
├── public/
│   ├── index.html              # Submission form
│   ├── report.html             # Reporting resources & status lookup
│   ├── manifest.json           # PWA manifest
│   ├── favicon.*               # Favicons
│   └── assets/
│       ├── scripts.js          # Frontend scripts (form, Turnstile)
│       └── styles.css          # Frontend stylesheet
│
├── wrangler.toml               # Cloudflare Workers configuration
└── .dev.vars.example           # Template for local secrets (copy to .dev.vars)
```

## APIs

The following APIs are integrated into this project for phishing analysis and scanning:

- [urlscan.io API v1](https://urlscan.io/docs/api/)
- [VirusTotal API v3](https://docs.virustotal.com/reference/overview)
- [IPQualityScore Malicious URL Scanner](https://www.ipqualityscore.com/documentation/malicious-url-scanner-api/overview)
- [Cloudflare URL Scanner API](https://developers.cloudflare.com/radar/investigate/url-scanner/)

> The user can opt out of any of these APIs per submission via the **Advanced API Settings** panel on the form.

## Configuration

### Secrets (per-environment, set via dashboard or `wrangler secret put`)

These are accessed at runtime as `env.<NAME>` and never appear in `wrangler.toml`:

```
URLSCAN_API_KEY="<YOUR_API_KEY_HERE>"
VIRUSTOTAL_API_KEY="<YOUR_API_KEY_HERE>"
IPQS_API_KEY="<YOUR_API_KEY_HERE>"
CLOUDFLARE_ACCOUNT_ID="<YOUR_CLOUDFLARE_ACCOUNT_ID>"
CLOUDFLARE_USER_EMAIL="<YOUR_CLOUDFLARE_USER_EMAIL>"
CLOUDFLARE_API_KEY="<YOUR_CLOUDFLARE_API_KEY>"
TURNSTILE_SECRET_KEY="<YOUR_TURNSTILE_SECRET_KEY>"
```

To upload a secret to a deployed Worker:

```
npx wrangler secret put <KEY>
```

See [Cloudflare Workers Secrets](https://developers.cloudflare.com/workers/configuration/secrets/) for details.

### Public vars (declared in `wrangler.toml [vars]`)

Both are optional. If unset, the worker falls back to permissive defaults so existing deployments keep working.

| Var | Purpose | Example |
|---|---|---|
| `ALLOWED_ORIGINS` | Comma-separated CORS allowlist for `/submit` and `/api/report/`. Set to `*` (default) to disable. | `https://report.example.com` |
| `TURNSTILE_EXPECTED_HOSTNAMES` | Comma-separated allowlist for the `hostname` returned by Turnstile siteverify. Disabled if unset. | `report.example.com` |

## App Security

- **Cloudflare Turnstile** — required to submit. The sitekey is set as `data-sitekey` on `#turnstile-container` in [public/index.html](public/index.html); the secret is verified server-side with HTTP `response.ok` checking, an idempotency key, a 5 s timeout via `AbortController`, and an optional hostname allowlist (`TURNSTILE_EXPECTED_HOSTNAMES`). All five Turnstile callbacks (`callback`, `expired-callback`, `error-callback`, `timeout-callback`, `unsupported-callback`) are wired with retry/reset logic.
- **CORS** — origin allowlist driven by `ALLOWED_ORIGINS` with a `Vary: Origin` header.
- **Security response headers** — every response carries `X-Content-Type-Options: nosniff`, `Referrer-Policy: strict-origin-when-cross-origin`, `X-Frame-Options: DENY`, and a restrictive `Permissions-Policy`. HTML responses additionally get a `Content-Security-Policy` that allows the Turnstile script/iframe.
- **Body size guard** — `/submit` rejects requests with `Content-Length > 50 000` bytes (`413`).
- **Input validation** — server-side via the `URL` constructor + protocol allowlist + length cap; category and source restricted to fixed enums.
- **D1 prepared statements** — all reads/writes use `?` placeholders; reads validate UUIDv4 format before querying.

## Accessibility & UX

- Honors `prefers-reduced-motion: reduce` (disables decorative animations on both pages).
- Honors `prefers-color-scheme: dark` (full dark palette on `index.html` and `report.html`); Turnstile widget uses `theme: 'auto'` to match.
- ARIA roles on alerts; decorative SVGs marked `aria-hidden="true"`; submit button has `aria-describedby` pointing to a visible hint about the security check.

## Local Development

1. Clone this repository.
2. Install [wrangler](https://developers.cloudflare.com/workers/wrangler/install-and-update/) (already a dev dependency: `npm install`).
3. Pick a secrets strategy:

   **Option A — use dashboard secrets directly (no local file needed):**
   ```
   npx wrangler dev --remote
   ```

   **Option B — local-only secrets:** copy [.dev.vars.example](.dev.vars.example) to `.dev.vars` (gitignored), fill in values, then:
   ```
   npx wrangler dev
   ```

4. Open <http://localhost:8787/>.

For deployment guidance, see the [Workers static assets docs](https://developers.cloudflare.com/workers/static-assets/get-started/#deploy-a-full-stack-application).

```
npx wrangler deploy
```

## D1 Reports Database

Create the D1 database:

```
npx wrangler d1 create reports_db
```

Apply the schema:

```
npx wrangler d1 execute reports_db --remote --file ./databases/001_create_table.sql
```

(Optional) Seed test data:

```
npx wrangler d1 execute reports_db --remote --file ./databases/002_seed_data.sql
```

Validate the setup (table is `reports_v2`):

```
npx wrangler d1 execute reports_db --remote --command="SELECT id, name, category, timestamp FROM reports_v2 ORDER BY timestamp DESC LIMIT 5"
```

### Managing schema updates

For schema changes, create new SQL files (e.g., `003_add_new_column.sql`) and maintain a clear version history. This ensures traceability and consistency across deployments.

## Endpoints

| Method | Path | Description |
|---|---|---|
| `POST` | `/submit` | Submit a URL with Turnstile verification. Body: JSON. |
| `GET`  | `/api/report/:id` | Look up a stored report by UUID. |
| `GET`  | `/random` | Returns a fresh UUID (utility). |
| `GET`  | `/*` | Static assets from `./public/` via the `ASSETS` binding. |

## Reporting Entities

The submission form ([public/report.html](public/report.html)) is the canonical, regularly-updated directory of reporting destinations (browsers, URL analysis tools, malware analysis, security services, regional CERTs, email-provider phishing reports). Live preview: <https://report.automatic-demo.com/report.html>.

## Known Limitations / Future Work

- **No rate limiting** — recommend adding a Cloudflare Rate Limiting Rule on `/submit` (or KV-backed token bucket).
- **`reports_v2.last_updated`** — declared but never updated (no trigger). Either remove or wire up an `UPDATE` trigger.
- **`/api/report/:id` is publicly readable by UUID** — acceptable given UUIDv4 entropy, but no auth.
- **TypeScript migration** — `src/index.js` is plain JS; per-project conventions prefer TypeScript for new code.

## Disclaimer

This project is intended for educational purposes only and is provided "as-is" without any guarantees.

- **Independence:** This repository is neither affiliated with nor endorsed by any of the APIs, entities, or organizations mentioned.
- **Use Responsibly:** Always adhere to the terms of service for any APIs and ensure compliance with local laws when handling sensitive or potentially malicious data.
- **Liability:** The repository owners are not responsible for misuse or consequences arising from the use of this tool.

For more information, consult the documentation of the respective APIs and legal guidelines for reporting phishing or malicious activities.
