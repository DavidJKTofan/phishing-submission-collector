# Phishing Submission Collector

## Project Structure

```
project/
│
├── src/
│   └── index.js              # Cloudflare Workers script
│
├── databases/
│   ├── 001_create_table.sql  # SQL to set up D1 database
│   └── 002_seed_data.sql     # Optional: Test data for development
│
├── public/
│   └── index.html            # Frontend HTML
│
└── wrangler.toml             # Cloudflare Workers configuration
```

## APIs

- URLScan.io API

- VirusTotal API

- Cloudflare URLScanner API

## Secrets & Environment Variables

Variables used:
```
URLSCAN_API_KEY="<YOUR_API_KEY_HERE>"
VIRUSTOTAL_API_KEY="<YOUR_API_KEY_HERE>"
CLOUDFLARE_ACCOUNT_ID="<YOUR_CLOUDFLARE_ACCOUNT_ID>"
CLOUDFLARE_USER_EMAIL="<YOUR_CLOUDFLARE_USER_EMAIL>"
CLOUDFLARE_API_KEY="<YOUR_CLOUDFLARE_API_KEY>"
```

Add [Secrets](https://developers.cloudflare.com/workers/configuration/secrets/) with `npx wrangler secret put <KEY>`.

> The user can SKIP the usage of these APIs on the frontend.

## Local Development & Testing

Generally followed this [Workers guide](https://developers.cloudflare.com/workers/static-assets/get-started/#deploy-a-full-stack-application).

```
npx wrangler dev
```

## D1 Reports Database

Create D1 database:
```
npx wrangler d1 create reports_db
```

Push the schema to the database:
```
npx wrangler d1 execute reports_db --remote --file ./databases/001_create_table.sql
```

(Optional) Seed the database:
```
npx wrangler d1 execute reports_db --remote --file ./databases/002_seed_data.sql
```

To validate that it works:
```
npx wrangler d1 execute reports_db --remote --command="SELECT * FROM reports"
```

**Version Control for Schema**
Track changes to the database schema by creating separate SQL files for updates (e.g., `003_add_new_column.sql`) and maintaining them in version control.

