# Phishing Submission Collector

A simple tool built on the [Cloudflare Developer Platform](https://developers.cloudflare.com/products/?product-group=Developer+platform) to collect and analyze phishing submissions using various APIs for enhanced threat detection, reporting, and storage.

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
│   ├── index.html            # Frontend HTML
│   ├── assets/
│   │   ├── scripts.js        # Frontend Scripts
│   │   ├── styles.css        # Frontend Stylesheets
│   │   └── ...               # Other assets
│   └── ...                   # Other assets
│
└── wrangler.toml             # Cloudflare Workers configuration
```

## APIs

The following APIs are integrated into this project for phishing analysis and scanning:

- [urlscan.io API v1](https://urlscan.io/docs/api/)
- [VirusTotal API v3](https://docs.virustotal.com/reference/overview)
- [Cloudflare URL Scanner API](https://developers.cloudflare.com/radar/investigate/url-scanner/)

> The user has the option to skip the usage of these APIs via the frontend during submission.

## Secrets & Environment Variables

Environment variables required for this project:

```
URLSCAN_API_KEY="<YOUR_API_KEY_HERE>"
VIRUSTOTAL_API_KEY="<YOUR_API_KEY_HERE>"
CLOUDFLARE_ACCOUNT_ID="<YOUR_CLOUDFLARE_ACCOUNT_ID>"
CLOUDFLARE_USER_EMAIL="<YOUR_CLOUDFLARE_USER_EMAIL>"
CLOUDFLARE_API_KEY="<YOUR_CLOUDFLARE_API_KEY>"
TURNSTILE_SECRET_KEY="<YOUR_TURNSTILE_SECRET_KEY>"
```

To configure these [Secrets](https://developers.cloudflare.com/workers/configuration/secrets/) for your Cloudflare Workers environment, use the following command:

```
npx wrangler secret put <KEY>
```

## App Security

We integrated [Turnstile](https://developers.cloudflare.com/turnstile/).

> Replace the `sitekey` variable in the `script.js` file with your own [Sitekey](https://developers.cloudflare.com/turnstile/get-started/#get-a-sitekey-and-secret-key).

## Local Development & Testing

To run the project locally:

1. Clone this repository.
2. Install the Cloudflare Workers CLI ([wrangler](https://developers.cloudflare.com/workers/wrangler/install-and-update/)) if you haven't already.
3. Start the [development server](https://developers.cloudflare.com/workers/testing/local-development/#supported-resource-bindings-in-different-environments):

```
npx wrangler dev
```

For more information on deploying Workers, refer to the [documentation](https://developers.cloudflare.com/workers/static-assets/get-started/#deploy-a-full-stack-application).

## D1 Reports Database

Create the D1 database:

```
npx wrangler d1 create reports_db
```

Apply the schema to the database:

```
npx wrangler d1 execute reports_db --remote --file ./databases/001_create_table.sql
```

(Optional) Seed the database with test data:

```
npx wrangler d1 execute reports_db --remote --file ./databases/002_seed_data.sql
```

Validate the setup:

```
npx wrangler d1 execute reports_db --remote --command="SELECT * FROM reports"
```

### Managing Schema Updates

For schema changes, create new SQL files (e.g., `003_add_new_column.sql`) and maintain a clear version history. This ensures traceability and consistency across deployments.

---

# Reporting Entities

Below is a non-exhaustive list of organizations where phishing threats and malicious activities can be reported:

- [Google Safe Browsing](https://safebrowsing.google.com/safebrowsing/report_phish/?hl=en)
- [Microsoft Report Unsafe Sites](https://www.microsoft.com/en-us/wdsi/support/report-unsafe-site)
- [VirusTotal](https://www.virustotal.com/)
- [Spamhaus](https://submit.spamhaus.org/submit)
- [Barracuda Central](https://www.barracudacentral.org/report)
- [Netcraft](https://report.netcraft.com/report)
- [Polyswarm](https://polyswarm.network/)
- [OPSWAT MetaDefender](https://metadefender.opswat.com/)
- [CISA Incident Reporting](https://myservices.cisa.gov/irf) *(USA)*
- [eConsumer.gov](https://econsumer.gov/?lang=en-US) *(USA)*
- [FTC Report Fraud](https://reportfraud.ftc.gov/) *(USA)*
- [Europol Cybercrime Reporting](https://www.europol.europa.eu/report-a-crime/report-cybercrime-online) *(Europe)*
- [UK NCSC Report Phishing Scams](https://www.ncsc.gov.uk/collection/phishing-scams) *(UK)*
- [UK NCSC Report Scam Websites](https://www.ncsc.gov.uk/section/about-this-website/report-scam-website) *(UK)*
- [Internet Complaints (Germany)](https://www.internet-beschwerdestelle.de/en/complaint/submit/e-mail-and-spam.html) *(Germany)*
- [IKT-Sicherheitsportal](https://www.onlinesicherheit.gv.at/Themen/Erste-Hilfe/Meldestellen.html) *(Austria)*
- [Watchlist Internet](https://www.watchlist-internet.at/melde-formular/) *(Austria)*

---

# Disclaimer

This project is intended for educational purposes only and is provided "as-is" without any guarantees.

- Independence: This repository is neither affiliated with nor endorsed by any of the APIs, entities, or organizations mentioned.
- Use Responsibly: Always adhere to the terms of service for any APIs and ensure compliance with local laws when handling sensitive or potentially malicious data.
- Liability: The repository owners are not responsible for misuse or consequences arising from the use of this tool.

For more information, consult the documentation of the respective APIs and legal guidelines for reporting phishing or malicious activities.
