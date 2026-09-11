#!/usr/bin/env bash
# Smoke-check the staging deployment through Cloudflare Access.
#
# Staging (report-staging.automatic-demo.com) sits behind Access, so anonymous
# curl gets a 302 to the login page. This script authenticates with the Access
# service token bound to the staging app's "Service Auth" policy, read from
# CF_ACCESS_CLIENT_ID / CF_ACCESS_CLIENT_SECRET — or from the gitignored
# .env.staging-access file (see .env.staging-access.example). The secret is
# only ever passed as a request header: no `curl -v`, no echo.
#
#   scripts/staging-check.sh            read-only: GET /, /report, /api/report/<unknown id>
#   scripts/staging-check.sh --submit   ALSO submits one real test report through /submit
#                                       using Turnstile's dummy token (staging runs the
#                                       always-pass testing keys). This writes a row to the
#                                       staging D1, starts the approval Workflow, and posts
#                                       an approval message to Discord — click Deny there.
set -euo pipefail

BASE_URL="${STAGING_BASE_URL:-https://report-staging.automatic-demo.com}"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SUBMIT=0
[[ "${1:-}" == "--submit" ]] && SUBMIT=1

if [[ -z "${CF_ACCESS_CLIENT_ID:-}" || -z "${CF_ACCESS_CLIENT_SECRET:-}" ]] && [[ -f "$ROOT/.env.staging-access" ]]; then
	set -a
	# shellcheck disable=SC1091
	. "$ROOT/.env.staging-access"
	set +a
fi
: "${CF_ACCESS_CLIENT_ID:?set CF_ACCESS_CLIENT_ID (or create .env.staging-access from .env.staging-access.example)}"
: "${CF_ACCESS_CLIENT_SECRET:?set CF_ACCESS_CLIENT_SECRET (or create .env.staging-access from .env.staging-access.example)}"

BODY="$(mktemp)"
trap 'rm -f "$BODY"' EXIT
FAILED=0

# request METHOD PATH [extra curl args...] -> prints the HTTP status; body lands in $BODY
request() {
	local method="$1" path="$2"
	shift 2
	curl -sS -o "$BODY" -w '%{http_code}' -X "$method" \
		-H "CF-Access-Client-Id: $CF_ACCESS_CLIENT_ID" \
		-H "CF-Access-Client-Secret: $CF_ACCESS_CLIENT_SECRET" \
		"$@" "$BASE_URL$path"
}

# expect LABEL GOT WANT
expect() {
	if [[ "$2" == "$3" ]]; then
		printf '  ok   %-58s %s\n' "$1" "$2"
	else
		printf '  FAIL %-58s got %s, want %s\n' "$1" "$2" "$3"
		FAILED=1
	fi
}

echo "Staging smoke check: $BASE_URL"

status="$(curl -sS -o /dev/null -w '%{http_code}' "$BASE_URL/")"
expect "GET / without token (Access still enforced)" "$status" "302"

status="$(request GET /)"
expect "GET / with service token" "$status" "200"
if grep -q 'data-testing-sitekey=' "$BODY"; then
	expect "index.html carries the Turnstile testing-sitekey switch" "yes" "yes"
else
	expect "index.html carries the Turnstile testing-sitekey switch" "no" "yes"
fi

status="$(request GET /report)"
expect "GET /report" "$status" "200"

status="$(request GET /api/report/00000000-0000-4000-8000-000000000000)"
expect "GET /api/report/<unknown uuid> (Worker answers, not Access)" "$status" "404"

if [[ "$SUBMIT" == "1" ]]; then
	# Reserved .test TLD (RFC 2606): never resolvable, so approving it by
	# mistake only pollutes the staging Gateway list. All scanners are skipped
	# so the check does not spend urlscan/VirusTotal/IPQS quota.
	payload='{"name":"Staging smoke check","category":"Other","source":"Other","url":"https://smoke-check.test/","description":"Automated staging smoke check - please Deny.","cf-turnstile-response":"XXXX.DUMMY.TOKEN.XXXX","skip_urlscan":true,"skip_virustotal":true,"skip_ipqualityscore":true,"skip_cloudflare":true}'
	status="$(request POST /submit -H 'Content-Type: application/json' -H "Origin: $BASE_URL" --data "$payload")"
	expect "POST /submit with Turnstile dummy token" "$status" "200"
	if [[ "$status" == "200" ]]; then
		report_id="$(sed -nE 's/.*"id":"([0-9a-f-]{36})".*/\1/p' "$BODY")"
		if [[ -n "$report_id" ]]; then
			status="$(request GET "/api/report/$report_id")"
			expect "GET /api/report/$report_id" "$status" "200"
			echo "  note: a Discord approval message was posted for this report - click Deny."
		else
			expect "submit response contains a report id" "no" "yes"
		fi
	else
		echo "  body: $(head -c 300 "$BODY")"
	fi
fi

if [[ "$FAILED" == "1" ]]; then
	echo "FAILED"
	exit 1
fi
echo "OK"
