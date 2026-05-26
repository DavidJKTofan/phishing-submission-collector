import assert from 'node:assert/strict';
import test, { afterEach } from 'node:test';

import {
	findCloudflareNameserver,
	reportToCloudflareAbuse,
	reportToMicrosoftMsrc,
	reportToNetcraft,
} from '/private/tmp/phishing-submission-collector-tests/src/provider-reporting.js';

const originalFetch = globalThis.fetch;

afterEach(() => {
	globalThis.fetch = originalFetch;
});

test('reports approved URLs to Netcraft', async () => {
	const calls = mockFetch(() => jsonResponse({ message: 'Successfully reported', uuid: 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' }));

	const result = await reportToNetcraft(makeEnv({ NETCRAFT_SOURCE_UUID: 'source-uuid' }), makeReport({ source: 'SMS' }));

	assert.equal(result.status, 'submitted');
	assert.equal(result.referenceId, 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa');
	assert.equal(calls[0].url, 'https://report.netcraft.com/api/v3/report/urls');
	const body = JSON.parse(calls[0].init.body);
	assert.equal(body.email, 'reports@example.com');
	assert.equal(body.source, 'source-uuid');
	assert.equal(body.urls[0].url, 'https://login.bad.example/path');
	assert.deepEqual(body.urls[0].tags, ['smishing']);
});

test('detects Cloudflare nameservers through Cloudflare DoH parent-domain lookup', async () => {
	mockFetch((url) => {
		const requestUrl = new URL(url);
		if (requestUrl.hostname === 'cloudflare-dns.com' && requestUrl.searchParams.get('name') === 'login.bad.example') {
			return jsonResponse({ Status: 0 });
		}
		if (requestUrl.hostname === 'cloudflare-dns.com' && requestUrl.searchParams.get('name') === 'bad.example') {
			return jsonResponse({ Status: 0, Answer: [{ type: 2, data: 'ada.ns.cloudflare.com.' }] });
		}
		throw new Error(`unexpected fetch ${url}`);
	});

	const result = await findCloudflareNameserver('login.bad.example');

	assert.equal(result.matched, true);
	assert.equal(result.domain, 'bad.example');
	assert.deepEqual(result.nameservers, ['ada.ns.cloudflare.com']);
});

test('submits Cloudflare abuse reports only when Cloudflare nameservers match', async () => {
	const calls = mockFetch((url) => {
		const requestUrl = new URL(url);
		if (requestUrl.hostname === 'cloudflare-dns.com' && requestUrl.searchParams.get('name') === 'login.bad.example') {
			return jsonResponse({ Status: 0 });
		}
		if (requestUrl.hostname === 'cloudflare-dns.com' && requestUrl.searchParams.get('name') === 'bad.example') {
			return jsonResponse({ Status: 0, Answer: [{ type: 2, data: 'bob.ns.cloudflare.com.' }] });
		}
		if (url === 'https://rdap.cloudflare.com/rdap/v1/domain/bad.example') return jsonResponse({ objectClassName: 'domain' });
		if (url === 'https://api.cloudflare.com/client/v4/accounts/account-1/abuse-reports/abuse_phishing') {
			return jsonResponse({ abuse_rand: 'cf-report-1', request: { act: 'abuse_phishing' }, result: 'success' });
		}
		throw new Error(`unexpected fetch ${url}`);
	});

	const result = await reportToCloudflareAbuse(makeEnv(), makeReport());

	assert.equal(result.status, 'submitted');
	assert.equal(result.referenceId, 'cf-report-1');
	assert.equal(calls.at(-1).init.method, 'POST');
	const body = JSON.parse(calls.at(-1).init.body);
	assert.equal(body.act, 'abuse_phishing');
	assert.equal(body.urls, 'https://login.bad.example/path');
	assert.equal(body.host_notification, 'send-anon');
});

test('skips Cloudflare abuse reports when nameservers are not Cloudflare', async () => {
	const calls = mockFetch((url) => {
		const requestUrl = new URL(url);
		if (requestUrl.hostname === 'cloudflare-dns.com') {
			return jsonResponse({ Status: 0, Answer: [{ type: 2, data: 'ns1.example.net.' }] });
		}
		throw new Error(`unexpected fetch ${url}`);
	});

	const result = await reportToCloudflareAbuse(makeEnv(), makeReport());

	assert.equal(result.status, 'skipped');
	assert.match(result.eligibilityReason, /No Cloudflare nameservers/);
	assert.equal(calls.some((call) => call.url.includes('/abuse-reports/')), false);
});

test('submits Microsoft MSRC reports after CNAME and Microsoft IP RDAP ownership checks', async () => {
	const calls = mockFetch((url) => {
		const requestUrl = new URL(url);
		if (requestUrl.hostname === 'cloudflare-dns.com') {
			const name = requestUrl.searchParams.get('name');
			const type = requestUrl.searchParams.get('type');
			if (name === 'login.bad.example' && type === 'A') return jsonResponse({ Status: 0, Answer: [{ type: 5, data: 'site.azurewebsites.net.' }] });
			if (name === 'login.bad.example' && type === 'CNAME') return jsonResponse({ Status: 0, Answer: [{ type: 5, data: 'site.azurewebsites.net.' }] });
			if (name === 'site.azurewebsites.net' && type === 'A') return jsonResponse({ Status: 0, Answer: [{ type: 1, data: '20.50.0.1' }] });
			return jsonResponse({ Status: 0 });
		}
		if (url === 'https://rdap.org/ip/20.50.0.1') return jsonResponse({ name: 'MICROSOFT-CORP-MSN-AS-BLOCK' });
		if (url === 'https://api.msrc.microsoft.com/report/v3.0/Abuse/report') return jsonResponse({ id: 'msrc-1' });
		throw new Error(`unexpected fetch ${url}`);
	});

	const result = await reportToMicrosoftMsrc(makeEnv(), makeReport());

	assert.equal(result.status, 'submitted');
	assert.equal(result.referenceId, 'msrc-1');
	const msrcCall = calls.find((call) => call.url === 'https://api.msrc.microsoft.com/report/v3.0/Abuse/report');
	assert.ok(msrcCall);
	const body = JSON.parse(msrcCall.init.body);
	assert.equal(body.incidentType, 'Phishing');
	assert.equal(body.destinationIp, '20.50.0.1');
	assert.equal(body.destinationUrl, 'https://login.bad.example/path');
	assert.equal(body.source, 'ReportApi');
});

test('skips Microsoft MSRC reports when resolved IPs are not Microsoft-owned', async () => {
	const calls = mockFetch((url) => {
		const requestUrl = new URL(url);
		if (requestUrl.hostname === 'cloudflare-dns.com' && requestUrl.searchParams.get('type') === 'A') {
			return jsonResponse({ Status: 0, Answer: [{ type: 1, data: '203.0.113.10' }] });
		}
		if (requestUrl.hostname === 'cloudflare-dns.com') return jsonResponse({ Status: 0 });
		if (url === 'https://rdap.org/ip/203.0.113.10') return jsonResponse({ name: 'EXAMPLE-NET' });
		throw new Error(`unexpected fetch ${url}`);
	});

	const result = await reportToMicrosoftMsrc(makeEnv(), makeReport());

	assert.equal(result.status, 'skipped');
	assert.match(result.eligibilityReason, /not owned by Microsoft/);
	assert.equal(calls.some((call) => call.url === 'https://api.msrc.microsoft.com/report/v3.0/Abuse/report'), false);
});

function makeEnv(overrides = {}) {
	return {
		CLOUDFLARE_ACCOUNT_ID: 'account-1',
		CLOUDFLARE_API_TOKEN: 'token-1',
		REPORTER_COUNTRY: 'US',
		REPORTER_EMAIL: 'reports@example.com',
		REPORTER_NAME: 'Security Team',
		REPORTER_ORG: 'Example Security',
		REPORTER_PHONE: '+15555550100',
		...overrides,
	};
}

function makeReport(overrides = {}) {
	return {
		reportId: 'report-1',
		name: 'Alice Reporter',
		category: 'Phishing',
		source: 'Website',
		submittedUrl: 'https://login.bad.example/path',
		normalizedHostname: 'login.bad.example',
		description: 'Credential harvesting page.',
		urlscanUuid: 'urlscan-1',
		virustotalScanId: 'vt-1',
		cloudflareScanUuid: 'cfscan-1',
		...overrides,
	};
}

function mockFetch(handler) {
	const calls = [];
	globalThis.fetch = async (url, init = {}) => {
		const call = { url: String(url), init };
		calls.push(call);
		return handler(call.url, init, calls.length - 1);
	};
	return calls;
}

function jsonResponse(body, status = 200) {
	return new Response(JSON.stringify(body), {
		status,
		headers: { 'Content-Type': 'application/json' },
	});
}
