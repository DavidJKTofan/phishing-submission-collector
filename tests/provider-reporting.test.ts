import assert from 'node:assert/strict';
import { afterEach, it as test } from 'vitest';

import {
	capProviderResult,
	findCloudflareNameserver,
	reportToCloudflareAbuse,
	reportToMicrosoftMsrc,
	reportToNetcraft,
} from '../src/provider-reporting';
import type { ProviderReportResult, ProviderReportingEnv } from '../src/provider-reporting';
import type { PhishingHostnameWorkflowParams } from '../src/approval';

type FetchCall = { url: string; init: RequestInit };

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
	const body = JSON.parse(String(calls[0].init.body));
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
	const lastCall = calls[calls.length - 1];
	assert.equal(lastCall.init.method, 'POST');
	const body = JSON.parse(String(lastCall.init.body));
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
	assert.match(result.eligibilityReason ?? '', /No Cloudflare nameservers/);
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
	const body = JSON.parse(String(msrcCall.init.body));
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
	assert.match(result.eligibilityReason ?? '', /not owned by Microsoft/);
	assert.equal(calls.some((call) => call.url === 'https://api.msrc.microsoft.com/report/v3.0/Abuse/report'), false);
});

test('skips Microsoft MSRC reports when RDAP only mentions Microsoft outside ownership fields', async () => {
	mockFetch((url) => {
		const requestUrl = new URL(url);
		if (requestUrl.hostname === 'cloudflare-dns.com' && requestUrl.searchParams.get('type') === 'A') {
			return jsonResponse({ Status: 0, Answer: [{ type: 1, data: '203.0.113.10' }] });
		}
		if (requestUrl.hostname === 'cloudflare-dns.com') return jsonResponse({ Status: 0 });
		if (url === 'https://rdap.org/ip/203.0.113.10') {
			// "azure" appears only in a remark, not in any ownership field.
			return jsonResponse({ name: 'EXAMPLE-NET', remarks: [{ description: ['Customer migrated from azure hosting'] }] });
		}
		throw new Error(`unexpected fetch ${url}`);
	});

	const result = await reportToMicrosoftMsrc(makeEnv(), makeReport());

	assert.equal(result.status, 'skipped');
});

test('detects Microsoft ownership from RDAP entity vCards', async () => {
	const calls = mockFetch((url) => {
		const requestUrl = new URL(url);
		if (requestUrl.hostname === 'cloudflare-dns.com' && requestUrl.searchParams.get('type') === 'A') {
			return jsonResponse({ Status: 0, Answer: [{ type: 1, data: '20.50.0.1' }] });
		}
		if (requestUrl.hostname === 'cloudflare-dns.com') return jsonResponse({ Status: 0 });
		if (url === 'https://rdap.org/ip/20.50.0.1') {
			return jsonResponse({
				name: 'NETBLK-1',
				entities: [{ handle: 'MSFT', vcardArray: ['vcard', [['fn', {}, 'text', 'Microsoft Corporation']]] }],
			});
		}
		if (url === 'https://api.msrc.microsoft.com/report/v3.0/Abuse/report') return jsonResponse({ id: 'msrc-2' });
		throw new Error(`unexpected fetch ${url}`);
	});

	const result = await reportToMicrosoftMsrc(makeEnv(), makeReport());

	assert.equal(result.status, 'submitted');
	assert.ok(calls.some((call) => call.url === 'https://api.msrc.microsoft.com/report/v3.0/Abuse/report'));
});

test('capProviderResult passes small responses through unchanged', () => {
	const result: ProviderReportResult = { provider: 'netcraft', status: 'submitted', referenceId: 'abc', responseJson: { ok: true, note: 'small' } };
	assert.deepEqual(capProviderResult(result), result);
});

test('capProviderResult truncates oversized response payloads while preserving status fields', () => {
	const big = 'x'.repeat(20_000);
	const result: ProviderReportResult = {
		provider: 'cloudflare_abuse',
		status: 'submitted',
		referenceId: 'ref-1',
		eligibilityReason: 'Cloudflare nameserver found',
		responseJson: { rdap: big },
	};

	const capped = capProviderResult(result);
	const responseJson = capped.responseJson as { truncated: boolean; original_chars: number; preview: string };

	assert.equal(capped.provider, 'cloudflare_abuse');
	assert.equal(capped.status, 'submitted');
	assert.equal(capped.referenceId, 'ref-1');
	assert.equal(capped.eligibilityReason, 'Cloudflare nameserver found');
	assert.equal(responseJson.truncated, true);
	assert.ok(responseJson.original_chars > 12_000);
	assert.ok(responseJson.preview.length <= 12_000);
	assert.deepEqual(result.responseJson, { rdap: big }, 'original result must not be mutated');
});

test('capProviderResult leaves results without a response payload untouched', () => {
	const result: ProviderReportResult = { provider: 'microsoft_msrc', status: 'skipped', eligibilityReason: 'No A or AAAA records resolved.' };
	assert.deepEqual(capProviderResult(result), result);
});

function makeEnv(overrides: Partial<ProviderReportingEnv> = {}): ProviderReportingEnv {
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

function makeReport(overrides: Partial<PhishingHostnameWorkflowParams> = {}): PhishingHostnameWorkflowParams {
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

function mockFetch(handler: (url: string, init: RequestInit, index: number) => Response | Promise<Response>): FetchCall[] {
	const calls: FetchCall[] = [];
	globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
		const call: FetchCall = { url: String(input), init: init ?? {} };
		calls.push(call);
		return handler(call.url, call.init, calls.length - 1);
	}) as typeof fetch;
	return calls;
}

function jsonResponse(body: unknown, status = 200): Response {
	return new Response(JSON.stringify(body), {
		status,
		headers: { 'Content-Type': 'application/json' },
	});
}
