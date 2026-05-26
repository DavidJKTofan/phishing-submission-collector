import type { PhishingHostnameWorkflowParams } from './approval';

const CLOUDFLARE_API_BASE = 'https://api.cloudflare.com/client/v4';
const CLOUDFLARE_DOH_ENDPOINT = 'https://cloudflare-dns.com/dns-query';
const CLOUDFLARE_RDAP_DOMAIN_BASE = 'https://rdap.cloudflare.com/rdap/v1/domain';
const MICROSOFT_MSRC_ABUSE_ENDPOINT = 'https://api.msrc.microsoft.com/report/v3.0/Abuse/report';
const NETCRAFT_REPORT_URLS_ENDPOINT = 'https://report.netcraft.com/api/v3/report/urls';
const RDAP_IP_BASE = 'https://rdap.org/ip';
const PROVIDER_TIMEOUT_MS = 20_000;
const MAX_PROVIDER_RESPONSE_CHARS = 12_000;

export const PROVIDERS = ['netcraft', 'cloudflare_abuse', 'microsoft_msrc'] as const;

export type ProviderName = (typeof PROVIDERS)[number];
export type ProviderReportStatus = 'not_started' | 'skipped' | 'submitted' | 'failed';
export type JsonValue = string | number | boolean | null | JsonValue[] | { [key: string]: JsonValue };

export type ProviderReportResult = {
	provider: ProviderName;
	status: ProviderReportStatus;
	eligibilityReason?: string;
	referenceId?: string;
	httpStatus?: number;
	responseJson?: JsonValue;
	error?: string;
};

export type ProviderReportingEnv = {
	CLOUDFLARE_ACCOUNT_ID?: string;
	CLOUDFLARE_API_TOKEN?: string;
	NETCRAFT_SOURCE_UUID?: string;
	REPORTER_COUNTRY?: string;
	REPORTER_EMAIL?: string;
	REPORTER_NAME?: string;
	REPORTER_ORG?: string;
	REPORTER_PHONE?: string;
};

type DnsAnswer = {
	name?: string;
	type?: number;
	TTL?: number;
	data?: string;
};

type DnsJsonResponse = {
	Status?: number;
	Answer?: DnsAnswer[];
	Authority?: DnsAnswer[];
};

type ReporterIdentity = {
	email: string;
	name: string;
	org?: string;
	country?: string;
	phone?: string;
};

type MicrosoftIpMatch = {
	ip: string;
	rdap: JsonValue;
};

type ResolvedIps = {
	ips: string[];
	cnames: string[];
};

export async function runProviderReporting(
	env: ProviderReportingEnv,
	report: PhishingHostnameWorkflowParams
): Promise<ProviderReportResult[]> {
	return Promise.all([
		runProvider('netcraft', () => reportToNetcraft(env, report)),
		runProvider('cloudflare_abuse', () => reportToCloudflareAbuse(env, report)),
		runProvider('microsoft_msrc', () => reportToMicrosoftMsrc(env, report)),
	]);
}

export async function reportToNetcraft(
	env: ProviderReportingEnv,
	report: PhishingHostnameWorkflowParams
): Promise<ProviderReportResult> {
	const reporter = requireReporterIdentity(env);
	const urlReport: Record<string, unknown> = {
		url: report.submittedUrl,
		reason: buildEvidenceNotes(report),
	};
	if (report.source === 'SMS') urlReport.tags = ['smishing'];

	const body: Record<string, unknown> = {
		email: reporter.email,
		reason: buildEvidenceNotes(report),
		urls: [urlReport],
	};
	if (env.NETCRAFT_SOURCE_UUID) body.source = env.NETCRAFT_SOURCE_UUID;

	const response = await fetch(NETCRAFT_REPORT_URLS_ENDPOINT, {
		method: 'POST',
		headers: { 'Content-Type': 'application/json' },
		body: JSON.stringify(body),
	});
	const data = await readResponseBody(response);
	if (!response.ok) throw providerHttpError('Netcraft', response, data);

	return {
		provider: 'netcraft',
		status: 'submitted',
		eligibilityReason: 'always',
		referenceId: stringValue(data, 'uuid'),
		httpStatus: response.status,
		responseJson: data,
	};
}

export async function reportToCloudflareAbuse(
	env: ProviderReportingEnv,
	report: PhishingHostnameWorkflowParams
): Promise<ProviderReportResult> {
	const eligibility = await findCloudflareNameserver(report.normalizedHostname);
	if (!eligibility.matched) {
		return {
			provider: 'cloudflare_abuse',
			status: 'skipped',
			eligibilityReason: eligibility.reason,
			responseJson: toJsonValue(eligibility),
		};
	}

	const reporter = requireReporterIdentity(env);
	const accountId = requireConfig(env.CLOUDFLARE_ACCOUNT_ID, 'CLOUDFLARE_ACCOUNT_ID');
	const apiToken = requireConfig(env.CLOUDFLARE_API_TOKEN, 'CLOUDFLARE_API_TOKEN');
	const rdap = eligibility.domain ? await fetchCloudflareDomainRdap(eligibility.domain) : undefined;
	const body = compactObject({
		act: 'abuse_phishing',
		comments: buildEvidenceNotes(report),
		company: reporter.org,
		email: reporter.email,
		email2: reporter.email,
		host_notification: 'send-anon',
		justification: buildEvidenceNotes(report),
		name: reporter.name,
		original_work: `Phishing report for ${report.normalizedHostname}`,
		owner_notification: 'send-anon',
		reported_country: reporter.country,
		tele: reporter.phone,
		title: `Phishing report for ${report.normalizedHostname}`,
		urls: report.submittedUrl,
	});

	const response = await fetch(`${CLOUDFLARE_API_BASE}/accounts/${accountId}/abuse-reports/abuse_phishing`, {
		method: 'POST',
		headers: {
			Authorization: `Bearer ${apiToken}`,
			'Content-Type': 'application/json',
		},
		body: JSON.stringify(body),
	});
	const data = await readResponseBody(response);
	if (!response.ok || (isRecord(data) && data.success === false)) throw providerHttpError('Cloudflare Abuse', response, data);

	return {
		provider: 'cloudflare_abuse',
		status: 'submitted',
		eligibilityReason: `Cloudflare nameserver found for ${eligibility.domain || report.normalizedHostname}`,
		referenceId: cloudflareReferenceId(data),
		httpStatus: response.status,
		responseJson: toJsonValue({ eligibility, rdap, response: data }),
	};
}

export async function reportToMicrosoftMsrc(
	env: ProviderReportingEnv,
	report: PhishingHostnameWorkflowParams
): Promise<ProviderReportResult> {
	const resolved = await resolveHostnameIps(report.normalizedHostname);
	if (resolved.ips.length === 0) {
		return {
			provider: 'microsoft_msrc',
			status: 'skipped',
			eligibilityReason: 'No A or AAAA records resolved.',
			responseJson: toJsonValue(resolved),
		};
	}

	const match = await findMicrosoftOwnedIp(resolved.ips);
	if (!match) {
		return {
			provider: 'microsoft_msrc',
			status: 'skipped',
			eligibilityReason: 'Resolved IPs are not owned by Microsoft.',
			responseJson: toJsonValue(resolved),
		};
	}

	const reporter = requireReporterIdentity(env);
	const now = new Date();
	const body = compactObject({
		anonymizeReport: false,
		date: now.toISOString().slice(0, 10),
		destinationIp: match.ip,
		destinationUrl: report.submittedUrl,
		incidentType: microsoftIncidentType(report.category),
		ipAddressList: [{ destinationIp: match.ip }],
		phoneNumber: reporter.phone,
		reporterEmail: reporter.email,
		reporterName: reporter.name,
		reporterNotes: buildEvidenceNotes(report),
		reporterOrg: reporter.org,
		reportNotes: buildEvidenceNotes(report),
		source: 'ReportApi',
		threatType: 'URL',
		time: now.toISOString().slice(11, 19),
		timeZone: 'UTC',
		urlList: [{ destinationUrl: report.submittedUrl }],
	});

	const response = await fetch(MICROSOFT_MSRC_ABUSE_ENDPOINT, {
		method: 'POST',
		headers: { 'Content-Type': 'application/json' },
		body: JSON.stringify(body),
	});
	const data = await readResponseBody(response);
	if (!response.ok) throw providerHttpError('Microsoft MSRC', response, data);

	return {
		provider: 'microsoft_msrc',
		status: 'submitted',
		eligibilityReason: `Microsoft-owned IP resolved: ${match.ip}`,
		referenceId: stringValue(data, 'id') || stringValue(data, 'reportId') || stringValue(data, 'trackingId'),
		httpStatus: response.status,
		responseJson: toJsonValue({ resolved, rdap: match.rdap, response: data }),
	};
}

async function runProvider(provider: ProviderName, action: () => Promise<ProviderReportResult>): Promise<ProviderReportResult> {
	try {
		return await withTimeout(action, PROVIDER_TIMEOUT_MS);
	} catch (error) {
		return {
			provider,
			status: 'failed',
			error: errorMessage(error),
		};
	}
}

async function withTimeout<T>(action: () => Promise<T>, timeoutMs: number): Promise<T> {
	let timeoutId: ReturnType<typeof setTimeout> | undefined;
	try {
		return await Promise.race([
			action(),
			new Promise<T>((_, reject) => {
				timeoutId = setTimeout(() => reject(new Error(`Provider timeout after ${timeoutMs}ms`)), timeoutMs);
			}),
		]);
	} finally {
		if (timeoutId) clearTimeout(timeoutId);
	}
}

export async function findCloudflareNameserver(hostname: string): Promise<{
	matched: boolean;
	domain?: string;
	nameservers: string[];
	checkedDomains: string[];
	reason: string;
}> {
	const checkedDomains: string[] = [];
	for (const domain of domainCandidates(hostname)) {
		checkedDomains.push(domain);
		const answers = await queryDns(domain, 'NS');
		const nameservers = answers
			.filter((answer) => answer.type === 2 && typeof answer.data === 'string')
			.map((answer) => normalizeDnsName(answer.data || ''));
		if (nameservers.some(isCloudflareNameserver)) {
			return {
				matched: true,
				domain,
				nameservers,
				checkedDomains,
				reason: `Cloudflare nameserver found for ${domain}`,
			};
		}
	}

	return {
		matched: false,
		nameservers: [],
		checkedDomains,
		reason: 'No Cloudflare nameservers found.',
	};
}

async function resolveHostnameIps(hostname: string): Promise<ResolvedIps> {
	const ips = new Set<string>();
	const cnames = new Set<string>();
	const queue = [hostname];
	const seen = new Set<string>();

	while (queue.length > 0 && seen.size < 8) {
		const current = queue.shift();
		if (!current) break;
		const normalized = normalizeDnsName(current);
		if (seen.has(normalized)) continue;
		seen.add(normalized);

		const [aAnswers, aaaaAnswers, cnameAnswers] = await Promise.all([
			queryDns(normalized, 'A'),
			queryDns(normalized, 'AAAA'),
			queryDns(normalized, 'CNAME'),
		]);
		for (const answer of [...aAnswers, ...aaaaAnswers, ...cnameAnswers]) {
			if ((answer.type === 1 || answer.type === 28) && typeof answer.data === 'string') ips.add(answer.data);
			if (answer.type === 5 && typeof answer.data === 'string') {
				const cname = normalizeDnsName(answer.data);
				cnames.add(cname);
				if (!seen.has(cname)) queue.push(cname);
			}
		}
	}

	return { ips: [...ips], cnames: [...cnames] };
}

async function findMicrosoftOwnedIp(ips: string[]): Promise<MicrosoftIpMatch | null> {
	for (const ip of ips) {
		const response = await fetch(`${RDAP_IP_BASE}/${encodeURIComponent(ip)}`, { headers: { Accept: 'application/rdap+json, application/json' } });
		if (!response.ok) continue;
		const data = await readResponseBody(response);
		if (containsMicrosoftOwnership(data)) return { ip, rdap: data };
	}
	return null;
}

async function queryDns(name: string, type: string): Promise<DnsAnswer[]> {
	const url = new URL(CLOUDFLARE_DOH_ENDPOINT);
	url.searchParams.set('name', name);
	url.searchParams.set('type', type);
	const response = await fetch(url.toString(), { headers: { Accept: 'application/dns-json' } });
	if (!response.ok) throw new Error(`Cloudflare DoH ${type} ${name} HTTP ${response.status}`);
	const data = (await response.json()) as DnsJsonResponse;
	if (data.Status !== undefined && ![0, 3].includes(data.Status)) throw new Error(`Cloudflare DoH ${type} ${name} status ${data.Status}`);
	return data.Answer || [];
}

async function fetchCloudflareDomainRdap(domain: string): Promise<JsonValue> {
	const response = await fetch(`${CLOUDFLARE_RDAP_DOMAIN_BASE}/${encodeURIComponent(domain)}`, {
		headers: { Accept: 'application/rdap+json, application/json' },
	});
	const data = await readResponseBody(response);
	if (!response.ok) return { http_status: response.status, error: response.statusText || `HTTP ${response.status}`, response: data };
	return data;
}

function domainCandidates(hostname: string): string[] {
	const labels = hostname.split('.').filter(Boolean);
	const candidates: string[] = [];
	for (let index = 0; index <= labels.length - 2; index += 1) candidates.push(labels.slice(index).join('.'));
	return candidates;
}

function isCloudflareNameserver(value: string): boolean {
	return value.endsWith('.ns.cloudflare.com');
}

function normalizeDnsName(value: string): string {
	return value.trim().toLowerCase().replace(/\.+$/, '');
}

function containsMicrosoftOwnership(value: JsonValue): boolean {
	const haystack = JSON.stringify(value).toLowerCase();
	return haystack.includes('microsoft') || haystack.includes('msft') || haystack.includes('azure');
}

function microsoftIncidentType(category: string): string {
	if (category === 'Malware') return 'Malware';
	if (category === 'Spam') return 'Spam';
	return 'Phishing';
}

function requireReporterIdentity(env: ProviderReportingEnv): ReporterIdentity {
	return {
		email: requireConfig(env.REPORTER_EMAIL, 'REPORTER_EMAIL'),
		name: requireConfig(env.REPORTER_NAME, 'REPORTER_NAME'),
		org: env.REPORTER_ORG || undefined,
		country: env.REPORTER_COUNTRY || undefined,
		phone: env.REPORTER_PHONE || undefined,
	};
}

function requireConfig(value: string | undefined, name: string): string {
	if (!value) throw new Error(`Missing ${name}`);
	return value;
}

function buildEvidenceNotes(report: PhishingHostnameWorkflowParams): string {
	const lines = [
		'Suspected malicious URL approved for provider reporting.',
		`Report ID: ${report.reportId}`,
		`Submitted URL: ${report.submittedUrl}`,
		`Hostname: ${report.normalizedHostname}`,
		`Category: ${report.category}`,
		`Source: ${report.source}`,
		`Submitter name: ${report.name}`,
	];
	if (report.description) lines.push(`Submitter description: ${report.description}`);
	if (report.urlscanUuid) lines.push(`urlscan.io UUID: ${report.urlscanUuid}`);
	if (report.virustotalScanId) lines.push(`VirusTotal URL ID: ${report.virustotalScanId}`);
	if (report.cloudflareScanUuid) lines.push(`Cloudflare Radar scan UUID: ${report.cloudflareScanUuid}`);
	return truncate(lines.join('\n'), 2_000);
}

function truncate(value: string, maxLength: number): string {
	return value.length <= maxLength ? value : `${value.slice(0, maxLength - 3)}...`;
}

function compactObject(value: Record<string, unknown>): Record<string, unknown> {
	return Object.fromEntries(Object.entries(value).filter(([, item]) => item !== undefined && item !== null && item !== ''));
}

async function readResponseBody(response: Response): Promise<JsonValue> {
	const contentType = response.headers.get('Content-Type') || '';
	if (contentType.includes('json')) return response.json().then(toJsonValue).catch(() => ({}));
	const text = await response.text().catch(() => '');
	if (!text) return {};
	try {
		return toJsonValue(JSON.parse(text) as unknown);
	} catch {
		return { text };
	}
}

function toJsonValue(value: unknown): JsonValue {
	if (value === null || typeof value === 'string' || typeof value === 'number' || typeof value === 'boolean') return value;
	if (Array.isArray(value)) return value.map(toJsonValue);
	if (isRecord(value)) {
		const output: { [key: string]: JsonValue } = {};
		for (const [key, item] of Object.entries(value)) output[key] = toJsonValue(item);
		return output;
	}
	return String(value);
}

function providerHttpError(provider: string, response: Response, data: JsonValue): Error {
	const message =
		(isRecord(data) && typeof data.message === 'string' && data.message) ||
		(isRecord(data) && Array.isArray(data.errors) && errorListMessage(data.errors)) ||
		`HTTP ${response.status}`;
	return new Error(`${provider}: ${message}`);
}

function errorListMessage(errors: unknown[]): string {
	return errors
		.map((item) => (isRecord(item) && typeof item.message === 'string' ? item.message : 'Unknown error'))
		.filter(Boolean)
		.join('; ');
}

function cloudflareReferenceId(data: unknown): string | undefined {
	if (!isRecord(data)) return undefined;
	if (typeof data.abuse_rand === 'string') return data.abuse_rand;
	if (typeof data.id === 'string') return data.id;
	if (isRecord(data.result)) {
		return stringValue(data.result, 'id') || stringValue(data.result, 'report_id') || stringValue(data.result, 'reportId');
	}
	return undefined;
}

function stringValue(value: unknown, key: string): string | undefined {
	if (!isRecord(value)) return undefined;
	const item = value[key];
	return typeof item === 'string' && item ? item : undefined;
}

export function serializeProviderResponse(value: unknown): string | null {
	if (value === undefined || value === null) return null;
	const serialized = JSON.stringify(value);
	return serialized.length <= MAX_PROVIDER_RESPONSE_CHARS ? serialized : serialized.slice(0, MAX_PROVIDER_RESPONSE_CHARS);
}

function isRecord(value: unknown): value is Record<string, unknown> {
	return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function errorMessage(error: unknown): string {
	return error instanceof Error ? error.message : String(error);
}
