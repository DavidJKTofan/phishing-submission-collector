import type { PhishingHostnameWorkflowParams } from './approval';
import {
	domainCandidates,
	normalizeDnsName,
	queryDns,
	readJsonBody,
	resolveHostnameIps,
	toJsonValue,
} from './rdap.js';
import type { JsonValue } from './rdap.js';
import { isRecord, requireConfig } from './shared.js';

const CLOUDFLARE_API_BASE = 'https://api.cloudflare.com/client/v4';
const CLOUDFLARE_RDAP_DOMAIN_BASE = 'https://rdap.cloudflare.com/rdap/v1/domain';
const MICROSOFT_MSRC_ABUSE_ENDPOINT = 'https://api.msrc.microsoft.com/report/v3.0/Abuse/report';
const NETCRAFT_REPORT_URLS_ENDPOINT = 'https://report.netcraft.com/api/v3/report/urls';
const RDAP_IP_BASE = 'https://rdap.org/ip';
const MAX_PROVIDER_RESPONSE_CHARS = 12_000;

export const PROVIDERS = ['netcraft', 'cloudflare_abuse', 'microsoft_msrc'] as const;

export type ProviderName = (typeof PROVIDERS)[number];
export type ProviderReportStatus = 'not_started' | 'skipped' | 'submitted' | 'failed';
export type { JsonValue } from './rdap.js';

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
	const data = await readJsonBody(response);
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
	const data = await readJsonBody(response);
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
	const data = await readJsonBody(response);
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

async function findMicrosoftOwnedIp(ips: string[]): Promise<MicrosoftIpMatch | null> {
	for (const ip of ips) {
		const response = await fetch(`${RDAP_IP_BASE}/${encodeURIComponent(ip)}`, { headers: { Accept: 'application/rdap+json, application/json' } });
		if (!response.ok) continue;
		const data = await readJsonBody(response);
		if (containsMicrosoftOwnership(data)) return { ip, rdap: data };
	}
	return null;
}

async function fetchCloudflareDomainRdap(domain: string): Promise<JsonValue> {
	const response = await fetch(`${CLOUDFLARE_RDAP_DOMAIN_BASE}/${encodeURIComponent(domain)}`, {
		headers: { Accept: 'application/rdap+json, application/json' },
	});
	const data = await readJsonBody(response);
	if (!response.ok) return { http_status: response.status, error: response.statusText || `HTTP ${response.status}`, response: data };
	return data;
}

function isCloudflareNameserver(value: string): boolean {
	return value.endsWith('.ns.cloudflare.com');
}

const MICROSOFT_OWNERSHIP_REGEX = /\b(microsoft|msft|azure)\b/i;

// Match only RDAP ownership fields (network name/handle and entity
// names/handles/vCard organizations). Substring-matching the whole document
// could false-positive on remarks or links that merely mention these terms,
// which would file an MSRC report against a non-Microsoft IP.
function containsMicrosoftOwnership(value: JsonValue): boolean {
	return collectRdapOwnershipStrings(value).some((item) => MICROSOFT_OWNERSHIP_REGEX.test(item));
}

function collectRdapOwnershipStrings(value: JsonValue): string[] {
	if (!isRecord(value)) return [];
	const strings: string[] = [];
	for (const key of ['name', 'handle', 'org']) {
		const item = value[key];
		if (typeof item === 'string') strings.push(item);
	}
	if (Array.isArray(value.entities)) {
		for (const entity of value.entities) strings.push(...collectRdapEntityStrings(entity));
	}
	return strings;
}

function collectRdapEntityStrings(entity: unknown): string[] {
	if (!isRecord(entity)) return [];
	const strings: string[] = [];
	if (typeof entity.handle === 'string') strings.push(entity.handle);
	strings.push(...vcardNameValues(entity.vcardArray));
	if (Array.isArray(entity.entities)) {
		for (const nested of entity.entities) strings.push(...collectRdapEntityStrings(nested));
	}
	return strings;
}

// vcardArray shape: ["vcard", [["fn", {}, "text", "Microsoft Corporation"], ...]]
function vcardNameValues(vcardArray: unknown): string[] {
	if (!Array.isArray(vcardArray) || !Array.isArray(vcardArray[1])) return [];
	const names: string[] = [];
	for (const entry of vcardArray[1]) {
		if (Array.isArray(entry) && (entry[0] === 'fn' || entry[0] === 'org') && typeof entry[3] === 'string') names.push(entry[3]);
	}
	return names;
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

// Cap a provider result before it is returned from a Workflow step. Step return
// values are persisted by the Workflows runtime (1 MiB limit per non-stream
// step), so we bound the largest field (raw upstream/RDAP/DNS payloads) while
// preserving the status, reference, and eligibility fields used downstream.
export function capProviderResult(result: ProviderReportResult): ProviderReportResult {
	if (result.responseJson === undefined) return result;
	const serialized = JSON.stringify(result.responseJson);
	if (serialized.length <= MAX_PROVIDER_RESPONSE_CHARS) return result;
	return {
		...result,
		responseJson: { truncated: true, original_chars: serialized.length, preview: serialized.slice(0, MAX_PROVIDER_RESPONSE_CHARS) },
	};
}

