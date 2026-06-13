// DNS-over-HTTPS and RDAP primitives shared by two callers:
//   - provider-reporting.ts: post-approval eligibility checks (Cloudflare
//     nameservers, Microsoft-owned IPs).
//   - abuse-contacts.ts: submission-time discovery of registrar/host abuse
//     emails surfaced to the reporter.
// Centralizing these keeps the DoH endpoint, RDAP parsing, and JSON coercion
// identical across both flows.
import { isRecord } from './shared.js';

const CLOUDFLARE_DOH_ENDPOINT = 'https://cloudflare-dns.com/dns-query';

export type JsonValue = string | number | boolean | null | JsonValue[] | { [key: string]: JsonValue };

export type DnsAnswer = {
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

export type ResolvedIps = {
	ips: string[];
	cnames: string[];
};

export type AbuseContact = {
	email: string;
	name?: string;
};

export function normalizeDnsName(value: string): string {
	return value.trim().toLowerCase().replace(/\.+$/, '');
}

// Progressively shorter parent domains, e.g. a.b.example -> [a.b.example,
// b.example]. Used to find the registrable domain that holds NS/RDAP records.
export function domainCandidates(hostname: string): string[] {
	const labels = hostname.split('.').filter(Boolean);
	const candidates: string[] = [];
	for (let index = 0; index <= labels.length - 2; index += 1) candidates.push(labels.slice(index).join('.'));
	return candidates;
}

export async function queryDns(name: string, type: string, signal?: AbortSignal): Promise<DnsAnswer[]> {
	const url = new URL(CLOUDFLARE_DOH_ENDPOINT);
	url.searchParams.set('name', name);
	url.searchParams.set('type', type);
	const response = await fetch(url.toString(), { headers: { Accept: 'application/dns-json' }, signal });
	if (!response.ok) throw new Error(`Cloudflare DoH ${type} ${name} HTTP ${response.status}`);
	const data = (await response.json()) as DnsJsonResponse;
	if (data.Status !== undefined && ![0, 3].includes(data.Status)) throw new Error(`Cloudflare DoH ${type} ${name} status ${data.Status}`);
	return data.Answer || [];
}

export async function resolveHostnameIps(hostname: string, signal?: AbortSignal): Promise<ResolvedIps> {
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
			queryDns(normalized, 'A', signal),
			queryDns(normalized, 'AAAA', signal),
			queryDns(normalized, 'CNAME', signal),
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

export function toJsonValue(value: unknown): JsonValue {
	if (value === null || typeof value === 'string' || typeof value === 'number' || typeof value === 'boolean') return value;
	if (Array.isArray(value)) return value.map(toJsonValue);
	if (isRecord(value)) {
		const output: { [key: string]: JsonValue } = {};
		for (const [key, item] of Object.entries(value)) output[key] = toJsonValue(item);
		return output;
	}
	return String(value);
}

export async function readJsonBody(response: Response): Promise<JsonValue> {
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

// RDAP vCard shape: ["vcard", [["fn", {}, "text", "Abuse Dept"], ["email", {}, "text", "abuse@host.com"], ...]].
// Returns the first value for the requested property (e.g. "email", "fn", "org").
export function vcardValue(vcardArray: unknown, key: string): string | undefined {
	if (!Array.isArray(vcardArray) || !Array.isArray(vcardArray[1])) return undefined;
	for (const entry of vcardArray[1]) {
		if (Array.isArray(entry) && entry[0] === key && typeof entry[3] === 'string' && entry[3]) return entry[3];
	}
	return undefined;
}

const ABUSE_EMAIL_REGEX = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

// Format-only validation for an abuse email before it is surfaced as a
// reporter-facing mailto. Rejects empty/oversized values and anything that is
// not a syntactically plausible single address.
export function isValidAbuseEmail(value: unknown): value is string {
	if (typeof value !== 'string') return false;
	const trimmed = value.trim();
	return trimmed.length >= 6 && trimmed.length <= 254 && ABUSE_EMAIL_REGEX.test(trimmed);
}

// Walks an RDAP object's nested `entities` arrays (abuse contacts are often
// nested under a registrar/network entity) and returns the first entity whose
// roles include "abuse" and whose vCard exposes a validly-formatted email.
export function extractAbuseContact(rdap: JsonValue): AbuseContact | undefined {
	for (const entity of walkEntities(rdap)) {
		const roles = entity.roles;
		if (!Array.isArray(roles) || !roles.includes('abuse')) continue;
		const email = vcardValue(entity.vcardArray, 'email');
		if (!isValidAbuseEmail(email)) continue;
		const name = vcardValue(entity.vcardArray, 'fn') || vcardValue(entity.vcardArray, 'org');
		return name ? { email: email.trim().toLowerCase(), name } : { email: email.trim().toLowerCase() };
	}
	return undefined;
}

function* walkEntities(value: JsonValue): Generator<Record<string, JsonValue>> {
	if (!isRecord(value)) return;
	const entities = value.entities;
	if (!Array.isArray(entities)) return;
	for (const entity of entities) {
		if (!isRecord(entity)) continue;
		yield entity;
		yield* walkEntities(entity);
	}
}
