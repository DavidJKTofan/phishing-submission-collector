// Submission-time discovery of registrar and hosting/network abuse contacts via
// RDAP. These are surfaced to the reporter on the success page as an optional
// "notify the provider directly" call-to-action — they are best-effort and must
// never block or fail the submission response.
import { extractAbuseContact, domainCandidates, readJsonBody, resolveHostnameIps } from './rdap.js';
import type { AbuseContact } from './rdap.js';

const RDAP_DOMAIN_BASE = 'https://rdap.org/domain';
const RDAP_IP_BASE = 'https://rdap.org/ip';
const LOOKUP_TIMEOUT_MS = 4_000;

export type AbuseContacts = {
	registrar?: AbuseContact;
	host?: AbuseContact;
};

// Looks up the registrar abuse contact (from domain RDAP) and the hosting/network
// abuse contact (from the resolved IP's RDAP) in parallel. Every branch is
// best-effort: any failure, timeout, or missing/invalid email yields no contact
// rather than throwing.
export async function lookupAbuseContacts(hostname: string): Promise<AbuseContacts> {
	const signal = AbortSignal.timeout(LOOKUP_TIMEOUT_MS);
	const [registrar, host] = await Promise.all([
		lookupRegistrarAbuse(hostname, signal).catch((error) => {
			logBranchFailure('registrar', hostname, error);
			return undefined;
		}),
		lookupHostAbuse(hostname, signal).catch((error) => {
			logBranchFailure('host', hostname, error);
			return undefined;
		}),
	]);

	const contacts: AbuseContacts = {};
	if (registrar) contacts.registrar = registrar;
	if (host) contacts.host = host;

	// One structured line per lookup so production behavior is observable via
	// `wrangler tail` (each branch is otherwise best-effort and silent).
	console.log(
		JSON.stringify({ event: 'abuse_contacts_lookup', hostname, registrar: registrar?.email ?? null, host: host?.email ?? null })
	);
	return contacts;
}

function logBranchFailure(branch: 'registrar' | 'host', hostname: string, error: unknown): void {
	console.error(
		JSON.stringify({
			event: 'abuse_contacts_branch_failed',
			branch,
			hostname,
			error: error instanceof Error ? error.message : String(error),
		})
	);
}

async function lookupRegistrarAbuse(hostname: string, signal: AbortSignal): Promise<AbuseContact | undefined> {
	// Walk progressively shorter parent domains so we query the registrable
	// domain (e.g. bad.example) rather than the full host (login.bad.example).
	for (const domain of domainCandidates(hostname)) {
		const rdap = await fetchRdap(`${RDAP_DOMAIN_BASE}/${encodeURIComponent(domain)}`, signal);
		if (!rdap) continue;
		const contact = extractAbuseContact(rdap);
		if (contact) return contact;
	}
	return undefined;
}

async function lookupHostAbuse(hostname: string, signal: AbortSignal): Promise<AbuseContact | undefined> {
	const resolved = await resolveHostnameIps(hostname, signal);
	for (const ip of resolved.ips) {
		const rdap = await fetchRdap(`${RDAP_IP_BASE}/${encodeURIComponent(ip)}`, signal);
		if (!rdap) continue;
		const contact = extractAbuseContact(rdap);
		if (contact) return contact;
	}
	return undefined;
}

async function fetchRdap(url: string, signal: AbortSignal): Promise<Awaited<ReturnType<typeof readJsonBody>> | undefined> {
	const response = await fetch(url, { headers: { Accept: 'application/rdap+json, application/json' }, signal });
	if (!response.ok) return undefined;
	return readJsonBody(response);
}
