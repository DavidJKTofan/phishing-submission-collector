import assert from 'node:assert/strict';
import { afterEach, it as test } from 'vitest';

import { lookupAbuseContacts } from '../src/abuse-contacts';
import { extractAbuseContact, isValidAbuseEmail } from '../src/rdap';
import type { JsonValue } from '../src/rdap';

const originalFetch = globalThis.fetch;

afterEach(() => {
	globalThis.fetch = originalFetch;
});

type FetchCall = { url: string };

function mockFetch(handler: (url: string) => Response): FetchCall[] {
	const calls: FetchCall[] = [];
	globalThis.fetch = (async (input: RequestInfo | URL) => {
		const url = typeof input === 'string' ? input : input instanceof URL ? input.toString() : (input as Request).url;
		calls.push({ url });
		return handler(url);
	}) as typeof fetch;
	return calls;
}

function jsonResponse(body: unknown, init: ResponseInit = {}): Response {
	return new Response(JSON.stringify(body), { status: 200, headers: { 'Content-Type': 'application/json' }, ...init });
}

function dnsAnswer(answers: Array<{ type: number; data: string }>): Response {
	return jsonResponse({ Status: 0, Answer: answers });
}

function rdapWithAbuse(email: string, name?: string): JsonValue {
	const vcard: JsonValue[] = [['version', {}, 'text', '4.0']];
	if (name) vcard.push(['fn', {}, 'text', name]);
	vcard.push(['email', {}, 'text', email]);
	return {
		objectClassName: 'domain',
		entities: [
			{
				roles: ['registrar'],
				entities: [{ roles: ['abuse'], vcardArray: ['vcard', vcard] }],
			},
		],
	};
}

test('isValidAbuseEmail accepts well-formed addresses and rejects malformed ones', () => {
	assert.equal(isValidAbuseEmail('abuse@registrar-corp.com'), true);
	assert.equal(isValidAbuseEmail('abuse@host.co.uk'), true);
	assert.equal(isValidAbuseEmail('not-an-email'), false);
	assert.equal(isValidAbuseEmail('abuse@nodot'), false);
	assert.equal(isValidAbuseEmail('two@@at.com'), false);
	assert.equal(isValidAbuseEmail(''), false);
	assert.equal(isValidAbuseEmail(undefined), false);
	assert.equal(isValidAbuseEmail('spaces in@email.com'), false);
});

test('extractAbuseContact finds the nested abuse entity email and name', () => {
	const contact = extractAbuseContact(rdapWithAbuse('Abuse@Registrar-Corp.com', 'Abuse Department'));
	assert.deepEqual(contact, { email: 'abuse@registrar-corp.com', name: 'Abuse Department' });
});

test('extractAbuseContact skips entities whose email is malformed', () => {
	const contact = extractAbuseContact(rdapWithAbuse('not-an-email'));
	assert.equal(contact, undefined);
});

test('extractAbuseContact returns undefined when no abuse role exists', () => {
	const fixture: JsonValue = { entities: [{ roles: ['registrant'], vcardArray: ['vcard', [['email', {}, 'text', 'admin@host.com']]] }] };
	const contact = extractAbuseContact(fixture);
	assert.equal(contact, undefined);
});

test('lookupAbuseContacts resolves both registrar and host abuse contacts', async () => {
	mockFetch((url) => {
		if (url.startsWith('https://rdap.org/domain/')) return jsonResponse(rdapWithAbuse('abuse@registrar-corp.com', 'Registrar Abuse'));
		if (url.includes('cloudflare-dns.com') && url.includes('type=A')) return dnsAnswer([{ type: 1, data: '203.0.113.10' }]);
		if (url.includes('cloudflare-dns.com')) return jsonResponse({ Status: 0 });
		if (url === 'https://rdap.org/ip/203.0.113.10') return jsonResponse(rdapWithAbuse('abuse@hoster.net', 'Network Abuse'));
		throw new Error(`unexpected fetch ${url}`);
	});

	const contacts = await lookupAbuseContacts('login.bad.example');

	assert.deepEqual(contacts.registrar, { email: 'abuse@registrar-corp.com', name: 'Registrar Abuse' });
	assert.deepEqual(contacts.host, { email: 'abuse@hoster.net', name: 'Network Abuse' });
});

test('lookupAbuseContacts returns an empty object when RDAP has no abuse contacts', async () => {
	mockFetch((url) => {
		if (url.startsWith('https://rdap.org/domain/')) return jsonResponse({ objectClassName: 'domain', entities: [] });
		if (url.includes('cloudflare-dns.com') && url.includes('type=A')) return dnsAnswer([{ type: 1, data: '203.0.113.10' }]);
		if (url.includes('cloudflare-dns.com')) return jsonResponse({ Status: 0 });
		if (url === 'https://rdap.org/ip/203.0.113.10') return jsonResponse({ entities: [] });
		throw new Error(`unexpected fetch ${url}`);
	});

	const contacts = await lookupAbuseContacts('login.bad.example');

	assert.deepEqual(contacts, {});
});

test('lookupAbuseContacts never throws when RDAP/DoH requests fail', async () => {
	mockFetch(() => new Response('upstream error', { status: 503 }));

	const contacts = await lookupAbuseContacts('login.bad.example');

	assert.deepEqual(contacts, {});
});
