// Integration tests for the Worker fetch handler, running in workerd via
// @cloudflare/vitest-pool-workers (SELF dispatches to the real Worker with
// the bindings from wrangler.jsonc). These cover routing, CORS, and input
// validation paths that fail before any external service or D1 query.
import { SELF, env } from 'cloudflare:test';
import { expect, it } from 'vitest';

const ALLOWED_ORIGIN = 'https://report.automatic-demo.com';

it('returns 405 for non-POST /submit', async () => {
	const response = await SELF.fetch('https://example.com/submit');
	expect(response.status).toBe(405);
});

it('requires a JSON content type on /submit', async () => {
	const response = await SELF.fetch('https://example.com/submit', { method: 'POST', body: 'name=x' });
	expect(response.status).toBe(400);
	const body = (await response.json()) as { error?: string };
	expect(body.error).toMatch(/Content-Type/);
});

it('rejects invalid JSON bodies on /submit', async () => {
	const response = await SELF.fetch('https://example.com/submit', {
		method: 'POST',
		headers: { 'Content-Type': 'application/json' },
		body: '{not json',
	});
	expect(response.status).toBe(400);
	const body = (await response.json()) as { code?: string };
	expect(body.code).toBe('INVALID_JSON');
});

it('validates submission fields before any external call', async () => {
	const response = await SELF.fetch('https://example.com/submit', {
		method: 'POST',
		headers: { 'Content-Type': 'application/json' },
		body: JSON.stringify({ name: 'x' }),
	});
	expect(response.status).toBe(400);
	const body = (await response.json()) as { code?: string };
	expect(body.code).toBe('INVALID_NAME');
});

it('rejects preflight requests from disallowed origins', async () => {
	const response = await SELF.fetch('https://example.com/submit', {
		method: 'OPTIONS',
		headers: { Origin: 'https://evil.example' },
	});
	expect(response.status).toBe(403);
});

it('allows preflight requests from the configured origin', async () => {
	const response = await SELF.fetch('https://example.com/submit', {
		method: 'OPTIONS',
		headers: { Origin: ALLOWED_ORIGIN },
	});
	expect(response.status).toBe(204);
	expect(response.headers.get('Access-Control-Allow-Origin')).toBe(ALLOWED_ORIGIN);
	expect(response.headers.get('Vary')).toBe('Origin');
});

it('rejects /submit POSTs from disallowed origins', async () => {
	const response = await SELF.fetch('https://example.com/submit', {
		method: 'POST',
		headers: { 'Content-Type': 'application/json', Origin: 'https://evil.example' },
		body: '{}',
	});
	expect(response.status).toBe(403);
	const body = (await response.json()) as { code?: string };
	expect(body.code).toBe('ORIGIN_NOT_ALLOWED');
});

it('rejects malformed report IDs without touching the database', async () => {
	const response = await SELF.fetch('https://example.com/api/report/not-a-uuid');
	expect(response.status).toBe(400);
	const body = (await response.json()) as { code?: string };
	expect(body.code).toBe('INVALID_REPORT_ID');
});

it('returns a stored report with its full public projection (guards REPORT_COLUMNS vs schema)', async () => {
	const id = '27028e66-f23b-4235-a980-19726a30fbca';
	await env.DB.prepare(
		`INSERT INTO reports_v2 (id, name, category, source, url, normalized_hostname, approval_status, cloudflare_list_status)
		 VALUES (?, 'Test Reporter', 'Phishing', 'Email', 'https://login.bad.example/', 'login.bad.example', 'approved', 'added')`
	)
		.bind(id)
		.run();

	const response = await SELF.fetch(`https://example.com/api/report/${id}`, { headers: { Origin: ALLOWED_ORIGIN } });
	expect(response.status).toBe(200);
	const body = (await response.json()) as { id?: string; approval_status?: string; cloudflare_list_status?: string; provider_reports?: unknown[] };
	expect(body.id).toBe(id);
	expect(body.approval_status).toBe('approved');
	expect(body.cloudflare_list_status).toBe('added');
	expect(Array.isArray(body.provider_reports)).toBe(true);
});

it('returns 405 for non-GET report reads', async () => {
	const response = await SELF.fetch('https://example.com/api/report/60e1a458-4ad0-44c4-a4be-d211bb321d7a', { method: 'POST' });
	expect(response.status).toBe(405);
});

it('rejects unsigned Discord interactions', async () => {
	const response = await SELF.fetch('https://example.com/discord/interactions', { method: 'POST', body: '{}' });
	expect(response.status).toBe(401);
});

it('sets security headers on API responses', async () => {
	const response = await SELF.fetch('https://example.com/api/report/not-a-uuid');
	expect(response.headers.get('X-Content-Type-Options')).toBe('nosniff');
	expect(response.headers.get('X-Frame-Options')).toBe('DENY');
});
