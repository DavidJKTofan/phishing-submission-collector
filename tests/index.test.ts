// Integration tests for the Worker fetch handler, running in workerd via
// @cloudflare/vitest-plugin (`exports.default` is a loopback stub to the real
// Worker's default export with the bindings from wrangler.jsonc). These cover
// routing, CORS, and input validation paths that fail before any external
// service or D1 query.
import { env, exports } from 'cloudflare:workers';
import { expect, it } from 'vitest';

const SELF = exports.default;

const ALLOWED_ORIGIN = 'https://report.automatic-demo.com';

// A fully valid submission body (the test env has no usable TURNSTILE_SECRET_KEY,
// so a request that passes field validation always ends in INVALID_TURNSTILE).
function submit(overrides: Record<string, unknown>): Promise<Response> {
	return SELF.fetch('https://example.com/submit', {
		method: 'POST',
		headers: { 'Content-Type': 'application/json', Origin: ALLOWED_ORIGIN },
		body: JSON.stringify({
			name: 'Test Reporter',
			category: 'Phishing',
			source: 'Email',
			url: 'https://login.bad.example/',
			'cf-turnstile-response': 'not-a-real-turnstile-token',
			...overrides,
		}),
	});
}

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

it('fails closed on Turnstile without storing the report', async () => {
	// A fully valid body reaches validateTurnstile. The test env has no usable
	// TURNSTILE_SECRET_KEY (and a real one would reject this token), so the
	// Worker must answer with the generic error and never write to D1.
	const hostname = 'turnstile-fail-closed.bad.example';
	const response = await SELF.fetch('https://example.com/submit', {
		method: 'POST',
		headers: { 'Content-Type': 'application/json', Origin: ALLOWED_ORIGIN },
		body: JSON.stringify({
			name: 'Test Reporter',
			category: 'Phishing',
			source: 'Email',
			url: `https://${hostname}/login`,
			'cf-turnstile-response': 'not-a-real-turnstile-token',
		}),
	});
	expect(response.status).toBe(400);
	const body = (await response.json()) as { error?: string; code?: string };
	expect(body).toEqual({ error: 'Invalid security verification', code: 'INVALID_TURNSTILE' });

	const stored = await env.DB.prepare('SELECT COUNT(*) AS n FROM reports_v2 WHERE normalized_hostname = ?').bind(hostname).first<{ n: number }>();
	expect(stored?.n).toBe(0);
});

it('counts the name length in code points, matching the D1 CHECK constraint', async () => {
	// SQLite length() counts characters: "😀" is 1 character but 2 UTF-16 code
	// units, so a unit-based check would let it through to a failing INSERT.
	const response = await submit({ name: '😀' });
	expect(response.status).toBe(400);
	expect(((await response.json()) as { code?: string }).code).toBe('INVALID_NAME');
});

it('accepts a 100-character name and a 500-character description made of astral characters', async () => {
	// 100 code points but 200 UTF-16 units. Reaching the Turnstile fail-closed
	// path proves the length checks counted characters, not code units.
	const accepted = await submit({ name: '😀'.repeat(100), description: '😀'.repeat(500) });
	expect(((await accepted.json()) as { code?: string }).code).toBe('INVALID_TURNSTILE');

	const tooLong = await submit({ description: '😀'.repeat(501) });
	expect(((await tooLong.json()) as { code?: string }).code).toBe('INVALID_DESCRIPTION');
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
	await env.DB.batch([
		env.DB.prepare(
			`INSERT INTO reports_v2 (id, name, category, source, url, normalized_hostname, approval_status, cloudflare_list_status)
			 VALUES (?, 'Test Reporter', 'Phishing', 'Email', 'https://login.bad.example/', 'login.bad.example', 'approved', 'added')`
		).bind(id),
		env.DB.prepare(
			`INSERT INTO provider_reports (report_id, provider, status, eligibility_reason, reference_id, response_json)
			 VALUES (?, 'netcraft', 'submitted', 'always', 'netcraft-ref-1', '{"secret":"must not leak"}')`
		).bind(id),
	]);

	const response = await SELF.fetch(`https://example.com/api/report/${id}`, { headers: { Origin: ALLOWED_ORIGIN } });
	expect(response.status).toBe(200);
	const body = (await response.json()) as {
		id?: string;
		approval_status?: string;
		cloudflare_list_status?: string;
		provider_reports?: Array<Record<string, unknown>>;
	};
	expect(body.id).toBe(id);
	expect(body.approval_status).toBe('approved');
	expect(body.cloudflare_list_status).toBe('added');
	// Both reads go out in one batch; the provider projection must never
	// include the raw response_json payload.
	expect(body.provider_reports).toHaveLength(1);
	expect(body.provider_reports?.[0]).toMatchObject({ provider: 'netcraft', status: 'submitted', reference_id: 'netcraft-ref-1' });
	expect(body.provider_reports?.[0]).not.toHaveProperty('response_json');
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
	// Report state changes over time; nothing may cache an API response.
	expect(response.headers.get('Cache-Control')).toBe('no-store');
});
