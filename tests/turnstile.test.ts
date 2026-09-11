import assert from 'node:assert/strict';
import { afterEach, it as test } from 'vitest';

import { isTurnstileTestingSecret, validateTurnstile } from '../src/turnstile';
import type { TurnstileEnv } from '../src/turnstile';

const originalFetch = globalThis.fetch;

afterEach(() => {
	globalThis.fetch = originalFetch;
});

const REAL_SECRET = '0x4AAAAAAA-not-a-testing-secret';
const TESTING_SECRET_PASS = '1x0000000000000000000000000000000AA';
const TESTING_SECRET_FAIL = '2x0000000000000000000000000000000AA';
const EXPECTED_HOSTNAME = 'report.automatic-demo.com';

// What siteverify actually returns for a testing secret (observed 2026-09;
// the docs' example response is stale): success for any token, a placeholder
// hostname, no action, and a metadata flag naming the testing key.
const TESTING_KEY_RESULT = {
	success: true,
	challenge_ts: '2026-09-11T07:17:12.105Z',
	hostname: 'example.com',
	'error-codes': [],
	metadata: { result_with_testing_key: true },
};

function makeEnv(overrides: Partial<TurnstileEnv> = {}): TurnstileEnv {
	return { TURNSTILE_SECRET_KEY: REAL_SECRET, TURNSTILE_EXPECTED_HOSTNAMES: EXPECTED_HOSTNAME, ...overrides };
}

test('accepts a real token bound to the expected action and hostname', async () => {
	const siteverify = mockSiteverify({ success: true, hostname: EXPECTED_HOSTNAME, action: 'submit-report', challenge_ts: 'ts' });

	const result = await validateTurnstile('real-token', '203.0.113.1', makeEnv());

	assert.equal(siteverify.calls, 1);
	assert.deepEqual(result, { success: true, testingKey: false, hostname: EXPECTED_HOSTNAME, action: 'submit-report', challengeTs: 'ts' });
});

test('rejects a placeholder (testing-key) result when a real secret is configured', async () => {
	// A real secret never yields this shape, but if it somehow did the action
	// binding must still fail closed — the placeholder carries no action.
	mockSiteverify(TESTING_KEY_RESULT);

	const result = await validateTurnstile('XXXX.DUMMY.TOKEN.XXXX', null, makeEnv());

	assert.equal(result.success, false);
	assert.equal(!result.success && result.error, 'action mismatch');
});

test('refuses a testing secret without TURNSTILE_ALLOW_TESTING_KEYS, before calling siteverify', async () => {
	const siteverify = mockSiteverify(TESTING_KEY_RESULT);

	const result = await validateTurnstile('XXXX.DUMMY.TOKEN.XXXX', null, makeEnv({ TURNSTILE_SECRET_KEY: TESTING_SECRET_PASS }));

	assert.equal(siteverify.calls, 0, 'must fail closed without a network call');
	assert.equal(result.success, false);
	assert.equal(!result.success && result.error, 'Testing secret not allowed in this environment');
});

test('does not treat TURNSTILE_ALLOW_TESTING_KEYS as truthy unless it is exactly "true"', async () => {
	const siteverify = mockSiteverify(TESTING_KEY_RESULT);

	const result = await validateTurnstile('XXXX.DUMMY.TOKEN.XXXX', null, makeEnv({ TURNSTILE_SECRET_KEY: TESTING_SECRET_PASS, TURNSTILE_ALLOW_TESTING_KEYS: 'yes' }));

	assert.equal(siteverify.calls, 0);
	assert.equal(result.success, false);
});

test('accepts the placeholder result when a testing secret is explicitly allowed (staging)', async () => {
	const siteverify = mockSiteverify(TESTING_KEY_RESULT);

	const result = await validateTurnstile('XXXX.DUMMY.TOKEN.XXXX', null, makeEnv({ TURNSTILE_SECRET_KEY: TESTING_SECRET_PASS, TURNSTILE_ALLOW_TESTING_KEYS: 'true' }));

	assert.equal(siteverify.calls, 1);
	assert.deepEqual(result, { success: true, testingKey: true, hostname: 'example.com', action: undefined, challengeTs: TESTING_KEY_RESULT.challenge_ts });
});

test('a testing secret still fails closed when siteverify rejects the token', async () => {
	mockSiteverify({ success: false, 'error-codes': ['invalid-input-response'] });

	const result = await validateTurnstile('anything', null, makeEnv({ TURNSTILE_SECRET_KEY: TESTING_SECRET_FAIL, TURNSTILE_ALLOW_TESTING_KEYS: 'true' }));

	assert.equal(result.success, false);
	assert.deepEqual(!result.success && result.errorCodes, ['invalid-input-response']);
});

test('TURNSTILE_ALLOW_TESTING_KEYS does not relax validation for a real secret', async () => {
	mockSiteverify({ success: true, hostname: 'evil.example', action: 'submit-report' });

	const result = await validateTurnstile('real-token', null, makeEnv({ TURNSTILE_ALLOW_TESTING_KEYS: 'true' }));

	assert.equal(result.success, false);
	assert.equal(!result.success && result.error, 'hostname mismatch');
});

test('recognizes only the documented testing secrets', () => {
	assert.equal(isTurnstileTestingSecret(TESTING_SECRET_PASS), true);
	assert.equal(isTurnstileTestingSecret(TESTING_SECRET_FAIL), true);
	assert.equal(isTurnstileTestingSecret('3x0000000000000000000000000000000AA'), true);
	assert.equal(isTurnstileTestingSecret(REAL_SECRET), false);
	assert.equal(isTurnstileTestingSecret(undefined), false);
});

// Stubs the siteverify endpoint; `calls` counts requests made to it.
function mockSiteverify(body: unknown): { calls: number } {
	const stub = { calls: 0 };
	globalThis.fetch = (async (input: RequestInfo | URL) => {
		assert.equal(String(input), 'https://challenges.cloudflare.com/turnstile/v0/siteverify');
		stub.calls += 1;
		return new Response(JSON.stringify(body), { status: 200, headers: { 'Content-Type': 'application/json' } });
	}) as typeof fetch;
	return stub;
}
