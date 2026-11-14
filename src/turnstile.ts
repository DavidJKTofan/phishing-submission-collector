// Server-side Turnstile validation for /submit. Kept apart from the Worker
// entrypoint so the fail-closed rules below can be unit-tested with a stubbed
// fetch (see tests/turnstile.test.ts).
import { errorMessage, isRecord, isTimeoutOrAbortError, parseCsv } from './shared';

const SITEVERIFY_TIMEOUT_MS = 5_000;
// Pause before the single retry so a transient siteverify failure has a moment
// to clear (the docs recommend backoff). One retry keeps the worst case bounded
// at roughly 2 × SITEVERIFY_TIMEOUT_MS + this delay.
const SITEVERIFY_RETRY_DELAY_MS = 300;
export const TURNSTILE_TOKEN_MAX_LENGTH = 2_048;
// Must match the `action` passed to turnstile.render() in public/assets/scripts.js.
const TURNSTILE_ACTION = 'submit-report';

// Cloudflare's documented Turnstile testing secret keys
// (https://developers.cloudflare.com/turnstile/troubleshooting/testing/).
// siteverify answers them with a placeholder result — `success: true` for ANY
// token (the always-pass key), hostname "example.com", no `action`, and
// `metadata.result_with_testing_key: true` — so none of the binding checks
// below can be evaluated. Staging deploys the always-pass key so agents and
// browser checks can submit without solving a real challenge; production must
// never be configured with one. Because a testing secret accepts forged
// tokens, it is only honored together with TURNSTILE_ALLOW_TESTING_KEYS="true"
// (set in wrangler.jsonc for the staging environment only) — a testing secret
// on its own fails closed rather than silently disabling bot protection.
const TURNSTILE_TESTING_SECRET_KEYS: ReadonlySet<string> = new Set([
	'1x0000000000000000000000000000000AA', // always passes
	'2x0000000000000000000000000000000AA', // always fails
	'3x0000000000000000000000000000000AA', // token already spent
]);

export type TurnstileEnv = {
	TURNSTILE_SECRET_KEY?: string;
	TURNSTILE_EXPECTED_HOSTNAMES?: string;
	TURNSTILE_ALLOW_TESTING_KEYS?: string;
};

type TurnstileSiteverifyResponse = {
	success: boolean;
	'error-codes'?: string[];
	challenge_ts?: string;
	hostname?: string;
	action?: string;
	cdata?: string;
	metadata?: unknown;
};

// Discriminated union so the success and failure shapes can't be mixed up: a
// passing result carries the verified hostname/action (both absent on the
// testing-key path, which is flagged by `testingKey`), a failing one carries a
// server-side reason. The `error` string is for logs only — it is never sent to
// the client, which always receives a generic message so a probing attacker
// learns nothing about why verification failed.
export type TurnstileValidation =
	| { success: true; testingKey: boolean; hostname?: string; action?: string; challengeTs?: string }
	| { success: false; error: string; errorCodes?: string[] };

export function isTurnstileTestingSecret(secretKey: string | undefined): boolean {
	return secretKey !== undefined && TURNSTILE_TESTING_SECRET_KEYS.has(secretKey);
}

export async function validateTurnstile(token: string, ip: string | null, env: TurnstileEnv): Promise<TurnstileValidation> {
	if (!token || token.length > TURNSTILE_TOKEN_MAX_LENGTH) {
		return { success: false, error: 'Invalid token format' };
	}

	if (!env.TURNSTILE_SECRET_KEY) {
		console.error('Turnstile validation failed: missing TURNSTILE_SECRET_KEY');
		return { success: false, error: 'Server Turnstile configuration missing' };
	}

	const expectedHostnames = parseCsv(env.TURNSTILE_EXPECTED_HOSTNAMES);
	if (expectedHostnames.length === 0) {
		console.error('Turnstile validation failed: TURNSTILE_EXPECTED_HOSTNAMES is not configured');
		return { success: false, error: 'Expected hostname configuration missing' };
	}

	// Refuse a testing secret unless the deployment explicitly opts in, before
	// spending a siteverify call on it. This is the guard that keeps an
	// accidentally deployed testing secret from accepting every token.
	const testingKey = isTurnstileTestingSecret(env.TURNSTILE_SECRET_KEY);
	if (testingKey && env.TURNSTILE_ALLOW_TESTING_KEYS !== 'true') {
		console.error('Turnstile validation failed: a Turnstile testing secret is configured but TURNSTILE_ALLOW_TESTING_KEYS is not "true"');
		return { success: false, error: 'Testing secret not allowed in this environment' };
	}

	// One idempotency_key shared across attempts lets a retried request after a
	// transient failure revalidate the single-use token (Turnstile server-side
	// validation docs: idempotency keys for retry operation).
	const idempotencyKey = crypto.randomUUID();
	let attempt = await requestSiteverify(env.TURNSTILE_SECRET_KEY, token, ip, idempotencyKey);
	if (!attempt.outcome && attempt.retryable) {
		await scheduler.wait(SITEVERIFY_RETRY_DELAY_MS);
		attempt = await requestSiteverify(env.TURNSTILE_SECRET_KEY, token, ip, idempotencyKey);
	}
	if (!attempt.outcome) {
		return attempt.errorCodes ? { success: false, error: attempt.error, errorCodes: attempt.errorCodes } : { success: false, error: attempt.error };
	}

	const outcome = attempt.outcome;

	// Fail closed first: if Cloudflare did not pass the token (expired, already
	// redeemed, forged, wrong secret, …) reject before running the cross-checks
	// below, which only carry meaning for a token Cloudflare actually accepted.
	if (!outcome.success) {
		return { success: false, error: 'token rejected', errorCodes: outcome['error-codes'] ?? [] };
	}

	if (testingKey) {
		// Placeholder result: no action, hostname "example.com". Log loudly so a
		// testing-key deployment is always visible in the Worker logs.
		console.log(
			JSON.stringify({
				event: 'turnstile_verified',
				testingKey: true,
				resultWithTestingKey: isRecord(outcome.metadata) && outcome.metadata.result_with_testing_key === true,
				hostname: outcome.hostname,
				challengeTs: outcome.challenge_ts,
				tokenAgeMs: tokenAgeMs(outcome.challenge_ts),
				timestamp: new Date().toISOString(),
			})
		);
		return { success: true, testingKey: true, hostname: outcome.hostname, action: outcome.action, challengeTs: outcome.challenge_ts };
	}

	// Bind the accepted token to this form. A token is otherwise replayable
	// against any endpoint sharing the sitekey, so require the action it was
	// minted for and a hostname we explicitly trust.
	if (outcome.action !== TURNSTILE_ACTION) {
		console.error('Turnstile action mismatch:', { got: outcome.action, expected: TURNSTILE_ACTION });
		return { success: false, error: 'action mismatch' };
	}

	if (!outcome.hostname || !expectedHostnames.includes(outcome.hostname)) {
		console.error('Turnstile hostname mismatch:', { got: outcome.hostname, expected: expectedHostnames });
		return { success: false, error: 'hostname mismatch' };
	}

	// Reaching here means the token passed every check, so this event names a
	// genuine verification. Record what was verified for audit; failures are
	// logged at the call site.
	console.log(
		JSON.stringify({
			event: 'turnstile_verified',
			testingKey: false,
			hostname: outcome.hostname,
			action: outcome.action,
			challengeTs: outcome.challenge_ts,
			// Siteverify already rejects tokens older than 300 s; the age is
			// recorded so slow form completions show up in the logs.
			tokenAgeMs: tokenAgeMs(outcome.challenge_ts),
			timestamp: new Date().toISOString(),
		})
	);

	return { success: true, testingKey: false, hostname: outcome.hostname, action: outcome.action, challengeTs: outcome.challenge_ts };
}

type SiteverifyAttempt =
	| { outcome: TurnstileSiteverifyResponse; error?: undefined }
	| { outcome?: undefined; error: string; errorCodes?: string[]; retryable: boolean };

async function requestSiteverify(secretKey: string, token: string, ip: string | null, idempotencyKey: string): Promise<SiteverifyAttempt> {
	try {
		const turnstileFormData = new FormData();
		turnstileFormData.append('secret', secretKey);
		turnstileFormData.append('response', token);
		if (ip) turnstileFormData.append('remoteip', ip);
		turnstileFormData.append('idempotency_key', idempotencyKey);

		const response = await fetch('https://challenges.cloudflare.com/turnstile/v0/siteverify', {
			method: 'POST',
			body: turnstileFormData,
			signal: AbortSignal.timeout(SITEVERIFY_TIMEOUT_MS),
		});

		if (!response.ok) {
			console.error('Turnstile siteverify HTTP error:', response.status);
			return { error: `siteverify HTTP ${response.status}`, retryable: response.status >= 500 };
		}

		const outcome: unknown = await response.json();
		if (!isTurnstileSiteverifyResponse(outcome)) {
			console.error('Turnstile siteverify returned a malformed response');
			return { error: 'Malformed siteverify response', retryable: false };
		}
		// Siteverify reports its own transient failures in-band (HTTP 200,
		// success:false, error-codes ["internal-error"]); the docs say to retry
		// rather than treat that as a rejected token.
		if (!outcome.success && outcome['error-codes']?.includes('internal-error')) {
			console.error('Turnstile siteverify internal-error');
			return { error: 'siteverify internal-error', errorCodes: outcome['error-codes'], retryable: true };
		}
		return { outcome };
	} catch (error) {
		const reason = isTimeoutOrAbortError(error) ? `timeout after ${SITEVERIFY_TIMEOUT_MS}ms` : errorMessage(error);
		console.error('Turnstile verification error:', reason);
		return { error: reason, retryable: true };
	}
}

function tokenAgeMs(challengeTs: string | undefined): number | undefined {
	if (!challengeTs) return undefined;
	const issuedAt = Date.parse(challengeTs);
	return Number.isNaN(issuedAt) ? undefined : Date.now() - issuedAt;
}

function isTurnstileSiteverifyResponse(value: unknown): value is TurnstileSiteverifyResponse {
	if (!isRecord(value) || typeof value.success !== 'boolean') return false;
	const errorCodes = value['error-codes'];
	if (errorCodes !== undefined && (!Array.isArray(errorCodes) || !errorCodes.every((code) => typeof code === 'string'))) return false;
	return ['challenge_ts', 'hostname', 'action', 'cdata'].every((key) => value[key] === undefined || typeof value[key] === 'string');
}
