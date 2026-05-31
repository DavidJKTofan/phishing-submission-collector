// Shared HTTP/Worker helpers used by the Worker entrypoint, the Discord
// approval flow, and provider reporting. Centralizing these avoids drift
// between request handlers (security headers, body-size limits, JSON
// responses, error shape) across modules.

export const SECURITY_HEADERS = {
	'X-Content-Type-Options': 'nosniff',
	'Referrer-Policy': 'strict-origin-when-cross-origin',
	'X-Frame-Options': 'DENY',
	'Permissions-Policy': 'geolocation=(), microphone=(), camera=(), payment=(), usb=(), browsing-topics=()',
	'Strict-Transport-Security': 'max-age=63072000; includeSubDomains',
} as const;

export const MAX_BODY_BYTES = 50_000;

export class HttpError extends Error {
	readonly status: number;
	readonly code: string;

	constructor(status: number, message: string, code = 'BAD_REQUEST') {
		super(message);
		this.name = 'HttpError';
		this.status = status;
		this.code = code;
	}
}

export function jsonResponse(body: unknown, status: number, extraHeaders: Record<string, string> = {}): Response {
	return new Response(JSON.stringify(body), {
		status,
		headers: {
			'Content-Type': 'application/json; charset=utf-8',
			...SECURITY_HEADERS,
			...extraHeaders,
		},
	});
}

export async function readTextBody(request: Request, maxBytes: number): Promise<string> {
	const contentLength = request.headers.get('Content-Length');
	if (contentLength) {
		const declaredLength = Number(contentLength);
		if (!Number.isFinite(declaredLength) || declaredLength < 0) {
			throw new HttpError(400, 'Invalid Content-Length', 'INVALID_CONTENT_LENGTH');
		}
		if (declaredLength > maxBytes) {
			throw new HttpError(413, 'Request body too large', 'BODY_TOO_LARGE');
		}
	}

	if (!request.body) throw new HttpError(400, 'Request body required', 'INVALID_JSON');

	const reader = request.body.getReader();
	const chunks: Uint8Array[] = [];
	let totalBytes = 0;

	try {
		while (true) {
			const { done, value } = await reader.read();
			if (done) break;
			if (!value) continue;
			totalBytes += value.byteLength;
			if (totalBytes > maxBytes) {
				throw new HttpError(413, 'Request body too large', 'BODY_TOO_LARGE');
			}
			chunks.push(value);
		}
	} finally {
		reader.releaseLock();
	}

	const bodyBytes = new Uint8Array(totalBytes);
	let offset = 0;
	for (const chunk of chunks) {
		bodyBytes.set(chunk, offset);
		offset += chunk.byteLength;
	}

	return new TextDecoder().decode(bodyBytes);
}

// Thrown when a required secret/config value is absent. Distinct from a generic
// Error so the Workflow can treat it as terminal (NonRetryableError) instead of
// burning retries on a gap that will never resolve mid-run.
export class MissingConfigError extends Error {
	constructor(name: string) {
		super(`Missing ${name}`);
		this.name = 'MissingConfigError';
	}
}

export function requireSecret(value: string | undefined, name: string): string {
	if (!value) throw new MissingConfigError(name);
	return value;
}

export function requireConfig(value: string | undefined, name: string): string {
	const trimmed = value?.trim();
	if (!trimmed) throw new MissingConfigError(name);
	return trimmed;
}

export function isRecord(value: unknown): value is Record<string, unknown> {
	return typeof value === 'object' && value !== null && !Array.isArray(value);
}

export function errorMessage(error: unknown): string {
	return error instanceof Error ? error.message : String(error);
}
