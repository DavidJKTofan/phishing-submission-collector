import { WorkflowEntrypoint } from 'cloudflare:workers';
import type { WorkflowEvent, WorkflowStep } from 'cloudflare:workers';

import {
	APPROVAL_EVENT_TYPE,
	addHostnameToCloudflareOneList,
	formatDiscordActor,
	handleDiscordInteraction,
	sendDiscordApprovalMessage,
} from './approval';
import type { ApprovalEventPayload, ApprovalStatus, CloudflareListStatus, PhishingHostnameWorkflowParams } from './approval';
import { HostnameNormalizationError, buildScanUrl, normalizeReportedHostname } from './hostname';

const SECURITY_HEADERS = {
	'X-Content-Type-Options': 'nosniff',
	'Referrer-Policy': 'strict-origin-when-cross-origin',
	'X-Frame-Options': 'DENY',
	'Permissions-Policy': 'geolocation=(), microphone=(), camera=()',
} as const;

const HTML_CSP =
	"default-src 'self'; " +
	"script-src 'self' https://challenges.cloudflare.com; " +
	"style-src 'self' 'unsafe-inline'; " +
	"img-src 'self' data: https:; " +
	"font-src 'self' data:; " +
	"connect-src 'self' https://challenges.cloudflare.com; " +
	"frame-src https://challenges.cloudflare.com; " +
	"frame-ancestors 'none'; " +
	"base-uri 'self'; " +
	"form-action 'self'";

const MAX_BODY_BYTES = 50_000;
const SITEVERIFY_TIMEOUT_MS = 5_000;
const API_TIMEOUT_MS = 10_000;
const MAX_URL_LENGTH = 2_048;
const TURNSTILE_TOKEN_MAX_LENGTH = 2_048;
const TURNSTILE_ACTION = 'submit-report';
const CLOUDFLARE_API_BASE = 'https://api.cloudflare.com/client/v4';
const APPROVAL_TIMEOUT = '7 days';

const ALLOWED_CATEGORIES = ['Phishing', 'Crypto Scam', 'Malware', 'Spam', 'Other'] as const;
const ALLOWED_SOURCES = ['Email', 'SMS', 'Social Media', 'Website', 'Other'] as const;

type Category = (typeof ALLOWED_CATEGORIES)[number];
type Source = (typeof ALLOWED_SOURCES)[number];

type ApiError = {
	api: string;
	message: string;
};

type SubmissionData = {
	name: string;
	category: Category;
	source: Source;
	url: string;
	scanUrl: string;
	normalizedHostname: string;
	description: string;
	skip_urlscan: boolean;
	skip_virustotal: boolean;
	skip_ipqualityscore: boolean;
	skip_cloudflare: boolean;
	turnstileToken: string;
};

type SubmissionResult = {
	success: boolean;
	id: string;
	apiErrors: ApiError[];
	normalized_hostname: string;
	approval_status: ApprovalStatus;
	workflow_instance_id?: string;
	urlscan_uuid?: string;
	virustotal_scan_id?: string;
	ipqs_scan?: unknown;
	cloudflare_scan_uuid?: string;
};

type ApiResultKey = 'urlscan_uuid' | 'virustotal_scan_id' | 'ipqs_scan' | 'cloudflare_scan_uuid';
type ApiResponseData = Partial<Pick<SubmissionResult, ApiResultKey>>;

type TurnstileSiteverifyResponse = {
	success: boolean;
	'error-codes'?: string[];
	challenge_ts?: string;
	hostname?: string;
	action?: string;
	cdata?: string;
};

type TurnstileValidation = {
	success: boolean;
	error?: string;
	errorCodes?: string[];
	timestamp?: string;
	hostname?: string;
	action?: string;
};

class HttpError extends Error {
	readonly status: number;
	readonly code: string;

	constructor(status: number, message: string, code = 'BAD_REQUEST') {
		super(message);
		this.name = 'HttpError';
		this.status = status;
		this.code = code;
	}
}

export class PhishingHostnameWorkflow extends WorkflowEntrypoint<Env, PhishingHostnameWorkflowParams> {
	async run(event: WorkflowEvent<PhishingHostnameWorkflowParams>, step: WorkflowStep): Promise<unknown> {
		const report = event.payload;

		await step.do('send Discord approval request', { retries: { limit: 3, delay: '10 seconds', backoff: 'exponential' } }, async () => {
			return sendDiscordApprovalMessage(this.env, report, event.instanceId);
		});

		let approvalEvent: { payload: Readonly<ApprovalEventPayload> };
		try {
			approvalEvent = await step.waitForEvent<ApprovalEventPayload>('wait for hostname approval', {
				type: APPROVAL_EVENT_TYPE,
				timeout: APPROVAL_TIMEOUT,
			});
		} catch (error) {
			await step.do('mark approval expired', async () => {
				await updateApprovalDecision(this.env.DB, report.reportId, {
					approvalStatus: 'expired',
					cloudflareListStatus: 'not_started',
					error: errorMessage(error),
				});
			});
			return { status: 'expired', reportId: report.reportId };
		}

		const approval = approvalEvent.payload as ApprovalEventPayload;
		const approvalStatus: ApprovalStatus = approval.approved ? 'approved' : 'denied';

		await step.do('record approval decision', async () => {
			await updateApprovalDecision(this.env.DB, report.reportId, {
				approvalStatus,
				actor: formatDiscordActor(approval),
				cloudflareListStatus: 'not_started',
			});
		});

		if (!approval.approved) {
			return { status: 'denied', reportId: report.reportId };
		}

		let listResult: { status: CloudflareListStatus; error: string | null };
		try {
			listResult = await step.do(
				'add hostname to Cloudflare One list',
				{ retries: { limit: 3, delay: '30 seconds', backoff: 'exponential' } },
				async () => addHostnameToCloudflareOneList(this.env, report.reportId, report.normalizedHostname)
			);
		} catch (error) {
			const message = errorMessage(error);
			await step.do('record Cloudflare One list failure', async () => {
				await updateCloudflareListResult(this.env.DB, report.reportId, 'failed', message);
			});
			return { status: 'failed', reportId: report.reportId, hostname: report.normalizedHostname, error: message };
		}

		await step.do('record Cloudflare One list result', async () => {
			await updateCloudflareListResult(this.env.DB, report.reportId, listResult.status, listResult.error);
		});

		return { status: listResult.status, reportId: report.reportId, hostname: report.normalizedHostname };
	}
}

export default {
	async fetch(request, env): Promise<Response> {
		const url = new URL(request.url);
		const cors = buildCorsHeaders(request, env);

		if (request.method === 'OPTIONS') {
			if (!cors.allowed) {
				return new Response(null, { status: 403, headers: { ...SECURITY_HEADERS, ...cors.headers } });
			}
			return new Response(null, { status: 204, headers: { ...SECURITY_HEADERS, ...cors.headers } });
		}

		if (url.pathname === '/submit') {
			if (request.method !== 'POST') return jsonResponse({ error: 'Method not allowed' }, 405, cors.headers);
			if (!cors.allowed) return jsonResponse({ error: 'Origin not allowed', code: 'ORIGIN_NOT_ALLOWED' }, 403, cors.headers);

			const contentType = request.headers.get('Content-Type') || '';
			if (!contentType.toLowerCase().includes('application/json')) {
				return jsonResponse({ error: 'Content-Type must be application/json' }, 400, cors.headers);
			}

			try {
				const submittedData = await readJsonBody(request, MAX_BODY_BYTES);
				const formData = validateFormData(submittedData);

				const turnstileValid = await validateTurnstile(formData.turnstileToken, request.headers.get('CF-Connecting-IP'), env);
				if (!turnstileValid.success) {
					console.error('Turnstile validation failed:', JSON.stringify(redactTurnstileFailure(turnstileValid)));
					return jsonResponse({ error: 'Invalid security verification', code: 'INVALID_TURNSTILE' }, 400, cors.headers);
				}

				const result = await handleSubmission(formData, env);
				return jsonResponse(result, 200, cors.headers);
			} catch (error) {
				return handleErrorResponse(error, cors.headers);
			}
		}

		if (url.pathname === '/discord/interactions') {
			if (request.method !== 'POST') return jsonResponse({ error: 'Method not allowed' }, 405);

			try {
				return await handleDiscordInteraction(request, env);
			} catch (error) {
				return handleErrorResponse(error, {});
			}
		}

		if (url.pathname === '/random') {
			return new Response(crypto.randomUUID(), {
				status: 200,
				headers: { 'Content-Type': 'text/plain; charset=utf-8', ...SECURITY_HEADERS, ...cors.headers },
			});
		}

		if (url.pathname.startsWith('/api/report/')) {
			if (request.method !== 'GET') return jsonResponse({ error: 'Method not allowed' }, 405, cors.headers);
			if (!cors.allowed) return jsonResponse({ error: 'Origin not allowed', code: 'ORIGIN_NOT_ALLOWED' }, 403, cors.headers);

			try {
				const id = url.pathname.split('/').pop();
				const report = await getReportFromDB(env.DB, id);
				if (!report) return jsonResponse({ error: 'Report not found' }, 404, cors.headers);
				return jsonResponse(report, 200, cors.headers);
			} catch (error) {
				return handleErrorResponse(error, cors.headers);
			}
		}

		return serveAsset(request, env);
	},
} satisfies ExportedHandler<Env>;

function buildCorsHeaders(request: Request, env: Env): { allowed: boolean; headers: Record<string, string> } {
	const origin = request.headers.get('Origin');
	const requestOrigin = new URL(request.url).origin;
	const configuredOrigins = parseCsv(env.ALLOWED_ORIGINS);
	const allowedList = configuredOrigins.includes('*') ? configuredOrigins : [...new Set([...configuredOrigins, requestOrigin])];
	const headers: Record<string, string> = { Vary: 'Origin' };

	if (!origin) return { allowed: true, headers };

	if (allowedList.includes('*')) {
		return {
			allowed: true,
			headers: {
				...headers,
				'Access-Control-Allow-Origin': '*',
				'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
				'Access-Control-Allow-Headers': 'Content-Type',
				'Access-Control-Max-Age': '86400',
			},
		};
	}

	if (!allowedList.includes(origin)) return { allowed: false, headers };

	return {
		allowed: true,
		headers: {
			...headers,
			'Access-Control-Allow-Origin': origin,
			'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
			'Access-Control-Allow-Headers': 'Content-Type',
			'Access-Control-Max-Age': '86400',
		},
	};
}

function jsonResponse(body: unknown, status: number, corsHeaders: Record<string, string> = {}): Response {
	return new Response(JSON.stringify(body), {
		status,
		headers: {
			'Content-Type': 'application/json; charset=utf-8',
			...SECURITY_HEADERS,
			...corsHeaders,
		},
	});
}

function handleErrorResponse(error: unknown, corsHeaders: Record<string, string>): Response {
	if (error instanceof HttpError) {
		return jsonResponse({ error: error.message, code: error.code }, error.status, corsHeaders);
	}

	const message = error instanceof Error ? error.message : String(error);
	console.error('Unhandled request error:', message);
	return jsonResponse({ error: 'Internal server error', code: 'INTERNAL_ERROR' }, 500, corsHeaders);
}

async function serveAsset(request: Request, env: Env): Promise<Response> {
	const assetResponse = await env.ASSETS.fetch(request);
	const headers = new Headers(assetResponse.headers);
	for (const [k, v] of Object.entries(SECURITY_HEADERS)) headers.set(k, v);
	const contentType = headers.get('Content-Type') || '';
	if (contentType.includes('text/html')) headers.set('Content-Security-Policy', HTML_CSP);
	return new Response(assetResponse.body, {
		status: assetResponse.status,
		statusText: assetResponse.statusText,
		headers,
	});
}

async function readJsonBody(request: Request, maxBytes: number): Promise<unknown> {
	const text = await readTextBody(request, maxBytes);
	if (!text.trim()) throw new HttpError(400, 'Request body required', 'INVALID_JSON');

	try {
		return JSON.parse(text) as unknown;
	} catch {
		throw new HttpError(400, 'Request body must be valid JSON', 'INVALID_JSON');
	}
}

async function readTextBody(request: Request, maxBytes: number): Promise<string> {
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

async function validateTurnstile(token: string, ip: string | null, env: Env): Promise<TurnstileValidation> {
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

	const controller = new AbortController();
	const timeoutId = setTimeout(() => controller.abort(), SITEVERIFY_TIMEOUT_MS);

	try {
		const turnstileFormData = new FormData();
		turnstileFormData.append('secret', env.TURNSTILE_SECRET_KEY);
		turnstileFormData.append('response', token);
		if (ip) turnstileFormData.append('remoteip', ip);
		turnstileFormData.append('idempotency_key', crypto.randomUUID());

		const turnstileResponse = await fetch('https://challenges.cloudflare.com/turnstile/v0/siteverify', {
			method: 'POST',
			body: turnstileFormData,
			signal: controller.signal,
		});

		if (!turnstileResponse.ok) {
			console.error('Turnstile siteverify HTTP error:', turnstileResponse.status);
			return { success: false, error: `siteverify HTTP ${turnstileResponse.status}` };
		}

		const outcome = (await turnstileResponse.json()) as TurnstileSiteverifyResponse;

		if (outcome.success && outcome.action !== TURNSTILE_ACTION) {
			console.error('Turnstile action mismatch:', { got: outcome.action, expected: TURNSTILE_ACTION });
			return { success: false, error: 'action mismatch' };
		}

		if (outcome.success && (!outcome.hostname || !expectedHostnames.includes(outcome.hostname))) {
			console.error('Turnstile hostname mismatch:', { got: outcome.hostname, expected: expectedHostnames });
			return { success: false, error: 'hostname mismatch' };
		}

		console.log(
			JSON.stringify({
				event: 'turnstile_verified',
				success: outcome.success,
				timestamp: new Date().toISOString(),
				errorCodes: outcome['error-codes'] || [],
			})
		);

		return {
			success: outcome.success,
			errorCodes: outcome['error-codes'] || [],
			timestamp: outcome.challenge_ts,
			hostname: outcome.hostname,
			action: outcome.action,
		};
	} catch (error) {
		const reason = error instanceof Error && error.name === 'AbortError' ? `timeout after ${SITEVERIFY_TIMEOUT_MS}ms` : errorMessage(error);
		console.error('Turnstile verification error:', reason);
		return { success: false, error: reason };
	} finally {
		clearTimeout(timeoutId);
	}
}

function redactTurnstileFailure(result: TurnstileValidation): TurnstileValidation {
	return {
		success: result.success,
		error: result.error,
		errorCodes: result.errorCodes,
		timestamp: result.timestamp,
		hostname: result.hostname,
		action: result.action,
	};
}

async function handleSubmission(formData: SubmissionData, env: Env): Promise<SubmissionResult> {
	const id = crypto.randomUUID();
	const requestId = crypto.randomUUID();

	console.log(
		JSON.stringify({
			event: 'submission_start',
			reportId: id,
			requestId,
			timestamp: new Date().toISOString(),
			category: formData.category,
			source: formData.source,
		})
	);

	const result: SubmissionResult = {
		success: true,
		id,
		apiErrors: [],
		normalized_hostname: formData.normalizedHostname,
		approval_status: 'pending',
	};

	const apiCalls: Array<{
		name: string;
		skip: boolean;
		call: (submittedUrl: string, env: Env, signal: AbortSignal) => Promise<ApiResponseData>;
		resultKey: ApiResultKey;
	}> = [
		{ name: 'URLScan', skip: formData.skip_urlscan, call: callUrlScanAPI, resultKey: 'urlscan_uuid' },
		{ name: 'VirusTotal', skip: formData.skip_virustotal, call: callVirusTotalAPI, resultKey: 'virustotal_scan_id' },
		{ name: 'IPQualityScore', skip: formData.skip_ipqualityscore, call: callIPQSAPI, resultKey: 'ipqs_scan' },
		{ name: 'Cloudflare', skip: formData.skip_cloudflare, call: callCloudflareAPI, resultKey: 'cloudflare_scan_uuid' },
	];

	const apiResults = await Promise.all(
		apiCalls
			.filter((api) => !api.skip)
			.map(async (api) => {
				const startTime = Date.now();
				try {
					const data = await callApiWithTimeout((signal) => api.call(formData.scanUrl, env, signal), API_TIMEOUT_MS);
					const duration = Date.now() - startTime;
					console.log(JSON.stringify({ event: 'api_success', api: api.name, requestId, duration }));
					return { success: true as const, name: api.name, resultKey: api.resultKey, data, duration };
				} catch (error) {
					const duration = Date.now() - startTime;
					const message = errorMessage(error);
					console.error(JSON.stringify({ event: 'api_failure', api: api.name, requestId, duration, error: message }));
					return { success: false as const, name: api.name, error: message, duration };
				}
			})
	);

	for (const apiResult of apiResults) {
		if (apiResult.success) {
			const value = apiResult.data[apiResult.resultKey];
			assignApiResult(result, apiResult.resultKey, value);
		} else {
			result.apiErrors.push({ api: apiResult.name, message: apiResult.error });
		}
	}

	await saveReportToDB(env.DB, id, formData, result);

	try {
		const instance = await env.PHISHING_HOSTNAME_WORKFLOW.create({
			id,
			params: {
				reportId: id,
				name: formData.name,
				category: formData.category,
				source: formData.source,
				submittedUrl: formData.url,
				normalizedHostname: formData.normalizedHostname,
				description: formData.description,
			},
			retention: {
				successRetention: '30 days',
				errorRetention: '30 days',
			},
		});
		result.workflow_instance_id = instance.id;
		await updateWorkflowInstanceId(env.DB, id, instance.id);
	} catch (error) {
		const message = errorMessage(error);
		result.approval_status = 'workflow_failed';
		result.apiErrors.push({ api: 'Workflow', message });
		await updateApprovalDecision(env.DB, id, {
			approvalStatus: 'workflow_failed',
			cloudflareListStatus: 'not_started',
			error: message,
		});
	}

	console.log(
		JSON.stringify({
			event: 'submission_complete',
			reportId: id,
			requestId,
			successfulApis: Object.keys(result).filter((k) => !['success', 'id', 'apiErrors'].includes(k)).length,
			failedApis: result.apiErrors.length,
		})
	);

	return result;
}

function assignApiResult(result: SubmissionResult, key: ApiResultKey, value: unknown): void {
	if (value === undefined) return;

	switch (key) {
		case 'urlscan_uuid':
		case 'virustotal_scan_id':
		case 'cloudflare_scan_uuid':
			if (typeof value === 'string') result[key] = value;
			return;
		case 'ipqs_scan':
			result.ipqs_scan = value;
			return;
	}
}

function validateFormData(data: unknown): SubmissionData {
	if (!isRecord(data)) throw new HttpError(400, 'Request body must be a JSON object', 'INVALID_JSON');

	const name = stringField(data.name).trim();
	const category = stringField(data.category).trim();
	const source = stringField(data.source).trim();
	const url = stringField(data.url).trim();
	const description = stringField(data.description).trim();
	const turnstileToken = stringField(data['cf-turnstile-response']).trim();

	if (!name || name.length < 2 || name.length > 100) {
		throw new HttpError(400, 'Name must be between 2 and 100 characters', 'INVALID_NAME');
	}
	if (!isAllowedCategory(category)) {
		throw new HttpError(400, 'Invalid category', 'INVALID_CATEGORY');
	}
	if (!isAllowedSource(source)) {
		throw new HttpError(400, 'Invalid source', 'INVALID_SOURCE');
	}
	if (!url || url.length > MAX_URL_LENGTH) {
		throw new HttpError(400, 'Invalid URL or hostname', 'INVALID_URL');
	}

	let normalizedHostname: string;
	try {
		normalizedHostname = normalizeReportedHostname(url);
	} catch (error) {
		const message = error instanceof HostnameNormalizationError ? error.message : 'Invalid URL or hostname format';
		throw new HttpError(400, message, 'INVALID_URL');
	}

	const scanUrl = buildScanUrl(url, normalizedHostname);

	if (description.length > 500) {
		throw new HttpError(400, 'Description must be 500 characters or less', 'INVALID_DESCRIPTION');
	}
	if (!turnstileToken || turnstileToken.length > TURNSTILE_TOKEN_MAX_LENGTH) {
		throw new HttpError(400, 'Invalid security verification', 'INVALID_TURNSTILE');
	}

	return {
		name,
		category,
		source,
		url,
		scanUrl,
		normalizedHostname,
		description,
		skip_urlscan: data.skip_urlscan === true,
		skip_virustotal: data.skip_virustotal === true,
		skip_ipqualityscore: data.skip_ipqualityscore === true,
		skip_cloudflare: data.skip_cloudflare === true,
		turnstileToken,
	};
}

async function callApiWithTimeout<T>(apiCall: (signal: AbortSignal) => Promise<T>, timeoutMs: number): Promise<T> {
	const controller = new AbortController();
	const timeoutId = setTimeout(() => controller.abort(), timeoutMs);
	try {
		return await apiCall(controller.signal);
	} catch (error) {
		if (error instanceof Error && error.name === 'AbortError') throw new Error(`API timeout after ${timeoutMs}ms`);
		throw error;
	} finally {
		clearTimeout(timeoutId);
	}
}

async function callUrlScanAPI(submittedUrl: string, env: Env, signal: AbortSignal): Promise<ApiResponseData> {
	try {
		const response = await fetch('https://urlscan.io/api/v1/scan/', {
			method: 'POST',
			headers: { 'Content-Type': 'application/json', 'API-Key': requireSecret(env.URLSCAN_API_KEY, 'URLSCAN_API_KEY') },
			body: JSON.stringify({ url: submittedUrl, visibility: 'unlisted' }),
			signal,
		});
		if (!response.ok) {
			const errorData = (await response.json().catch(() => ({}))) as { message?: string; description?: string };
			throw new Error(errorData.message || errorData.description || `HTTP ${response.status}`);
		}
		const data = (await response.json()) as { uuid?: string };
		if (!data.uuid) throw new Error('Missing UUID in response');
		return { urlscan_uuid: data.uuid };
	} catch (error) {
		throw new Error(`URLScan API: ${errorMessage(error)}`);
	}
}

async function callVirusTotalAPI(submittedUrl: string, env: Env, signal: AbortSignal): Promise<ApiResponseData> {
	try {
		const response = await fetch('https://www.virustotal.com/api/v3/urls', {
			method: 'POST',
			headers: {
				accept: 'application/json',
				'content-type': 'application/x-www-form-urlencoded',
				'x-apikey': requireSecret(env.VIRUSTOTAL_API_KEY, 'VIRUSTOTAL_API_KEY'),
			},
			body: new URLSearchParams({ url: submittedUrl }),
			signal,
		});
		if (!response.ok) throw new Error(`HTTP ${response.status}`);
		const data = (await response.json()) as { data?: { id?: string } };
		if (!data.data?.id) throw new Error('Missing scan ID in response');
		const rawScanId = data.data.id;
		const cleanScanId = rawScanId.substring(2, rawScanId.lastIndexOf('-'));
		return { virustotal_scan_id: cleanScanId };
	} catch (error) {
		throw new Error(`VirusTotal API: ${errorMessage(error)}`);
	}
}

async function callIPQSAPI(submittedUrl: string, env: Env, signal: AbortSignal): Promise<ApiResponseData> {
	try {
		const apiUrl = `https://ipqualityscore.com/api/json/url/${requireSecret(env.IPQS_API_KEY, 'IPQS_API_KEY')}/${encodeURIComponent(
			submittedUrl
		)}`;
		const response = await fetch(apiUrl, { signal });
		if (!response.ok) throw new Error(`HTTP ${response.status}`);
		const data = (await response.json()) as { success?: boolean; message?: string };
		if (!data.success) throw new Error(data.message || 'API returned success: false');
		return { ipqs_scan: data };
	} catch (error) {
		throw new Error(`IPQualityScore API: ${errorMessage(error)}`);
	}
}

async function callCloudflareAPI(submittedUrl: string, env: Env, signal: AbortSignal): Promise<ApiResponseData> {
	try {
		const response = await fetch(
			`${CLOUDFLARE_API_BASE}/accounts/${requireSecret(env.CLOUDFLARE_ACCOUNT_ID, 'CLOUDFLARE_ACCOUNT_ID')}/urlscanner/scan`,
			{
				method: 'POST',
				headers: {
					'Content-Type': 'application/json',
					Authorization: `Bearer ${requireSecret(env.CLOUDFLARE_API_TOKEN, 'CLOUDFLARE_API_TOKEN')}`,
				},
				body: JSON.stringify({ url: submittedUrl, visibility: 'unlisted' }),
				signal,
			}
		);
		if (!response.ok) {
			const errorData = (await response.json().catch(() => ({}))) as { errors?: Array<{ message?: string }> };
			throw new Error(errorData.errors?.[0]?.message || `HTTP ${response.status}`);
		}
		const data = (await response.json()) as { result?: { uuid?: string } };
		if (!data.result?.uuid) throw new Error('Missing UUID in response');
		return { cloudflare_scan_uuid: data.result.uuid };
	} catch (error) {
		throw new Error(`Cloudflare API: ${errorMessage(error)}`);
	}
}

async function saveReportToDB(db: D1Database, id: string, formData: SubmissionData, result: SubmissionResult): Promise<void> {
	const startTime = Date.now();
	try {
		const apiErrorsJson = result.apiErrors.length > 0 ? JSON.stringify(result.apiErrors) : null;
		await runD1WriteWithRetry(() =>
			db
				.prepare(
					`INSERT INTO reports_v2 (
						id, name, category, source, url, description,
						urlscan_uuid, virustotal_scan_id, ipqs_scan, cloudflare_scan_uuid,
						api_errors, submission_success, normalized_hostname, approval_status,
						cloudflare_list_status
					) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
				)
				.bind(
					id,
					formData.name,
					formData.category,
					formData.source,
					formData.url,
					formData.description || null,
					result.urlscan_uuid || null,
					result.virustotal_scan_id || null,
					result.ipqs_scan ? JSON.stringify(result.ipqs_scan) : null,
					result.cloudflare_scan_uuid || null,
					apiErrorsJson,
					result.apiErrors.length === 0,
					formData.normalizedHostname,
					result.approval_status,
					'not_started'
				)
				.run()
		);
		console.log(JSON.stringify({ event: 'db_save', reportId: id, duration: Date.now() - startTime }));
	} catch (error) {
		console.error(JSON.stringify({ event: 'db_save_error', reportId: id, duration: Date.now() - startTime, error: errorMessage(error) }));
		throw new HttpError(503, 'Report could not be saved. Please try again.', 'DB_SAVE_FAILED');
	}
}

async function updateWorkflowInstanceId(db: D1Database, reportId: string, workflowInstanceId: string): Promise<void> {
	await runD1WriteWithRetry(() =>
		db
			.prepare('UPDATE reports_v2 SET workflow_instance_id = ?, last_updated = CURRENT_TIMESTAMP WHERE id = ?')
			.bind(workflowInstanceId, reportId)
			.run()
	);
}

async function updateApprovalDecision(
	db: D1Database,
	reportId: string,
	decision: {
		approvalStatus: ApprovalStatus;
		actor?: string;
		cloudflareListStatus?: CloudflareListStatus;
		error?: string;
	}
): Promise<void> {
	await runD1WriteWithRetry(() =>
		db
			.prepare(
				`UPDATE reports_v2
				 SET approval_status = ?,
				     approval_actor = COALESCE(?, approval_actor),
				     approval_decided_at = CASE WHEN ? IN ('approved', 'denied', 'expired') THEN CURRENT_TIMESTAMP ELSE approval_decided_at END,
				     cloudflare_list_status = COALESCE(?, cloudflare_list_status),
				     cloudflare_list_error = ?,
				     last_updated = CURRENT_TIMESTAMP
				 WHERE id = ?`
			)
			.bind(
				decision.approvalStatus,
				decision.actor || null,
				decision.approvalStatus,
				decision.cloudflareListStatus || null,
				decision.error || null,
				reportId
			)
			.run()
	);
}

async function updateCloudflareListResult(
	db: D1Database,
	reportId: string,
	status: CloudflareListStatus,
	error: string | null = null
): Promise<void> {
	await runD1WriteWithRetry(() =>
		db
			.prepare(
				`UPDATE reports_v2
				 SET cloudflare_list_status = ?,
				     cloudflare_list_error = ?,
				     last_updated = CURRENT_TIMESTAMP
				 WHERE id = ?`
			)
			.bind(status, error, reportId)
			.run()
	);
}

async function runD1WriteWithRetry<T>(operation: () => Promise<T>, maxAttempts = 3): Promise<T> {
	let lastError: unknown;
	for (let attempt = 1; attempt <= maxAttempts; attempt += 1) {
		try {
			return await operation();
		} catch (error) {
			lastError = error;
			if (attempt >= maxAttempts || !isRetryableD1Error(error)) break;
			await delay(jitterDelayMs(attempt));
		}
	}
	throw lastError;
}

function isRetryableD1Error(error: unknown): boolean {
	const message = errorMessage(error);
	return (
		message.includes('Network connection lost') ||
		message.includes('storage caused object to be reset') ||
		message.includes('reset because its code was updated')
	);
}

function jitterDelayMs(attempt: number): number {
	const random = new Uint32Array(1);
	crypto.getRandomValues(random);
	const jitter = (random[0] ?? 0) / 0xffffffff;
	return Math.min(1_000, 100 * 2 ** (attempt - 1) + Math.floor(jitter * 100));
}

function delay(ms: number): Promise<void> {
	return new Promise((resolve) => setTimeout(resolve, ms));
}

const REPORT_COLUMNS =
	'id, name, category, source, url, description, urlscan_uuid, virustotal_scan_id, ipqs_scan, cloudflare_scan_uuid, api_errors, submission_success, timestamp, normalized_hostname, workflow_instance_id, approval_status, approval_actor, approval_decided_at, cloudflare_list_status, cloudflare_list_error';

async function getReportFromDB(db: D1Database, id: string | undefined): Promise<Record<string, unknown> | null> {
	const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
	if (!id || !uuidRegex.test(id)) throw new HttpError(400, 'Invalid Report ID format', 'INVALID_REPORT_ID');

	try {
		return await db.prepare(`SELECT ${REPORT_COLUMNS} FROM reports_v2 WHERE id = ?`).bind(id).first<Record<string, unknown>>();
	} catch (error) {
		console.error('Database read error:', errorMessage(error));
		throw new HttpError(500, 'Database read failed', 'DB_READ_FAILED');
	}
}

function parseCsv(value: string | undefined): string[] {
	return (value || '')
		.split(',')
		.map((item) => item.trim())
		.filter(Boolean);
}

function isRecord(value: unknown): value is Record<string, unknown> {
	return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function stringField(value: unknown): string {
	return typeof value === 'string' ? value : '';
}

function isAllowedCategory(value: string): value is Category {
	return (ALLOWED_CATEGORIES as readonly string[]).includes(value);
}

function isAllowedSource(value: string): value is Source {
	return (ALLOWED_SOURCES as readonly string[]).includes(value);
}

function requireSecret(value: string | undefined, name: string): string {
	if (!value) throw new Error(`Missing ${name}`);
	return value;
}

function errorMessage(error: unknown): string {
	return error instanceof Error ? error.message : String(error);
}
