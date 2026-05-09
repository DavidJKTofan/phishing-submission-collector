const SECURITY_HEADERS = {
	'X-Content-Type-Options': 'nosniff',
	'Referrer-Policy': 'strict-origin-when-cross-origin',
	'X-Frame-Options': 'DENY',
	'Permissions-Policy': 'geolocation=(), microphone=(), camera=()',
};

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

const ALLOWED_CATEGORIES = ['Phishing', 'Crypto Scam', 'Malware', 'Spam', 'Other'];
const ALLOWED_SOURCES = ['Email', 'SMS', 'Social Media', 'Website', 'Other'];

function buildCorsHeaders(request, env) {
	const origin = request.headers.get('Origin') || '';
	const allowedRaw = (env.ALLOWED_ORIGINS || '*').trim();
	const allowedList = allowedRaw === '*' ? ['*'] : allowedRaw.split(',').map((o) => o.trim()).filter(Boolean);

	let allowOrigin;
	if (allowedList.includes('*')) {
		allowOrigin = '*';
	} else if (origin && allowedList.includes(origin)) {
		allowOrigin = origin;
	} else {
		allowOrigin = allowedList[0] || 'null';
	}

	return {
		'Access-Control-Allow-Origin': allowOrigin,
		'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
		'Access-Control-Allow-Headers': 'Content-Type',
		'Access-Control-Max-Age': '86400',
		Vary: 'Origin',
	};
}

function jsonResponse(body, status, corsHeaders) {
	return new Response(JSON.stringify(body), {
		status,
		headers: {
			'Content-Type': 'application/json; charset=utf-8',
			...SECURITY_HEADERS,
			...corsHeaders,
		},
	});
}

async function serveAsset(request, env) {
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

export default {
	async fetch(request, env, ctx) {
		const url = new URL(request.url);
		const corsHeaders = buildCorsHeaders(request, env);

		if (request.method === 'OPTIONS') {
			return new Response(null, { status: 204, headers: { ...SECURITY_HEADERS, ...corsHeaders } });
		}

		if (url.pathname === '/submit') {
			if (request.method !== 'POST') return jsonResponse({ error: 'Method not allowed' }, 405, corsHeaders);

			const contentType = request.headers.get('Content-Type') || '';
			if (!contentType.toLowerCase().includes('application/json')) {
				return jsonResponse({ error: 'Content-Type must be application/json' }, 400, corsHeaders);
			}

			const declaredLen = Number(request.headers.get('Content-Length') || '0');
			if (Number.isFinite(declaredLen) && declaredLen > MAX_BODY_BYTES) {
				return jsonResponse({ error: 'Request body too large' }, 413, corsHeaders);
			}

			try {
				const submittedData = await request.json();

				const turnstileValid = await validateTurnstile(
					submittedData['cf-turnstile-response'],
					request.headers.get('CF-Connecting-IP'),
					env
				);

				if (!turnstileValid.success) {
					console.error('Turnstile validation failed:', JSON.stringify(turnstileValid));
					return jsonResponse({ error: 'Invalid security verification', code: 'INVALID_TURNSTILE' }, 400, corsHeaders);
				}

				const result = await handleSubmission(submittedData, env, ctx);
				return jsonResponse(result, 200, corsHeaders);
			} catch (error) {
				console.error('Error processing submission:', error);
				return jsonResponse(
					{ error: error.message || 'Internal server error', code: error.code || 'INTERNAL_ERROR' },
					error.status || 500,
					corsHeaders
				);
			}
		}

		if (url.pathname === '/random') {
			return new Response(crypto.randomUUID(), {
				status: 200,
				headers: { 'Content-Type': 'text/plain; charset=utf-8', ...SECURITY_HEADERS, ...corsHeaders },
			});
		}

		if (url.pathname.startsWith('/api/report/')) {
			if (request.method !== 'GET') return jsonResponse({ error: 'Method not allowed' }, 405, corsHeaders);

			try {
				const id = url.pathname.split('/').pop();
				const report = await getReportFromDB(env.DB, id);
				if (!report) return jsonResponse({ error: 'Report not found' }, 404, corsHeaders);
				return jsonResponse(report, 200, corsHeaders);
			} catch (error) {
				console.error('Error fetching report:', error);
				if (error.message === 'Invalid report ID format') {
					return jsonResponse({ error: 'Invalid Report ID format' }, 400, corsHeaders);
				}
				return jsonResponse({ error: 'Internal server error' }, 500, corsHeaders);
			}
		}

		return serveAsset(request, env);
	},
};

async function validateTurnstile(token, ip, env) {
	if (!token) {
		console.error('Turnstile validation failed: Missing token');
		return { success: false, error: 'Missing token' };
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

		const outcome = await turnstileResponse.json();

		if (outcome.success && env.TURNSTILE_EXPECTED_HOSTNAMES) {
			const expected = env.TURNSTILE_EXPECTED_HOSTNAMES.split(',').map((h) => h.trim()).filter(Boolean);
			if (expected.length > 0 && !expected.includes(outcome.hostname)) {
				console.error('Turnstile hostname mismatch:', { got: outcome.hostname, expected });
				return { success: false, error: 'hostname mismatch' };
			}
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
		};
	} catch (error) {
		const reason = error.name === 'AbortError' ? `timeout after ${SITEVERIFY_TIMEOUT_MS}ms` : error.message;
		console.error('Turnstile verification error:', reason);
		return { success: false, error: reason };
	} finally {
		clearTimeout(timeoutId);
	}
}

async function handleSubmission(formData, env, ctx) {
	validateFormData(formData);

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

	const result = { success: true, id, apiErrors: [] };

	const apiCalls = [
		{ name: 'URLScan', skip: formData.skip_urlscan, call: callUrlScanAPI, resultKey: 'urlscan_uuid' },
		{ name: 'VirusTotal', skip: formData.skip_virustotal, call: callVirusTotalAPI, resultKey: 'virustotal_scan_id' },
		{ name: 'IPQualityScore', skip: formData.skip_ipqualityscore, call: callIPQSAPI, resultKey: 'ipqs_scan' },
		{ name: 'Cloudflare', skip: formData.skip_cloudflare, call: callCloudflareAPI, resultKey: 'cloudflare_scan_uuid' },
	];

	const activeApiCalls = apiCalls.filter((api) => !api.skip);

	const apiPromises = activeApiCalls.map(async (api) => {
		const startTime = Date.now();
		try {
			const apiResult = await callApiWithTimeout((signal) => api.call(formData.url, env, signal), API_TIMEOUT_MS);
			const duration = Date.now() - startTime;
			console.log(JSON.stringify({ event: 'api_success', api: api.name, requestId, duration }));
			return { success: true, name: api.name, resultKey: api.resultKey, data: apiResult, duration };
		} catch (error) {
			const duration = Date.now() - startTime;
			console.error(JSON.stringify({ event: 'api_failure', api: api.name, requestId, duration, error: error.message }));
			return { success: false, name: api.name, error: error.message || 'Unknown error', duration };
		}
	});

	const apiResults = await Promise.allSettled(apiPromises);

	apiResults.forEach((promiseResult) => {
		if (promiseResult.status === 'fulfilled') {
			const apiResult = promiseResult.value;
			if (apiResult.success && apiResult.data) {
				result[apiResult.resultKey] = apiResult.data[apiResult.resultKey];
			} else if (!apiResult.success) {
				result.apiErrors.push({ api: apiResult.name, message: apiResult.error });
			}
		} else {
			console.error('API promise rejected:', promiseResult.reason);
		}
	});

	try {
		await saveReportToDB(env.DB, id, formData, result);
	} catch (dbError) {
		console.error('Database save error:', dbError);
		result.dbError = 'Failed to save to database';
	}

	console.log(
		JSON.stringify({
			event: 'submission_complete',
			reportId: id,
			requestId,
			successfulApis: Object.keys(result).filter((k) => !['success', 'id', 'apiErrors', 'dbError'].includes(k)).length,
			failedApis: result.apiErrors.length,
		})
	);

	return result;
}

function validateFormData(data) {
	const name = data.name?.trim();
	const category = data.category?.trim();
	const source = data.source?.trim();
	const url = data.url?.trim();
	const description = data.description?.trim();

	if (!name || name.length < 2 || name.length > 100) {
		throw { status: 400, message: 'Name must be between 2 and 100 characters', code: 'INVALID_NAME' };
	}
	if (!category || !ALLOWED_CATEGORIES.includes(category)) {
		throw { status: 400, message: 'Invalid category', code: 'INVALID_CATEGORY' };
	}
	if (!source || !ALLOWED_SOURCES.includes(source)) {
		throw { status: 400, message: 'Invalid source', code: 'INVALID_SOURCE' };
	}
	if (!url || url.length > MAX_URL_LENGTH) {
		throw { status: 400, message: 'Invalid URL', code: 'INVALID_URL' };
	}
	let parsedUrl;
	try {
		parsedUrl = new URL(url);
	} catch {
		throw { status: 400, message: 'Invalid URL format', code: 'INVALID_URL' };
	}
	if (!['http:', 'https:'].includes(parsedUrl.protocol)) {
		throw { status: 400, message: 'URL must use http:// or https://', code: 'INVALID_URL' };
	}
	if (description && description.length > 500) {
		throw { status: 400, message: 'Description must be 500 characters or less', code: 'INVALID_DESCRIPTION' };
	}
}

async function callApiWithTimeout(apiCall, timeoutMs) {
	const controller = new AbortController();
	const timeoutId = setTimeout(() => controller.abort(), timeoutMs);
	try {
		return await apiCall(controller.signal);
	} catch (error) {
		if (error.name === 'AbortError') throw new Error(`API timeout after ${timeoutMs}ms`);
		throw error;
	} finally {
		clearTimeout(timeoutId);
	}
}

async function callUrlScanAPI(submittedUrl, env, signal) {
	try {
		const response = await fetch('https://urlscan.io/api/v1/scan/', {
			method: 'POST',
			headers: { 'Content-Type': 'application/json', 'API-Key': env.URLSCAN_API_KEY },
			body: JSON.stringify({ url: submittedUrl, visibility: 'unlisted' }),
			signal,
		});
		if (!response.ok) {
			const errorData = await response.json().catch(() => ({}));
			throw new Error(errorData.message || errorData.description || `HTTP ${response.status}`);
		}
		const data = await response.json();
		if (!data.uuid) throw new Error('Missing UUID in response');
		return { urlscan_uuid: data.uuid };
	} catch (error) {
		throw new Error(`URLScan API: ${error.message}`);
	}
}

async function callVirusTotalAPI(submittedUrl, env, signal) {
	try {
		const response = await fetch('https://www.virustotal.com/api/v3/urls', {
			method: 'POST',
			headers: {
				accept: 'application/json',
				'content-type': 'application/x-www-form-urlencoded',
				'x-apikey': env.VIRUSTOTAL_API_KEY,
			},
			body: new URLSearchParams({ url: submittedUrl }),
			signal,
		});
		if (!response.ok) throw new Error(`HTTP ${response.status}`);
		const data = await response.json();
		if (!data.data?.id) throw new Error('Missing scan ID in response');
		const rawScanId = data.data.id;
		const cleanScanId = rawScanId.substring(2, rawScanId.lastIndexOf('-'));
		return { virustotal_scan_id: cleanScanId };
	} catch (error) {
		throw new Error(`VirusTotal API: ${error.message}`);
	}
}

async function callIPQSAPI(submittedUrl, env, signal) {
	try {
		const apiUrl = `https://ipqualityscore.com/api/json/url/${env.IPQS_API_KEY}/${encodeURIComponent(submittedUrl)}`;
		const response = await fetch(apiUrl, { signal });
		if (!response.ok) throw new Error(`HTTP ${response.status}`);
		const data = await response.json();
		if (!data.success) throw new Error(data.message || 'API returned success: false');
		return { ipqs_scan: data };
	} catch (error) {
		throw new Error(`IPQualityScore API: ${error.message}`);
	}
}

async function callCloudflareAPI(submittedUrl, env, signal) {
	try {
		const response = await fetch(
			`https://api.cloudflare.com/client/v4/accounts/${env.CLOUDFLARE_ACCOUNT_ID}/urlscanner/scan`,
			{
				method: 'POST',
				headers: {
					'Content-Type': 'application/json',
					'X-Auth-Key': env.CLOUDFLARE_API_KEY,
					'X-Auth-Email': env.CLOUDFLARE_USER_EMAIL,
				},
				body: JSON.stringify({ url: submittedUrl, visibility: 'unlisted' }),
				signal,
			}
		);
		if (!response.ok) {
			const errorData = await response.json().catch(() => ({}));
			throw new Error(errorData.errors?.[0]?.message || `HTTP ${response.status}`);
		}
		const data = await response.json();
		if (!data.result?.uuid) throw new Error('Missing UUID in response');
		return { cloudflare_scan_uuid: data.result.uuid };
	} catch (error) {
		throw new Error(`Cloudflare API: ${error.message}`);
	}
}

async function saveReportToDB(db, id, formData, result) {
	const startTime = Date.now();
	try {
		const apiErrorsJson = result.apiErrors.length > 0 ? JSON.stringify(result.apiErrors) : null;
		await db
			.prepare(
				`INSERT INTO reports_v2 (
					id, name, category, source, url, description,
					urlscan_uuid, virustotal_scan_id, ipqs_scan, cloudflare_scan_uuid,
					api_errors, submission_success
				) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
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
				result.apiErrors.length === 0
			)
			.run();
		console.log(JSON.stringify({ event: 'db_save', reportId: id, duration: Date.now() - startTime }));
	} catch (error) {
		console.error(JSON.stringify({ event: 'db_save_error', reportId: id, duration: Date.now() - startTime, error: error.message }));
		throw new Error('Database save failed');
	}
}

const REPORT_COLUMNS =
	'id, name, category, source, url, description, urlscan_uuid, virustotal_scan_id, cloudflare_scan_uuid, api_errors, submission_success, timestamp';

async function getReportFromDB(db, id) {
	const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
	if (!uuidRegex.test(id)) throw new Error('Invalid report ID format');

	try {
		const stmt = db.prepare(`SELECT ${REPORT_COLUMNS} FROM reports_v2 WHERE id = ?`);
		return await stmt.bind(id).first();
	} catch (error) {
		console.error('Database read error:', error);
		throw new Error('Database read failed');
	}
}
