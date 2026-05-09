const JSON_HEADERS = { 'Content-Type': 'application/json; charset=utf-8' };
const SECURITY_HEADERS = {
	'Content-Security-Policy':
		"default-src 'self'; script-src 'self' 'unsafe-inline' https://challenges.cloudflare.com; style-src 'self' 'unsafe-inline'; img-src 'self' data: https://report.automatic-demo.com; frame-src https://challenges.cloudflare.com; connect-src 'self' https://challenges.cloudflare.com; object-src 'none'; base-uri 'self'; form-action 'self'",
	'Permissions-Policy': 'camera=(), microphone=(), geolocation=()',
	'Referrer-Policy': 'strict-origin-when-cross-origin',
	'X-Content-Type-Options': 'nosniff',
};
const TURNSTILE_EXPECTED_ACTION = 'submit-report';
const TURNSTILE_VERIFY_URL = 'https://challenges.cloudflare.com/turnstile/v0/siteverify';

export default {
	async fetch(request, env, ctx) {
		const url = new URL(request.url);

		if (request.method === 'OPTIONS') {
			return withSecurityHeaders(new Response(null, { status: 204, headers: { Allow: 'GET, POST, OPTIONS' } }));
		}

		switch (url.pathname) {
			case '/submit': {
				if (request.method !== 'POST') {
					return jsonResponse({ error: 'Method not allowed' }, 405, { Allow: 'POST' });
				}

				if (!isJsonRequest(request)) {
					return jsonResponse({ error: 'Content-Type must be application/json' }, 415);
				}

				try {
					const submittedData = await request.json();
					const turnstileValid = await validateTurnstile(
						submittedData['cf-turnstile-response'],
						request.headers.get('CF-Connecting-IP'),
						env
					);

					if (!turnstileValid.success) {
						console.error('Turnstile validation failed:', turnstileValid);
						return jsonResponse(
							{
								error: 'Invalid security verification',
								code: 'INVALID_TURNSTILE',
							},
							400
						);
					}

					console.log('Turnstile validation successful');
					const result = await handleSubmission(submittedData, env);
					return jsonResponse(result);
				} catch (error) {
					console.error('Error processing submission:', error);
					return jsonResponse(
						{
							error: error.status ? error.message : 'Internal server error',
							code: error.code || 'INTERNAL_ERROR',
						},
						error.status || 500
					);
				}
			}

			case '/random': {
				return textResponse(crypto.randomUUID());
			}

			case url.pathname.startsWith('/api/report/') ? url.pathname : '': {
				if (request.method !== 'GET') {
					return jsonResponse({ error: 'Method not allowed' }, 405, { Allow: 'GET' });
				}

				try {
					const id = url.pathname.split('/').pop();
					const report = await getReportFromDB(env.DB, id);

					if (!report) {
						return jsonResponse({ error: 'Report not found' }, 404);
					}

					return jsonResponse(report);
				} catch (error) {
					console.error('Error fetching report:', error);
					if (error.message === 'Invalid report ID format') {
						return jsonResponse({ error: 'Invalid Report ID format' }, 400);
					}
					return jsonResponse({ error: 'Internal server error' }, 500);
				}
			}

			default: {
				return withSecurityHeaders(await env.ASSETS.fetch(request));
			}
		}
	},
};

function withSecurityHeaders(response) {
	const headers = new Headers(response.headers);
	for (const [key, value] of Object.entries(SECURITY_HEADERS)) {
		headers.set(key, value);
	}
	return new Response(response.body, {
		status: response.status,
		statusText: response.statusText,
		headers,
	});
}

function jsonResponse(body, status = 200, headers = {}) {
	return withSecurityHeaders(
		new Response(JSON.stringify(body), {
			status,
			headers: { ...JSON_HEADERS, ...headers },
		})
	);
}

function textResponse(body, status = 200, headers = {}) {
	return withSecurityHeaders(
		new Response(body, {
			status,
			headers: { 'Content-Type': 'text/plain; charset=utf-8', ...headers },
		})
	);
}

function isJsonRequest(request) {
	const contentType = request.headers.get('Content-Type') || '';
	return contentType.toLowerCase().split(';')[0].trim() === 'application/json';
}

async function validateTurnstile(token, ip, env) {
	if (!token || typeof token !== 'string') {
		return { success: false, error: 'Missing token' };
	}

	if (token.length > 2048) {
		return { success: false, error: 'Invalid token format' };
	}

	if (!env.TURNSTILE_SECRET_KEY || !env.TURNSTILE_EXPECTED_HOSTNAME) {
		return { success: false, error: 'Missing Turnstile configuration' };
	}

	const idempotencyKey = crypto.randomUUID();
	const outcome = await verifyTurnstileWithRetry(token, ip, env.TURNSTILE_SECRET_KEY, idempotencyKey);

	console.log('Turnstile verification response:', {
		success: outcome.success,
		errorCodes: outcome['error-codes'] || [],
		action: outcome.action,
		hostname: outcome.hostname,
		timestamp: new Date().toISOString(),
	});

	if (!outcome.success) {
		return {
			success: false,
			errorCodes: outcome['error-codes'] || [],
		};
	}

	if (outcome.action !== TURNSTILE_EXPECTED_ACTION) {
		return { success: false, error: 'Action mismatch' };
	}

	if (outcome.hostname !== env.TURNSTILE_EXPECTED_HOSTNAME) {
		return { success: false, error: 'Hostname mismatch' };
	}

	return {
		success: true,
		action: outcome.action,
		hostname: outcome.hostname,
		timestamp: outcome.challenge_ts,
	};
}

async function verifyTurnstileWithRetry(token, ip, secret, idempotencyKey, maxRetries = 2) {
	let lastOutcome = { success: false, 'error-codes': ['internal-error'] };

	for (let attempt = 1; attempt <= maxRetries; attempt++) {
		const formData = new FormData();
		formData.append('secret', secret);
		formData.append('response', token);
		formData.append('idempotency_key', idempotencyKey);

		if (ip) {
			formData.append('remoteip', ip);
		}

		try {
			const response = await fetchWithTimeout(
				TURNSTILE_VERIFY_URL,
				{
					method: 'POST',
					body: formData,
				},
				5000
			);
			lastOutcome = await response.json();

			if (response.ok) {
				return lastOutcome;
			}
		} catch (error) {
			lastOutcome = { success: false, 'error-codes': ['internal-error'], error: error.message };
		}

		if (attempt < maxRetries) {
			await delay(200 * attempt);
		}
	}

	return lastOutcome;
}

async function handleSubmission(formData, env) {
	const validatedData = validateFormData(formData);
	const id = crypto.randomUUID();
	const requestId = crypto.randomUUID();

	console.log('Starting submission process:', {
		reportId: id,
		requestId,
		timestamp: new Date().toISOString(),
		category: validatedData.category,
		source: validatedData.source,
	});

	const result = {
		success: true,
		id,
		apiErrors: [],
	};

	const apiCalls = [
		{
			name: 'URLScan',
			skip: validatedData.skip_urlscan,
			call: (signal) => callUrlScanAPI(validatedData.url, env, signal),
			resultKey: 'urlscan_uuid',
			timeout: 10000,
		},
		{
			name: 'VirusTotal',
			skip: validatedData.skip_virustotal,
			call: (signal) => callVirusTotalAPI(validatedData.url, env, signal),
			resultKey: 'virustotal_scan_id',
			timeout: 10000,
		},
		{
			name: 'IPQualityScore',
			skip: validatedData.skip_ipqualityscore,
			call: (signal) => callIPQSAPI(validatedData.url, env, signal),
			resultKey: 'ipqs_scan',
			timeout: 10000,
		},
		{
			name: 'Cloudflare',
			skip: validatedData.skip_cloudflare,
			call: (signal) => callCloudflareAPI(validatedData.url, env, signal),
			resultKey: 'cloudflare_scan_uuid',
			timeout: 10000,
		},
	];

	const activeApiCalls = apiCalls.filter((api) => !api.skip);
	const apiPromises = activeApiCalls.map(async (api) => {
		const startTime = Date.now();

		try {
			console.log(`Starting ${api.name} API call`, { requestId, timestamp: new Date().toISOString() });
			const apiResult = await callApiWithTimeout(api.call, api.timeout);
			const duration = Date.now() - startTime;

			console.log(`${api.name} API call successful`, {
				requestId,
				duration: `${duration}ms`,
				timestamp: new Date().toISOString(),
			});

			return {
				success: true,
				name: api.name,
				resultKey: api.resultKey,
				data: apiResult,
				duration,
			};
		} catch (error) {
			const duration = Date.now() - startTime;

			console.error(`${api.name} API call failed`, {
				requestId,
				error: error.message,
				duration: `${duration}ms`,
				timestamp: new Date().toISOString(),
			});

			return {
				success: false,
				name: api.name,
				error: error.message || 'Unknown error',
				duration,
			};
		}
	});

	const apiResults = await Promise.allSettled(apiPromises);
	apiResults.forEach((promiseResult) => {
		if (promiseResult.status === 'fulfilled') {
			const apiResult = promiseResult.value;

			if (apiResult.success && apiResult.data) {
				result[apiResult.resultKey] = apiResult.data[apiResult.resultKey];
			} else if (!apiResult.success) {
				result.apiErrors.push({
					api: apiResult.name,
					message: apiResult.error,
				});
			}
		} else {
			console.error('API promise rejected:', promiseResult.reason);
		}
	});

	try {
		await saveReportToDB(env.DB, id, validatedData, result);
	} catch (dbError) {
		console.error('Database save error:', dbError);
		result.dbError = 'Failed to save to database';
	}

	console.log('Submission process completed:', {
		reportId: id,
		requestId,
		successfulApis: Object.keys(result).filter((k) => !['success', 'id', 'apiErrors', 'dbError'].includes(k)).length,
		failedApis: result.apiErrors.length,
		timestamp: new Date().toISOString(),
	});

	return result;
}

function validateFormData(data) {
	const name = data.name?.trim();
	const category = data.category?.trim();
	const source = data.source?.trim();
	const url = data.url?.trim();
	const description = data.description?.trim();

	if (!name || name.length < 2 || name.length > 100) {
		throw {
			status: 400,
			message: 'Name must be between 2 and 100 characters',
			code: 'INVALID_NAME',
		};
	}

	const allowedCategories = ['Phishing', 'Crypto Scam', 'Malware', 'Spam', 'Other'];
	if (!category || !allowedCategories.includes(category)) {
		throw {
			status: 400,
			message: 'Invalid category',
			code: 'INVALID_CATEGORY',
		};
	}

	const allowedSources = ['Email', 'SMS', 'Social Media', 'Website', 'Other'];
	if (!source || !allowedSources.includes(source)) {
		throw {
			status: 400,
			message: 'Invalid source',
			code: 'INVALID_SOURCE',
		};
	}

	const parsedUrl = parseSubmittedUrl(url);
	if (!parsedUrl) {
		throw {
			status: 400,
			message: 'Invalid URL format',
			code: 'INVALID_URL',
		};
	}

	if (description && description.length > 500) {
		throw {
			status: 400,
			message: 'Description must be 500 characters or less',
			code: 'INVALID_DESCRIPTION',
		};
	}

	return {
		name,
		category,
		source,
		url: parsedUrl.href,
		description: description || null,
		skip_urlscan: Boolean(data.skip_urlscan),
		skip_virustotal: Boolean(data.skip_virustotal),
		skip_ipqualityscore: Boolean(data.skip_ipqualityscore),
		skip_cloudflare: Boolean(data.skip_cloudflare),
	};
}

function parseSubmittedUrl(value) {
	if (!value) {
		return null;
	}

	try {
		const parsed = new URL(value);
		if (!['http:', 'https:'].includes(parsed.protocol) || !parsed.hostname) {
			return null;
		}
		return parsed;
	} catch {
		return null;
	}
}

async function callApiWithTimeout(apiCall, timeoutMs) {
	const controller = new AbortController();
	const timeout = setTimeout(() => controller.abort(), timeoutMs);

	try {
		return await apiCall(controller.signal);
	} catch (error) {
		if (error.name === 'AbortError') {
			throw new Error(`API timeout after ${timeoutMs}ms`);
		}
		throw error;
	} finally {
		clearTimeout(timeout);
	}
}

async function fetchWithTimeout(resource, options = {}, timeoutMs = 10000) {
	const controller = new AbortController();
	const timeout = setTimeout(() => controller.abort(), timeoutMs);

	try {
		return await fetch(resource, { ...options, signal: controller.signal });
	} catch (error) {
		if (error.name === 'AbortError') {
			throw new Error(`Request timeout after ${timeoutMs}ms`);
		}
		throw error;
	} finally {
		clearTimeout(timeout);
	}
}

function delay(ms) {
	return new Promise((resolve) => setTimeout(resolve, ms));
}

async function callUrlScanAPI(submittedUrl, env, signal) {
	try {
		if (!env.URLSCAN_API_KEY) {
			throw new Error('URLScan API key is not configured');
		}

		const response = await fetch('https://urlscan.io/api/v1/scan/', {
			method: 'POST',
			headers: {
				'Content-Type': 'application/json',
				'API-Key': env.URLSCAN_API_KEY,
			},
			body: JSON.stringify({
				url: submittedUrl,
				visibility: 'unlisted',
			}),
			signal,
		});

		if (!response.ok) {
			const errorData = await response.json().catch(() => ({}));
			throw new Error(errorData.message || errorData.description || `HTTP ${response.status}`);
		}

		const data = await response.json();
		if (!data.uuid) {
			throw new Error('Missing UUID in response');
		}

		return { urlscan_uuid: data.uuid };
	} catch (error) {
		throw new Error(`URLScan API: ${error.message}`);
	}
}

async function callVirusTotalAPI(submittedUrl, env, signal) {
	try {
		if (!env.VIRUSTOTAL_API_KEY) {
			throw new Error('VirusTotal API key is not configured');
		}

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

		if (!response.ok) {
			throw new Error(`HTTP ${response.status}`);
		}

		const data = await response.json();
		if (!data.data?.id) {
			throw new Error('Missing scan ID in response');
		}

		const rawScanId = data.data.id;
		const cleanScanId = rawScanId.substring(2, rawScanId.lastIndexOf('-'));
		return { virustotal_scan_id: cleanScanId };
	} catch (error) {
		throw new Error(`VirusTotal API: ${error.message}`);
	}
}

async function callIPQSAPI(submittedUrl, env, signal) {
	try {
		if (!env.IPQS_API_KEY) {
			throw new Error('IPQualityScore API key is not configured');
		}

		const apiUrl = `https://ipqualityscore.com/api/json/url/${env.IPQS_API_KEY}/${encodeURIComponent(submittedUrl)}`;
		const response = await fetch(apiUrl, { signal });

		if (!response.ok) {
			throw new Error(`HTTP ${response.status}`);
		}

		const data = await response.json();
		if (!data.success) {
			throw new Error(data.message || 'API returned success: false');
		}

		return { ipqs_scan: data };
	} catch (error) {
		throw new Error(`IPQualityScore API: ${error.message}`);
	}
}

async function callCloudflareAPI(submittedUrl, env, signal) {
	try {
		if (!env.CLOUDFLARE_ACCOUNT_ID || !env.CLOUDFLARE_API_TOKEN) {
			throw new Error('Cloudflare URL Scanner credentials are not configured');
		}

		const response = await fetch(`https://api.cloudflare.com/client/v4/accounts/${env.CLOUDFLARE_ACCOUNT_ID}/urlscanner/scan`, {
			method: 'POST',
			headers: {
				'Content-Type': 'application/json',
				Authorization: `Bearer ${env.CLOUDFLARE_API_TOKEN}`,
			},
			body: JSON.stringify({
				url: submittedUrl,
				visibility: 'unlisted',
			}),
			signal,
		});

		if (!response.ok) {
			const errorData = await response.json().catch(() => ({}));
			throw new Error(errorData.errors?.[0]?.message || `HTTP ${response.status}`);
		}

		const data = await response.json();
		if (!data.result?.uuid) {
			throw new Error('Missing UUID in response');
		}

		return { cloudflare_scan_uuid: data.result.uuid };
	} catch (error) {
		throw new Error(`Cloudflare API: ${error.message}`);
	}
}

async function saveReportToDB(db, id, formData, result) {
	const startTime = Date.now();

	try {
		console.log('Saving to database:', { reportId: id });
		const apiErrorsJson = result.apiErrors.length > 0 ? JSON.stringify(result.apiErrors) : null;

		await db
			.prepare(
				`
					INSERT INTO reports_v2 (
						id, name, category, source, url, description,
						urlscan_uuid, virustotal_scan_id, ipqs_scan, cloudflare_scan_uuid,
						api_errors, submission_success
					) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
				`
			)
			.bind(
				id,
				formData.name,
				formData.category,
				formData.source,
				formData.url,
				formData.description,
				result.urlscan_uuid || null,
				result.virustotal_scan_id || null,
				result.ipqs_scan ? JSON.stringify(result.ipqs_scan) : null,
				result.cloudflare_scan_uuid || null,
				apiErrorsJson,
				result.apiErrors.length === 0
			)
			.run();

		console.log('Database save completed:', {
			reportId: id,
			duration: `${Date.now() - startTime}ms`,
		});
	} catch (error) {
		console.error('Database save error:', {
			reportId: id,
			error: error.message,
			duration: `${Date.now() - startTime}ms`,
		});
		throw new Error('Database save failed');
	}
}

async function getReportFromDB(db, id) {
	const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
	if (!uuidRegex.test(id)) {
		throw new Error('Invalid report ID format');
	}

	try {
		return await db.prepare('SELECT * FROM reports_v2 WHERE id = ?').bind(id).first();
	} catch (error) {
		console.error('Database read error:', error);
		throw new Error('Database read failed');
	}
}
