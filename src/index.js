export default {
	async fetch(request, env, ctx) {
		const url = new URL(request.url);

		// CORS headers for development
		const corsHeaders = {
			'Access-Control-Allow-Origin': '*',
			'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
			'Access-Control-Allow-Headers': 'Content-Type',
		};

		// Handle OPTIONS request for CORS
		if (request.method === 'OPTIONS') {
			return new Response(null, {
				status: 204,
				headers: corsHeaders,
			});
		}

		switch (url.pathname) {
			case '/submit': {
				if (request.method !== 'POST') {
					return new Response(JSON.stringify({ error: 'Method not allowed' }), {
						status: 405,
						headers: { 'Content-Type': 'application/json', ...corsHeaders },
					});
				}

				if (request.headers.get('Content-Type') !== 'application/json') {
					return new Response(JSON.stringify({ error: 'Content-Type must be application/json' }), {
						status: 400,
						headers: { 'Content-Type': 'application/json', ...corsHeaders },
					});
				}

				try {
					const submittedData = await request.json();

					// Validate Turnstile token
					const turnstileValid = await validateTurnstile(
						submittedData['cf-turnstile-response'],
						request.headers.get('CF-Connecting-IP'),
						env
					);

					if (!turnstileValid.success) {
						console.error('Turnstile validation failed:', turnstileValid);
						return new Response(
							JSON.stringify({
								error: 'Invalid security verification',
								details: turnstileValid,
								code: 'INVALID_TURNSTILE',
							}),
							{
								status: 400,
								headers: { 'Content-Type': 'application/json', ...corsHeaders },
							}
						);
					}

					console.log('Turnstile validation successful');

					// Process submission
					const result = await handleSubmission(submittedData, env);

					return new Response(JSON.stringify(result), {
						status: 200,
						headers: { 'Content-Type': 'application/json', ...corsHeaders },
					});
				} catch (error) {
					console.error('Error processing submission:', error);
					return new Response(
						JSON.stringify({
							error: error.message || 'Internal server error',
							code: error.code || 'INTERNAL_ERROR',
						}),
						{
							status: error.status || 500,
							headers: { 'Content-Type': 'application/json', ...corsHeaders },
						}
					);
				}
			}

			case '/random': {
				return new Response(crypto.randomUUID(), {
					status: 200,
					headers: { 'Content-Type': 'text/plain', ...corsHeaders },
				});
			}

			// New endpoint to get a report by ID
			case url.pathname.startsWith('/api/report/') ? url.pathname : '': {
				if (request.method !== 'GET') {
					return new Response(JSON.stringify({ error: 'Method not allowed' }), {
						status: 405,
						headers: { 'Content-Type': 'application/json', ...corsHeaders },
					});
				}

				try {
					const id = url.pathname.split('/').pop();
					const report = await getReportFromDB(env.DB, id);

					if (!report) {
						return new Response(JSON.stringify({ error: 'Report not found' }), {
							status: 404,
							headers: { 'Content-Type': 'application/json', ...corsHeaders },
						});
					}

					return new Response(JSON.stringify(report), {
						status: 200,
						headers: { 'Content-Type': 'application/json', ...corsHeaders },
					});
				} catch (error) {
					console.error('Error fetching report:', error);
					if (error.message === 'Invalid report ID format') {
						return new Response(JSON.stringify({ error: 'Invalid Report ID format' }), {
							status: 400,
							headers: { 'Content-Type': 'application/json', ...corsHeaders },
						});
					}
					return new Response(JSON.stringify({ error: 'Internal server error' }), {
						status: 500,
						headers: { 'Content-Type': 'application/json', ...corsHeaders },
					});
				}
			}

			default: {
				// Return asset from KV store
				return env.ASSETS.fetch(request);
			}
		}
	},
};

// Validate Turnstile token
async function validateTurnstile(token, ip, env) {
	if (!token) {
		console.error('Turnstile validation failed: Missing token');
		return { success: false, error: 'Missing token' };
	}

	console.log('Attempting Turnstile verification');

	try {
		const turnstileFormData = new FormData();
		turnstileFormData.append('secret', env.TURNSTILE_SECRET_KEY);
		turnstileFormData.append('response', token);

		if (ip) {
			turnstileFormData.append('remoteip', ip);
		}

		const idempotencyKey = crypto.randomUUID();
		turnstileFormData.append('idempotency_key', idempotencyKey);

		console.log('Sending Turnstile verification request');
		const turnstileResponse = await fetch('https://challenges.cloudflare.com/turnstile/v0/siteverify', {
			method: 'POST',
			body: turnstileFormData,
		});

		const outcome = await turnstileResponse.json();

		console.log('Turnstile verification response:', {
			success: outcome.success,
			timestamp: new Date().toISOString(),
			errorCodes: outcome['error-codes'] || [],
		});

		return {
			success: outcome.success,
			errorCodes: outcome['error-codes'] || [],
			timestamp: outcome.challenge_ts,
			hostname: outcome.hostname,
		};
	} catch (error) {
		console.error('Turnstile verification error:', error);
		return { success: false, error: error.message };
	}
}

// Handle form submission
async function handleSubmission(formData, env) {
	// Validate form data
	validateFormData(formData);

	const id = crypto.randomUUID();
	const requestId = crypto.randomUUID();

	console.log('Starting submission process:', {
		reportId: id,
		requestId: requestId,
		timestamp: new Date().toISOString(),
		category: formData.category,
		source: formData.source,
	});

	const result = {
		success: true,
		id,
		apiErrors: [],
	};

	// Define API calls with configurations
	const apiCalls = [
		{
			name: 'URLScan',
			skip: formData.skip_urlscan,
			call: () => callUrlScanAPI(formData.url, env),
			resultKey: 'urlscan_uuid',
			timeout: 10000,
		},
		{
			name: 'VirusTotal',
			skip: formData.skip_virustotal,
			call: () => callVirusTotalAPI(formData.url, env),
			resultKey: 'virustotal_scan_id',
			timeout: 10000,
		},
		{
			name: 'IPQualityScore',
			skip: formData.skip_ipqualityscore,
			call: () => callIPQSAPI(formData.url, env),
			resultKey: 'ipqs_scan',
			timeout: 10000,
		},
		{
			name: 'Cloudflare',
			skip: formData.skip_cloudflare,
			call: () => callCloudflareAPI(formData.url, env),
			resultKey: 'cloudflare_scan_uuid',
			timeout: 10000,
		},
	];

	// Process API calls in parallel with individual error handling
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

	// Wait for all API calls to complete
	const apiResults = await Promise.allSettled(apiPromises);

	// Process results
	apiResults.forEach((promiseResult) => {
		if (promiseResult.status === 'fulfilled') {
			const apiResult = promiseResult.value;

			if (apiResult.success && apiResult.data) {
				// Add successful result
				result[apiResult.resultKey] = apiResult.data[apiResult.resultKey];
			} else if (!apiResult.success) {
				// Track API error but continue
				result.apiErrors.push({
					api: apiResult.name,
					message: apiResult.error,
				});
			}
		} else {
			// Promise rejected
			console.error('API promise rejected:', promiseResult.reason);
		}
	});

	// Save to database (always save, even with some API failures)
	try {
		await saveReportToDB(env.DB, id, formData, result);
	} catch (dbError) {
		console.error('Database save error:', dbError);
		// Still return the result even if DB save fails
		result.dbError = 'Failed to save to database';
	}

	console.log('Submission process completed:', {
		reportId: id,
		requestId: requestId,
		successfulApis: Object.keys(result).filter((k) => !['success', 'id', 'apiErrors', 'dbError'].includes(k)).length,
		failedApis: result.apiErrors.length,
		timestamp: new Date().toISOString(),
	});

	return result;
}

// Validate form data
function validateFormData(data) {
	const name = data.name?.trim();
	const category = data.category?.trim();
	const source = data.source?.trim();
	const url = data.url?.trim();
	const description = data.description?.trim();

	// Name validation
	if (!name || name.length < 2 || name.length > 100) {
		throw {
			status: 400,
			message: 'Name must be between 2 and 100 characters',
			code: 'INVALID_NAME',
		};
	}

	// Category validation
	const allowedCategories = ['Phishing', 'Crypto Scam', 'Malware', 'Spam', 'Other'];
	if (!category || !allowedCategories.includes(category)) {
		throw {
			status: 400,
			message: 'Invalid category',
			code: 'INVALID_CATEGORY',
		};
	}

	// Source validation
	const allowedSources = ['Email', 'SMS', 'Social Media', 'Website', 'Other'];
	if (!source || !allowedSources.includes(source)) {
		throw {
			status: 400,
			message: 'Invalid source',
			code: 'INVALID_SOURCE',
		};
	}

	// URL validation
	const urlRegex = /^https?:\/\/(www\.)?[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b([-a-zA-Z0-9()@:%_\+.~#?&//=]*)$/;
	if (!url || !urlRegex.test(url)) {
		throw {
			status: 400,
			message: 'Invalid URL format',
			code: 'INVALID_URL',
		};
	}

	// Description validation (optional)
	if (description && description.length > 500) {
		throw {
			status: 400,
			message: 'Description must be 500 characters or less',
			code: 'INVALID_DESCRIPTION',
		};
	}
}

// Timeout wrapper for API calls
async function callApiWithTimeout(apiCall, timeoutMs) {
	return new Promise((resolve, reject) => {
		const timeout = setTimeout(() => {
			reject(new Error(`API timeout after ${timeoutMs}ms`));
		}, timeoutMs);

		apiCall()
			.then((result) => {
				clearTimeout(timeout);
				resolve(result);
			})
			.catch((error) => {
				clearTimeout(timeout);
				reject(error);
			});
	});
}

// API: URLScan.io
async function callUrlScanAPI(submittedUrl, env) {
	try {
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

// API: VirusTotal
async function callVirusTotalAPI(submittedUrl, env) {
	try {
		const response = await fetch('https://www.virustotal.com/api/v3/urls', {
			method: 'POST',
			headers: {
				accept: 'application/json',
				'content-type': 'application/x-www-form-urlencoded',
				'x-apikey': env.VIRUSTOTAL_API_KEY,
			},
			body: new URLSearchParams({ url: submittedUrl }),
		});

		if (!response.ok) {
			throw new Error(`HTTP ${response.status}`);
		}

		const data = await response.json();

		if (!data.data?.id) {
			throw new Error('Missing scan ID in response');
		}

		// Extract the clean scan ID
		const rawScanId = data.data.id;
		const cleanScanId = rawScanId.substring(2, rawScanId.lastIndexOf('-'));

		return { virustotal_scan_id: cleanScanId };
	} catch (error) {
		throw new Error(`VirusTotal API: ${error.message}`);
	}
}

// API: IPQualityScore
async function callIPQSAPI(submittedUrl, env) {
	try {
		const apiUrl = `https://ipqualityscore.com/api/json/url/${env.IPQS_API_KEY}/${encodeURIComponent(submittedUrl)}`;
		const response = await fetch(apiUrl);

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

// API: Cloudflare Radar
async function callCloudflareAPI(submittedUrl, env) {
	try {
		const response = await fetch(`https://api.cloudflare.com/client/v4/accounts/${env.CLOUDFLARE_ACCOUNT_ID}/urlscanner/scan`, {
			method: 'POST',
			headers: {
				'Content-Type': 'application/json',
				'X-Auth-Key': env.CLOUDFLARE_API_KEY,
				'X-Auth-Email': env.CLOUDFLARE_USER_EMAIL,
			},
			body: JSON.stringify({
				url: submittedUrl,
				visibility: 'unlisted',
			}),
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

// Save report to D1 database
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
				formData.description || null,
				result.urlscan_uuid || null,
				result.virustotal_scan_id || null,
				result.ipqs_scan ? JSON.stringify(result.ipqs_scan) : null,
				result.cloudflare_scan_uuid || null,
				apiErrorsJson,
				result.apiErrors.length === 0
			)
			.run();

		const duration = Date.now() - startTime;
		console.log('Database save completed:', {
			reportId: id,
			duration: `${duration}ms`,
		});
	} catch (error) {
		const duration = Date.now() - startTime;
		console.error('Database save error:', {
			reportId: id,
			error: error.message,
			duration: `${duration}ms`,
		});
		throw new Error('Database save failed');
	}
}

// Get a report by ID from the D1 database
async function getReportFromDB(db, id) {
	// Validate the ID format (UUID)
	const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
	if (!uuidRegex.test(id)) {
		throw new Error('Invalid report ID format');
	}

	try {
		const stmt = db.prepare('SELECT * FROM reports_v2 WHERE id = ?');
		const result = await stmt.bind(id).first();
		return result;
	} catch (error) {
		console.error('Database read error:', error);
		throw new Error('Database read failed');
	}
}
