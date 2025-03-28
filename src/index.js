export default {
	async fetch(request, env, ctx) {
		const url = new URL(request.url);

		switch (url.pathname) {
			case '/submit': {
				if (request.method !== 'POST') {
					return new Response('Method Not Allowed', { status: 405 });
				}

				if (request.headers.get('Content-Type') !== 'application/json') {
					return new Response('Unsupported Media Type', { status: 415 });
				}

				try {
					const formData = await request.json();

					// Turnstile injects a token in "turnstile-token".
					const token = formData['turnstile-token'];
					// const ip = request.headers.get('CF-Connecting-IP');
					// console.log(ip);
					// Validate the token by calling the Turnstile API.
					let turnstileFormData = new FormData();
					turnstileFormData.append('secret', env.TURNSTILE_SECRET_KEY); // Your Turnstile Secret Key
					turnstileFormData.append('response', token);
					// turnstileFormData.append('remoteip', ip);
					const turnstileUrl = 'https://challenges.cloudflare.com/turnstile/v0/siteverify';
					const turnstileResult = await fetch(turnstileUrl, {
						body: turnstileFormData,
						method: 'POST',
					});
					const outcome = await turnstileResult.json();
					// console.log('TURNSTILE OUTCOME: ', outcome);
					if (!outcome.success) {
						console.log('ERROR');
						console.error('Error with Turnstile server-side validation!');
						return new Response('Turnstile validation failed', { status: 400 });
					}

					// Continue if Turnstile server-side validation is a success
					const result = await handleSubmission(formData, env);
					return new Response(JSON.stringify(result), {
						status: 200,
						headers: {
							'Content-Type': 'application/json',
							'Access-Control-Allow-Origin': '*',
						},
					});
				} catch (error) {
					console.log('ERROR');
					console.error('Error handling submission:', error);
					const status = error.status || 500;
					return new Response(error.message || 'Internal Server Error', { status });
				}
			}

			case '/random': {
				return new Response(crypto.randomUUID(), {
					status: 200,
					headers: {
						'Content-Type': 'text/plain',
						'Access-Control-Allow-Origin': '*',
					},
				});
			}

			default: {
				return new Response('Not Found', { status: 404 });
			}
		}
	},
};

// Helper Function: Handle Submission
async function handleSubmission(formData, env) {
	validateFormData(formData);

	const id = crypto.randomUUID();
	console.log('REPORT UUID:', id);

	let result = {
		success: true,
		id,
		apiErrors: []  // Dedicated array to track API errors
	};

	// Parallel API calls with comprehensive error handling
	const apiCalls = [
		{
			name: 'URLScan',
			skip: formData.skip_urlscan,
			call: () => callUrlScanAPI(formData.url, env),
			resultKey: 'urlscan_uuid'
		},
		{
			name: 'VirusTotal',
			skip: formData.skip_virustotal,
			call: () => callVirusTotalAPI(formData.url, env),
			resultKey: 'virustotal_scan_id'
		},
		{
			name: 'IPQualityScore',
			skip: formData.skip_ipqualityscore,
			call: () => callIPQSAPI(formData.url, env),
			resultKey: 'ipqs_scan'
		},
		{
			name: 'Cloudflare',
			skip: formData.skip_cloudflare,
			call: () => callCloudflareAPI(formData.url, env),
			resultKey: 'cloudflare_scan_uuid'
		}
	];

	// Process API calls with individual error handling
	const scanPromises = apiCalls
		.filter(api => !api.skip)
		.map(async (api) => {
			try {
				const apiResult = await callApiWithTimeout(api.call, 8000);
				return {
					name: api.name,
					resultKey: api.resultKey,
					data: apiResult
				};
			} catch (error) {
				// Capture detailed error information
				return {
					name: api.name,
					error: {
						message: error.message || 'Unknown API error',
						details: error
					}
				};
			}
		});

	// Wait for all API calls to complete
	const scanResults = await Promise.allSettled(scanPromises);

	// Process results and errors
	scanResults.forEach(resultData => {
		if (resultData.status === 'fulfilled') {
			const apiResult = resultData.value;

			// If API call was successful, add to result
			if (apiResult.data) {
				result[apiResult.resultKey] = apiResult.data[apiResult.resultKey];
			}

			// If API call resulted in an error, track it
			if (apiResult.error) {
				result.success = false;
				result.apiErrors.push({
					api: apiResult.name,
					message: apiResult.error.message,
					details: apiResult.error.details
				});
			}
		}
	});

	// Save to the database, including any errors
	await saveReportToDB(env.DB, id, formData, result);

	return result;
}

// Validate incoming data
function validateFormData(data) {
	// Trim and validate inputs
	const name = data.name?.trim();
	const category = data.category?.trim();
	const source = data.source?.trim();
	const url = data.url?.trim();
	const description = data.description?.trim();

	// Comprehensive validation
	if (!name || name.length < 2 || name.length > 100) {
		throw { status: 400, message: 'Name must be between 2 and 100 characters.' };
	}

	const allowedCategories = ['Phishing', 'Crypto Scam', 'Malware', 'Spam', 'Other'];
	if (!category || !allowedCategories.includes(category)) {
		throw { status: 400, message: 'Invalid category. Must be one of: ' + allowedCategories.join(', ') };
	}

	if (!source || source.length < 2 || source.length > 100) {
		throw { status: 400, message: 'Source must be between 2 and 100 characters.' };
	}

	// More robust URL validation
	const urlRegex = /^(https?:\/\/)?([\da-z\.-]+)\.([a-z\.]{2,6})([\/\w \.-]*)*\/?$/;
	if (!url || !urlRegex.test(url)) {
		throw { status: 400, message: 'Invalid URL format.' };
	}

	// Optional description length limit
	if (description && description.length > 500) {
		throw { status: 400, message: 'Description must be 500 characters or less.' };
	}
}

// Timeout wrapper for API calls
async function callApiWithTimeout(apiCall, timeoutMs) {
	return new Promise((resolve, reject) => {
		const timeout = setTimeout(() => {
			reject({
				message: 'API Timeout',
				details: {
					timeoutDuration: timeoutMs
				}
			});
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

// API: URLScan
async function callUrlScanAPI(submittedUrl, env) {
	const response = await fetch('https://urlscan.io/api/v1/scan/', {
		method: 'POST',
		headers: {
			'Content-Type': 'application/json',
			'API-Key': env.URLSCAN_API_KEY,
		},
		body: JSON.stringify({ url: submittedUrl, visibility: 'unlisted' }),
	});

	if (!response.ok) {
		console.log('ERROR');
		throw { urlscan_uuid_error: 'Failed to fetch from URLScan API' };
	}

	const data = await response.json();
	if (!data.uuid) {
		console.log('ERROR');
		throw { urlscan_uuid_error: 'Invalid data from URLScan API' };
	}

	return { urlscan_uuid: data.uuid };
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
			throw { virustotal_scan_id_error: 'Failed to fetch from VirusTotal API' };
		}

		const data = await response.json();

		if (data && data.data && data.data.id) {
			// Extract the scan ID using the correct substring logic
			const rawScanId = data.data.id;
			const cleanScanId = rawScanId.substring(2, rawScanId.lastIndexOf('-'));

			return { virustotal_scan_id: cleanScanId };
		} else {
			throw { virustotal_scan_id_error: 'Missing or invalid Scan ID in VirusTotal API response' };
		}
	} catch (error) {
		console.warn('VirusTotal API Error:', error);
		throw { virustotal_scan_id_error: 'VirusTotal API call failed or returned invalid data' };
	}
}

// API: IPQualityScore
async function callIPQSAPI(submittedUrl, env) {
	try {
		const response = await fetch('https://ipqualityscore.com/api/json/url/' + env.IPQS_API_KEY + '/' + encodeURIComponent(submittedUrl));

		if (!response.ok) {
			console.log('ERROR');
			throw { ipqs_scan_error: 'Failed to fetch from IPQualityScore API' };
		}

		const data = await response.json();
		if (!data.success) {
			console.log('ERROR');
			throw { ipqs_scan_error: 'Invalid data from IPQualityScore API' };
		}

		return { ipqs_scan: data };
	} catch (error) {
		console.warn('IPQS API Error:', error);
		throw { ipqs_scan_error: 'IPQS API call failed or returned invalid data' };
	}
}

// API: Cloudflare
async function callCloudflareAPI(submittedUrl, env) {
	const response = await fetch(`https://api.cloudflare.com/client/v4/accounts/${env.CLOUDFLARE_ACCOUNT_ID}/urlscanner/scan`, {
		method: 'POST',
		headers: {
			'Content-Type': 'application/json',
			'X-Auth-Key': env.CLOUDFLARE_API_KEY,
			'X-Auth-Email': env.CLOUDFLARE_USER_EMAIL,
		},
		body: JSON.stringify({ url: submittedUrl, visibility: 'unlisted' }),
	});

	if (!response.ok) {
		console.log('ERROR');
		throw { cloudflare_scan_uuid_error: 'Failed to fetch from Cloudflare URLScanner API' };
	}

	const data = await response.json();
	if (!data.result || !data.result.uuid) {
		console.log('ERROR');
		throw { cloudflare_scan_uuid_error: 'Invalid data from Cloudflare API' };
	}

	return { cloudflare_scan_uuid: data.result.uuid };
}

// Database Save Function
async function saveReportToDB(db, id, formData, result) {
	try {
		const apiErrorsJson = result.apiErrors ? JSON.stringify(result.apiErrors) : null;

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
				formData.description,
				result.urlscan_uuid || null,
				result.virustotal_scan_id || null,
				result.ipqs_scan || null,
				result.cloudflare_scan_uuid || null,
				apiErrorsJson,
				result.success
			)
			.run();

		console.log('D1 Database upload success!');
	} catch (error) {
		console.error('Database Save Error:', error);
		throw { status: 500, message: 'Database Error', error };
	}
}
