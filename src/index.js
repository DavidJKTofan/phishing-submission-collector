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

	let result = { success: true, id };

	// Parallel API calls with error handling
	const scanPromises = [
		formData.skip_urlscan ? null : callApiWithTimeout(() => callUrlScanAPI(formData.url, env), 8000),
		formData.skip_virustotal ? null : callApiWithTimeout(() => callVirusTotalAPI(formData.url, env), 8000),
		formData.skip_cloudflare ? null : callApiWithTimeout(() => callCloudflareAPI(formData.url, env), 8000),
	].filter(Boolean);

	const scanResults = await Promise.allSettled(scanPromises);

	// Collect results and errors
	scanResults.forEach((resultData) => {
		if (resultData.status === 'fulfilled') {
			Object.assign(result, resultData.value);
		} else {
			console.log('ERROR');
			console.warn('API Call Error:', resultData.reason);
			Object.assign(result, resultData.reason); // Add error messages
		}
	});

	// Save to the database
	await saveReportToDB(env.DB, id, formData, result);

	return result;
}

// Validate incoming data
function validateFormData({ name, category, source, url, description }) {
	if (!name || !category || !source || !url) {
		throw { status: 400, message: 'All fields are required, except description.' };
	}

	if (!/^https?:\/\/[^\s$.?#].[^\s]*$/.test(url)) {
		throw { status: 400, message: 'Invalid URL format.' };
	}
}

// Timeout wrapper for API calls
async function callApiWithTimeout(apiCall, timeoutMs) {
	return new Promise((resolve, reject) => {
		const timeout = setTimeout(() => reject({ message: 'API Timeout' }), timeoutMs);
		apiCall()
			.then(resolve)
			.catch(reject)
			.finally(() => clearTimeout(timeout));
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
		throw { scan_uuid_error: 'Failed to fetch from URLScan API' };
	}

	const data = await response.json();
	if (!data.uuid) {
		console.log('ERROR');
		throw { scan_uuid_error: 'Invalid data from URLScan API' };
	}

	return { scan_uuid: data.uuid };
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
		await db
			.prepare(
				`INSERT INTO reports (id, name, category, source, url, description, urlscan_uuid, virustotal_scan_id, cloudflare_scan_uuid)
				VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`
			)
			.bind(
				id,
				formData.name,
				formData.category,
				formData.source,
				formData.url,
				formData.description,
				result.scan_uuid || null,
				result.virustotal_scan_id || null,
				result.cloudflare_scan_uuid || null
			)
			.run();

		console.log('D1 Database upload success!');
	} catch (error) {
		console.log('ERROR');
		throw { status: 500, message: 'Database Error', error };
	}
}
