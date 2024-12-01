export default {
	async fetch(request, env, ctx) {
		const url = new URL(request.url);

		switch (url.pathname) {
			case '/submit': {
				if (request.method === 'POST') {
					try {
						// Parse the submitted form data
						const formData = await request.json();
						const { name, category, source, url: submittedUrl, description, skip_urlscan, skip_virustotal, skip_cloudflare } = formData;

						// Validate required fields
						if (!name || !category || !source || !submittedUrl || !description) {
							return new Response('All fields are required.', { status: 400 });
						}

						// Generate a UUID for the submission
						const id = crypto.randomUUID();
						console.log('REPORT UUID: ', id);

						// Initialize result object
						let result = {
							success: true,
							id, // Always return the report UUID
						};

						// If both APIs are skipped, return early with the result
						if (skip_urlscan && skip_virustotal && skip_cloudflare) {
							return new Response(JSON.stringify(result), {
								status: 200,
								headers: { 'Content-Type': 'application/json' },
							});
						}

						// URLSCAN.IO API LOGIC
						let urlscanUUID = null;
						if (!skip_urlscan) {
							const urlscanResponse = await fetch('https://urlscan.io/api/v1/scan/', {
								method: 'POST',
								headers: {
									'Content-Type': 'application/json',
									'API-Key': env.URLSCAN_API_KEY, // Add this to wrangler.toml
								},
								body: JSON.stringify({
									url: submittedUrl,
									visibility: 'unlisted',
								}),
							});

							if (!urlscanResponse.ok) {
								console.log('ERROR');
								console.error('urlscan.io API Error:', await urlscanResponse.text());
								return new Response('urlscan.io API Error', { status: 500 });
							}

							const urlscanData = await urlscanResponse.json();
							urlscanUUID = urlscanData.uuid;
							result.scan_uuid = urlscanUUID;
							console.log('URLScan UUID: ', urlscanUUID);
						}

						// VIRUSTOTAL API LOGIC
						let virustotalScanID = null;
						if (!skip_virustotal) {
							const virustotalResponse = await fetch('https://www.virustotal.com/api/v3/urls', {
								method: 'POST',
								headers: {
									accept: 'application/json',
									'content-type': 'application/x-www-form-urlencoded',
									'x-apikey': env.VIRUSTOTAL_API_KEY,
								},
								body: new URLSearchParams({ url: submittedUrl }),
							});

							if (!virustotalResponse.ok) {
								console.log('ERROR');
								console.error('VirusTotal API Error:', await virustotalResponse.text());
								return new Response('VirusTotal API Error', { status: 500 });
							}

							const virustotalData = await virustotalResponse.json();
							const virustotalScanResult = virustotalData.data.id;
							const cleanScanId = virustotalScanResult.substring(2, virustotalScanResult.lastIndexOf('-'));
							virustotalScanID = cleanScanId;
							result.virustotal_scan_id = virustotalScanID;
							console.log('VirusTotal Scan ID: ', virustotalScanID);
						}

						// CLOUDFLARE URLSCAN API LOGIC
						let cloudflareScanUUID = null;
						if (!skip_cloudflare) {
							const cloudflareResponse = await fetch(
								`https://api.cloudflare.com/client/v4/accounts/${env.CLOUDFLARE_ACCOUNT_ID}/urlscanner/scan`,
								{
									method: 'POST',
									headers: {
										'Content-Type': 'application/json',
										'X-Auth-Key': `${env.CLOUDFLARE_API_KEY}`,
										'X-Auth-Email': `${env.CLOUDFLARE_USER_EMAIL}`,
									},
									body: JSON.stringify({
										screenshotsResolutions: ['desktop'],
										url: submittedUrl,
										visibility: 'Unlisted',
									}),
								}
							);

							if (!cloudflareResponse.ok) {
								console.log('ERROR');
								console.error('Cloudflare URLScanner API Error:', await cloudflareResponse.text());
								return new Response('Cloudflare URLScanner API Error', { status: 500 });
							}

							const cloudflareData = await cloudflareResponse.json();
							cloudflareScanUUID = cloudflareData.result.uuid;
							result.cloudflare_scan_uuid = cloudflareScanUUID;
							console.log('Cloudflare URLScan UUID: ', cloudflareScanUUID);
						}

						// D1 DATABASE LOGIC: Insert the data into the D1 database with the new IDs
						try {
							await env.DB.prepare(
								`INSERT INTO reports (id, name, category, source, url, description, urlscan_uuid, virustotal_scan_id, cloudflare_scan_uuid)
				   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`
							)
								.bind(id, name, category, source, submittedUrl, description, urlscanUUID, virustotalScanID, cloudflareScanUUID)
								.run();
							console.log('D1 UPLOAD SUCCESS!');
						} catch (error) {
							console.log('ERROR');
							console.error('D1 Database Error:', error);
							return new Response('Database Error', { status: 500 });
						}

						// Respond with the results from URLScan, VirusTotal, and/or Cloudflare
						return new Response(JSON.stringify(result), {
							status: 200,
							headers: { 'Content-Type': 'application/json' },
						});
					} catch (error) {
						console.log('ERROR');
						console.error('Error handling submission:', error);
						return new Response('Internal Server Error', { status: 500 });
					}
				} else {
					return new Response('Method Not Allowed', { status: 405 });
				}
			}

			case '/random': {
				return new Response(crypto.randomUUID(), {
					status: 200,
					headers: { 'Content-Type': 'text/plain' },
				});
			}

			default: {
				return new Response('Not Found', { status: 404 });
			}
		}
	},
};
