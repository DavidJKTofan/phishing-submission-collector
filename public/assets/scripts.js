document.addEventListener('DOMContentLoaded', function () {
	turnstile.ready(function () {
		turnstile.render('#turnstile-container', {
			sitekey: '1x00000000000000000000AA', // Replace with your site key
			action: 'submit-report',
			theme: 'light',
			callback: function (token) {
				// Set the token in the hidden input field
				document.getElementById('turnstile-token').value = token;
			},
		});
	});

	document.getElementById('phishingForm').addEventListener('submit', async function (e) {
		e.preventDefault();

		// Ensure the Turnstile token is included in the form data
		const turnstileToken = document.getElementById('turnstile-token').value;
		if (!turnstileToken) {
			alert('Please complete the Turnstile verification.');
			return;
		}

		const formData = {
			name: document.getElementById('name').value,
			category: document.getElementById('category').value,
			source: document.getElementById('source').value,
			url: document.getElementById('url').value,
			description: document.getElementById('description').value,
			skip_urlscan: document.getElementById('skip_urlscan').checked,
			skip_virustotal: document.getElementById('skip_virustotal').checked,
			skip_cloudflare: document.getElementById('skip_cloudflare').checked,
			'turnstile-token': turnstileToken, // Include the Turnstile token
		};

		const response = await fetch('/submit', {
			method: 'POST',
			headers: { 'Content-Type': 'application/json' },
			body: JSON.stringify(formData),
		});

		if (response.ok) {
			const data = await response.json();

			// Display the result
			const resultContainer = document.createElement('div');
			resultContainer.innerHTML = `
				<p>Submission successful!</p>
				<p><strong>Report UUID:</strong> ${data.id}</p>
				${
					data.scan_uuid
						? `<p><strong>URLScan UUID:</strong> <a href="https://urlscan.io/result/${data.scan_uuid}/" target="_blank" rel="nofollow noreferrer external">${data.scan_uuid}</a></p>`
						: ''
				}
				${
					data.virustotal_scan_id
						? `<p><strong>VirusTotal Scan ID:</strong> <a href="https://www.virustotal.com/gui/url/${data.virustotal_scan_id}" target="_blank" rel="nofollow noreferrer external">${data.virustotal_scan_id}</a></p>`
						: ''
				}
				${
					data.cloudflare_scan_uuid
						? `<p><strong>Cloudflare URLScanner ID:</strong> <a href="https://radar.cloudflare.com/scan/${data.cloudflare_scan_uuid}/summary" target="_blank" rel="nofollow noreferrer external">${data.cloudflare_scan_uuid}</a></p>`
						: ''
				}
			`;
			document.body.appendChild(resultContainer);
		} else {
			alert('Error: Could not submit the report.');
		}
	});
});
