document.addEventListener('DOMContentLoaded', function () {
	const submitBtn = document.getElementById('submit-btn');
	const errorMessage = document.getElementById('error-message');
	let turnstileWidget = null;

	// Initialize Turnstile
	function initTurnstile() {
		turnstile.ready(function () {
			// Remove existing widget if it exists
			if (turnstileWidget) {
				turnstile.remove(turnstileWidget);
			}

			// Render new widget
			turnstileWidget = turnstile.render('#turnstile-container', {
				sitekey: '0x4AAAAAAA1Q4zDSRdaSX7mZ',
				action: 'submit-report',
				theme: 'light',
				callback: function (token) {
					document.getElementById('cf-turnstile-response').value = token;
					submitBtn.disabled = false;
					errorMessage.style.display = 'none';
				},
				'expired-callback': function () {
					document.getElementById('cf-turnstile-response').value = '';
					submitBtn.disabled = true;
					errorMessage.textContent = 'Turnstile verification expired. Please complete the verification again.';
					errorMessage.style.display = 'block';
				},
				'error-callback': function () {
					document.getElementById('turnstile-token').value = '';
					submitBtn.disabled = true;
					errorMessage.textContent = 'Error with Turnstile verification. Please refresh the page and try again.';
					errorMessage.style.display = 'block';
				}
			});
		});
	}

	// Initialize Turnstile on page load
	initTurnstile();

	// Disable submit button initially
	submitBtn.disabled = true;

	// Form validation function
	function validateForm() {
		const name = document.getElementById('name').value.trim();
		const category = document.getElementById('category').value;
		const source = document.getElementById('source').value;
		const url = document.getElementById('url').value.trim();
		const turnstileResponse = document.getElementById('cf-turnstile-response').value;

		if (!name || !category || !source || !url) {
			errorMessage.textContent = 'Please fill out all required fields.';
			errorMessage.style.display = 'block';
			return false;
		}

		const urlPattern = /^https?:\/\/[^\s$.?#].[^\s]*$/;
		if (!urlPattern.test(url)) {
			errorMessage.textContent = 'Please enter a valid URL (must start with http:// or https://).';
			errorMessage.style.display = 'block';
			return false;
		}

		if (!turnstileResponse) {
			errorMessage.textContent = 'Please complete the Turnstile verification.';
			errorMessage.style.display = 'block';
			return false;
		}

		errorMessage.style.display = 'none';
		return true;
	}

	document.getElementById('phishingForm').addEventListener('submit', async function (e) {
		e.preventDefault();

		if (!validateForm()) {
			return;
		}

		// Disable submit button during submission
		submitBtn.disabled = true;
		submitBtn.textContent = 'Submitting...';

		const formData = {
			name: document.getElementById('name').value.trim(),
			category: document.getElementById('category').value,
			source: document.getElementById('source').value,
			url: document.getElementById('url').value.trim(),
			description: document.getElementById('description').value.trim(),
			skip_urlscan: document.getElementById('skip_urlscan').checked,
			skip_virustotal: document.getElementById('skip_virustotal').checked,
			skip_ipqualityscore: document.getElementById('skip_ipqualityscore').checked,
			skip_cloudflare: document.getElementById('skip_cloudflare').checked,
			'cf-turnstile-response': document.getElementById('cf-turnstile-response').value,
		};

		try {
			const response = await fetch('/submit', {
				method: 'POST',
				headers: { 'Content-Type': 'application/json' },
				body: JSON.stringify(formData),
			});

			const data = await response.json();

			if (response.ok) {
				// Clear form and reset Turnstile
				document.getElementById('phishingForm').reset();
				initTurnstile(); // Re-initialize Turnstile widget

				// Update or create result container
				const existingResult = document.querySelector('.result-container');
				if (existingResult) {
					existingResult.remove();
				}

				const resultContainer = document.createElement('div');
				resultContainer.className = 'result-container';
				resultContainer.innerHTML = `
					<h2>Submission Successful!</h2>
					<div class="result-details">
						<p><strong>Report UUID:</strong> ${data.id}</p>
						${data.urlscan_uuid ? `
							<p>
								<strong>URLScan UUID:</strong> 
								<a href="https://urlscan.io/result/${data.urlscan_uuid}/" 
								   target="_blank" 
								   rel="nofollow noreferrer external">
									${data.urlscan_uuid}
								</a>
							</p>` : ''
						}
						${data.virustotal_scan_id ? `
							<p>
								<strong>VirusTotal Scan ID:</strong> 
								<a href="https://www.virustotal.com/gui/url/${data.virustotal_scan_id}" 
								   target="_blank" 
								   rel="nofollow noreferrer external">
									${data.virustotal_scan_id}
								</a>
							</p>` : ''
						}
						${data.cloudflare_scan_uuid ? `
							<p>
								<strong>Cloudflare URLScanner ID:</strong> 
								<a href="https://radar.cloudflare.com/scan/${data.cloudflare_scan_uuid}/summary" 
								   target="_blank" 
								   rel="nofollow noreferrer external">
									${data.cloudflare_scan_uuid}
								</a>
							</p>` : ''
						}
					</div>
				`;
				
				// Insert result container after the form
				const form = document.getElementById('phishingForm');
				form.parentNode.insertBefore(resultContainer, form.nextSibling);
				
				// Scroll to result
				resultContainer.scrollIntoView({ behavior: 'smooth' });
			} else {
				errorMessage.textContent = data.error || 'Submission failed. Please try again.';
				errorMessage.style.display = 'block';
				
				// If there was a Turnstile error, reset it
				if (data.error?.includes('Turnstile')) {
					initTurnstile();
				}
			}
		} catch (error) {
			console.error('Submission error:', error);
			errorMessage.textContent = 'Network error. Please try again.';
			errorMessage.style.display = 'block';
		} finally {
			// Re-enable submit button
			submitBtn.disabled = false;
			submitBtn.textContent = 'Submit Report';
		}
	});
});