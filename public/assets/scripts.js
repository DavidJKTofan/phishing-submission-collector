// State management
const state = {
	turnstileWidget: null,
	turnstileLoaded: false,
	isSubmitting: false,
	retryCount: 0,
	maxRetries: 3,
};

// DOM elements
const elements = {
	form: null,
	submitBtn: null,
	errorMessage: null,
	warningMessage: null,
	turnstileContainer: null,
	turnstileError: null,
	turnstileResponse: null,
};

// Global callback for Turnstile onload
window.onloadTurnstileCallback = function () {
	console.log('Turnstile library loaded');
	state.turnstileLoaded = true;
	renderTurnstileWidget();
};

// Initialize when DOM is ready
document.addEventListener('DOMContentLoaded', function () {
	initializeElements();
	setupFormValidation();
	setupFormSubmission();
	setupAnimations();

	// If Turnstile already loaded (unlikely but possible), render it
	if (window.turnstile && !state.turnstileWidget) {
		console.log('Turnstile already loaded on DOMContentLoaded');
		renderTurnstileWidget();
	}

	// Safety check: If Turnstile doesn't load within 10 seconds, show error
	setTimeout(() => {
		if (!state.turnstileLoaded) {
			console.error('Turnstile failed to load within timeout');
			showTurnstileError('Security verification failed to load. Please refresh the page.');
		}
	}, 10000);
});

// Initialize DOM element references
function initializeElements() {
	elements.form = document.getElementById('phishingForm');
	elements.submitBtn = document.getElementById('submit-btn');
	elements.errorMessage = document.getElementById('error-message');
	elements.warningMessage = document.getElementById('warning-message');
	elements.turnstileContainer = document.getElementById('turnstile-container');
	elements.turnstileError = document.getElementById('turnstile-error');
	elements.turnstileResponse = document.getElementById('cf-turnstile-response');
}

// Render Turnstile widget
function renderTurnstileWidget() {
	// Check if Turnstile is available
	if (typeof turnstile === 'undefined' || !window.turnstile) {
		console.error('Turnstile library not available');
		showTurnstileError('Security verification not available. Please refresh the page.');
		return;
	}

	// Remove existing widget if present
	if (state.turnstileWidget) {
		try {
			turnstile.remove(state.turnstileWidget);
		} catch (e) {
			console.warn('Error removing Turnstile widget:', e);
		}
	}

	// Clear any previous errors
	hideTurnstileError();

	try {
		state.turnstileWidget = turnstile.render('#turnstile-container', {
			sitekey: '0x4AAAAAAA1Q4zDSRdaSX7mZ',
			action: 'submit-report',
			theme: 'light',
			size: 'normal',
			callback: handleTurnstileSuccess,
			'expired-callback': handleTurnstileExpired,
			'error-callback': handleTurnstileError,
			'timeout-callback': handleTurnstileTimeout,
			'unsupported-callback': handleTurnstileUnsupported,
		});

		state.turnstileLoaded = true;
		state.retryCount = 0;
		console.log('Turnstile widget rendered successfully');
	} catch (error) {
		console.error('Error rendering Turnstile:', error);
		handleTurnstileError();
	}
}

// Turnstile callback handlers
function handleTurnstileSuccess(token) {
	console.log('Turnstile verification successful');
	elements.turnstileResponse.value = token;
	elements.submitBtn.disabled = false;
	hideTurnstileError();
	hideError();
}

function handleTurnstileExpired() {
	console.warn('Turnstile token expired');
	elements.turnstileResponse.value = '';
	elements.submitBtn.disabled = true;
	showTurnstileError('Security verification expired. Please complete it again.');

	// Auto-refresh the widget
	setTimeout(() => {
		if (state.retryCount < state.maxRetries) {
			state.retryCount++;
			console.log(`Auto-refreshing Turnstile (attempt ${state.retryCount}/${state.maxRetries})`);
			renderTurnstileWidget();
		}
	}, 1000);
}

function handleTurnstileError() {
	console.error('Turnstile verification error');
	elements.turnstileResponse.value = '';
	elements.submitBtn.disabled = true;
	showTurnstileError('Security verification failed. Retrying...');

	// Retry rendering the widget
	if (state.retryCount < state.maxRetries) {
		state.retryCount++;
		setTimeout(() => {
			console.log(`Retrying Turnstile render (attempt ${state.retryCount}/${state.maxRetries})`);
			renderTurnstileWidget();
		}, 2000);
	} else {
		showTurnstileError('Security verification unavailable. Please refresh the page.');
	}
}

function handleTurnstileTimeout() {
	console.warn('Turnstile verification timeout');
	elements.turnstileResponse.value = '';
	showTurnstileError('Security verification timed out. Please try again.');

	// Reset and try again
	setTimeout(() => {
		renderTurnstileWidget();
	}, 1500);
}

function handleTurnstileUnsupported() {
	console.error('Turnstile not supported');
	showTurnstileError('Security verification not supported in this browser.');
}

// Show/hide Turnstile errors
function showTurnstileError(message) {
	elements.turnstileError.textContent = message;
	elements.turnstileError.style.display = 'block';
}

function hideTurnstileError() {
	elements.turnstileError.style.display = 'none';
}

// Reset Turnstile widget
function resetTurnstile() {
	if (!window.turnstile) {
		console.error('Turnstile not available for reset');
		return;
	}

	if (state.turnstileWidget) {
		try {
			turnstile.reset(state.turnstileWidget);
			elements.turnstileResponse.value = '';
			elements.submitBtn.disabled = true;
		} catch (error) {
			console.error('Error resetting Turnstile:', error);
			// If reset fails, re-render the widget
			renderTurnstileWidget();
		}
	} else {
		// No widget exists, try to render one
		renderTurnstileWidget();
	}
}

// Form validation setup
function setupFormValidation() {
	// Real-time URL validation
	const urlInput = document.getElementById('url');
	urlInput.addEventListener('blur', function () {
		validateField('url');
	});

	urlInput.addEventListener('input', function () {
		clearFieldError('url');
	});

	// Real-time description character count
	const descriptionInput = document.getElementById('description');
	const descriptionHint = document.getElementById('description-hint');

	descriptionInput.addEventListener('input', function () {
		const remaining = 500 - this.value.length;

		if (remaining < 0) {
			descriptionHint.textContent = `${Math.abs(remaining)} characters over limit`;
			descriptionHint.style.color = 'var(--danger)';
			this.classList.add('error');
		} else if (remaining < 50) {
			descriptionHint.textContent = `${remaining} characters remaining`;
			descriptionHint.style.color = 'var(--warning)';
			this.classList.remove('error');
		} else {
			descriptionHint.textContent = 'Optional - Maximum 500 characters';
			descriptionHint.style.color = '';
			this.classList.remove('error');
		}
	});

	// Clear error on input for other fields
	['name', 'category', 'source'].forEach((fieldId) => {
		const field = document.getElementById(fieldId);
		field.addEventListener('input', () => clearFieldError(fieldId));
		field.addEventListener('change', () => clearFieldError(fieldId));
	});
}

// Validate individual field
function validateField(fieldId) {
	const field = document.getElementById(fieldId);
	const value = field.value.trim();
	let isValid = true;
	let errorMessage = '';

	switch (fieldId) {
		case 'name':
			if (!value) {
				errorMessage = 'Name is required';
				isValid = false;
			} else if (value.length < 2) {
				errorMessage = 'Name must be at least 2 characters';
				isValid = false;
			} else if (value.length > 100) {
				errorMessage = 'Name must be 100 characters or less';
				isValid = false;
			}
			break;

		case 'category':
			if (!value) {
				errorMessage = 'Please select a category';
				isValid = false;
			}
			break;

		case 'source':
			if (!value) {
				errorMessage = 'Please select a source';
				isValid = false;
			}
			break;

		case 'url':
			if (!value) {
				errorMessage = 'URL is required';
				isValid = false;
			} else {
				const urlPattern = /^https?:\/\/(www\.)?[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b([-a-zA-Z0-9()@:%_\+.~#?&//=]*)$/;
				if (!urlPattern.test(value)) {
					errorMessage = 'Please enter a valid URL (must start with http:// or https://)';
					isValid = false;
				}
			}
			break;
	}

	if (!isValid) {
		showFieldError(fieldId, errorMessage);
		field.classList.add('error');
	} else {
		clearFieldError(fieldId);
		field.classList.remove('error');
	}

	return isValid;
}

// Validate entire form
function validateForm() {
	const fields = ['name', 'category', 'source', 'url'];
	let isValid = true;

	fields.forEach((fieldId) => {
		if (!validateField(fieldId)) {
			isValid = false;
		}
	});

	// Check description length
	const description = document.getElementById('description').value;
	if (description.length > 500) {
		showFieldError('description', 'Description must be 500 characters or less');
		document.getElementById('description').classList.add('error');
		isValid = false;
	}

	// Check Turnstile token
	if (!elements.turnstileResponse.value) {
		showError('Please complete the security verification');
		isValid = false;
	}

	return isValid;
}

// Show/hide field errors
function showFieldError(fieldId, message) {
	const errorElement = document.getElementById(`${fieldId}-error`);
	if (errorElement) {
		errorElement.textContent = message;
		errorElement.style.display = 'block';
	}
}

function clearFieldError(fieldId) {
	const errorElement = document.getElementById(`${fieldId}-error`);
	if (errorElement) {
		errorElement.style.display = 'none';
	}
	document.getElementById(fieldId).classList.remove('error');
}

// Show/hide general messages
function showError(message) {
	elements.errorMessage.textContent = message;
	elements.errorMessage.style.display = 'block';
	elements.errorMessage.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
}

function hideError() {
	elements.errorMessage.style.display = 'none';
}

function showWarning(message) {
	elements.warningMessage.textContent = message;
	elements.warningMessage.style.display = 'block';
}

function hideWarning() {
	elements.warningMessage.style.display = 'none';
}

// Form submission setup
function setupFormSubmission() {
	elements.form.addEventListener('submit', async function (e) {
		e.preventDefault();

		// Prevent double submission
		if (state.isSubmitting) {
			return;
		}

		// Hide previous messages
		hideError();
		hideWarning();

		// Validate form
		if (!validateForm()) {
			return;
		}

		await submitForm();
	});
}

// Submit form to API
async function submitForm() {
	state.isSubmitting = true;

	// Update button state
	elements.submitBtn.disabled = true;
	elements.submitBtn.classList.add('loading');

	// Collect form data
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
		'cf-turnstile-response': elements.turnstileResponse.value,
	};

	try {
		const response = await fetch('/submit', {
			method: 'POST',
			headers: {
				'Content-Type': 'application/json',
			},
			body: JSON.stringify(formData),
		});

		const data = await response.json();

		if (response.ok) {
			// Success - show results
			handleSubmissionSuccess(data);
		} else {
			// Error response from server
			handleSubmissionError(data);
		}
	} catch (error) {
		console.error('Submission error:', error);
		showError('Network error. Please check your connection and try again.');
	} finally {
		// Reset button state
		state.isSubmitting = false;
		elements.submitBtn.classList.remove('loading');
		elements.submitBtn.disabled = false;
	}
}

// Handle successful submission
function handleSubmissionSuccess(data) {
	// Clear form
	elements.form.reset();

	// Reset Turnstile
	resetTurnstile();

	// Remove existing result if present
	const existingResult = document.querySelector('.result-container');
	if (existingResult) {
		existingResult.remove();
	}

	// Create success result
	const resultContainer = document.createElement('div');
	resultContainer.className = 'result-container';

	let resultHTML = `
		<h2>✅ Submission Successful!</h2>
		<div class="result-details">
			<p>
				<strong>Report ID</strong>
				<span style="font-family: monospace; background: white; padding: 0.5rem; border-radius: 8px; display: inline-block;">${data.id}</span>
			</p>
	`;

	// Add API results if available
	const apiResults = [];

	if (data.urlscan_uuid) {
		apiResults.push({
			name: 'URLScan.io Analysis',
			url: `https://urlscan.io/result/${data.urlscan_uuid}/`,
			text: 'View detailed scan results →',
		});
	}

	if (data.virustotal_scan_id) {
		apiResults.push({
			name: 'VirusTotal Scan',
			url: `https://www.virustotal.com/gui/url/${data.virustotal_scan_id}`,
			text: 'View malware analysis →',
		});
	}

	if (data.cloudflare_scan_uuid) {
		apiResults.push({
			name: 'Cloudflare Radar Scan',
			url: `https://radar.cloudflare.com/scan/${data.cloudflare_scan_uuid}/summary`,
			text: 'View security report →',
		});
	}

	// Display API results
	apiResults.forEach((result) => {
		resultHTML += `
			<p>
				<strong>${result.name}</strong>
				<a href="${result.url}" target="_blank" rel="nofollow noreferrer external">
					${result.text}
				</a>
			</p>
		`;
	});

	// Show API errors if any occurred
	if (data.apiErrors && data.apiErrors.length > 0) {
		resultHTML += `
			<details style="margin-top: 1rem; padding: 1rem; background: #fef3c7; border: 2px solid #f59e0b; border-radius: 12px;">
				<summary style="cursor: pointer; font-weight: 600; color: #92400e; user-select: none;">
					⚠️ Some API calls had issues (${data.apiErrors.length})
				</summary>
				<ul style="margin-top: 0.75rem; padding-left: 1.5rem; font-size: 0.9rem; color: #78350f;">
					${data.apiErrors
						.map(
							(error) => `
						<li style="margin: 0.5rem 0;"><strong>${error.api}:</strong> ${error.message}</li>
					`
						)
						.join('')}
				</ul>
			</details>
		`;
	}

	resultHTML += `</div>`;
	resultContainer.innerHTML = resultHTML;

	// Insert result after form
	elements.form.parentNode.insertBefore(resultContainer, elements.form.nextSibling);

	// Scroll to result
	setTimeout(() => {
		resultContainer.scrollIntoView({ behavior: 'smooth', block: 'center' });
	}, 100);
}

// Handle submission errors
function handleSubmissionError(data) {
	const errorMsg = data.error || 'Submission failed. Please try again.';
	showError(errorMsg);

	// If Turnstile error, reset it
	if (data.code === 'INVALID_TURNSTILE' || errorMsg.toLowerCase().includes('turnstile')) {
		resetTurnstile();
	}
}

// Setup animations for form elements
function setupAnimations() {
	const observer = new IntersectionObserver(
		(entries) => {
			entries.forEach((entry, index) => {
				if (entry.isIntersecting) {
					setTimeout(() => {
						entry.target.style.opacity = '1';
						entry.target.style.transform = 'translateY(0)';
					}, index * 50);
					observer.unobserve(entry.target);
				}
			});
		},
		{ threshold: 0.1 }
	);

	// Animate form groups and quick links
	document.querySelectorAll('.form-group, .quick-link').forEach((el, index) => {
		el.style.opacity = '0';
		el.style.transform = 'translateY(20px)';
		el.style.transition = 'opacity 0.5s ease, transform 0.5s ease';
		el.style.transitionDelay = `${index * 0.05}s`;
		observer.observe(el);
	});
}

// Handle page visibility changes - refresh Turnstile if needed
document.addEventListener('visibilitychange', function () {
	if (!document.hidden && state.turnstileLoaded && window.turnstile) {
		// Check if token is still valid when user returns to page
		if (!elements.turnstileResponse.value) {
			console.log('Page visible again, checking Turnstile status');
			// Widget might have expired, try to reset it
			setTimeout(() => {
				if (!elements.turnstileResponse.value) {
					resetTurnstile();
				}
			}, 1000);
		}
	}
});
