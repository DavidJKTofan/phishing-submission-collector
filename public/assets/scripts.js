const TURNSTILE_SITE_KEY = '0x4AAAAAAA1Q4zDSRdaSX7mZ';
const TURNSTILE_TOKEN_TTL_MS = 4 * 60 * 1000;

const state = {
	turnstileWidget: null,
	turnstileLoaded: false,
	isSubmitting: false,
	tokenIssuedAt: 0,
};

const elements = {
	form: null,
	submitBtn: null,
	errorMessage: null,
	warningMessage: null,
	turnstileContainer: null,
	turnstileError: null,
	turnstileResponse: null,
};

window.onloadTurnstileCallback = function () {
	state.turnstileLoaded = true;
	renderTurnstileWidget();
};

document.addEventListener('DOMContentLoaded', function () {
	initializeElements();
	setupFormValidation();
	setupFormSubmission();
	setupAnimations();

	if (window.turnstile) {
		state.turnstileLoaded = true;
		renderTurnstileWidget();
	}

	setTimeout(() => {
		if (!state.turnstileLoaded) {
			showTurnstileError('Security verification failed to load. Please refresh the page.');
		}
	}, 10000);
});

function initializeElements() {
	elements.form = document.getElementById('phishingForm');
	elements.submitBtn = document.getElementById('submit-btn');
	elements.errorMessage = document.getElementById('error-message');
	elements.warningMessage = document.getElementById('warning-message');
	elements.turnstileContainer = document.getElementById('turnstile-container');
	elements.turnstileError = document.getElementById('turnstile-error');
	elements.turnstileResponse = document.getElementById('cf-turnstile-response');
	setSubmitEnabled(false);
}

function renderTurnstileWidget() {
	if (!elements.turnstileContainer || !window.turnstile) {
		return;
	}

	if (state.turnstileWidget) {
		resetTurnstile();
		return;
	}

	hideTurnstileError();

	try {
		state.turnstileWidget = window.turnstile.render('#turnstile-container', {
			sitekey: TURNSTILE_SITE_KEY,
			action: 'submit-report',
			theme: 'light',
			size: 'normal',
			retry: 'auto',
			'retry-interval': 8000,
			callback: handleTurnstileSuccess,
			'expired-callback': handleTurnstileExpired,
			'error-callback': handleTurnstileError,
			'timeout-callback': handleTurnstileTimeout,
			'unsupported-callback': handleTurnstileUnsupported,
		});
	} catch (error) {
		console.error('Error rendering Turnstile:', error);
		showTurnstileError('Security verification failed to initialize. Please refresh the page.');
	}
}

function handleTurnstileSuccess(token) {
	elements.turnstileResponse.value = token;
	state.tokenIssuedAt = Date.now();
	hideTurnstileError();
	hideError();
	setSubmitEnabled(true);
}

function handleTurnstileExpired() {
	clearTurnstileToken();
	showTurnstileError('Security verification expired. Please complete it again.');
	resetTurnstile();
}

function handleTurnstileError(errorCode) {
	clearTurnstileToken();
	console.error('Turnstile verification error:', errorCode);
	showTurnstileError('Security verification failed. Please try again or refresh the page.');
	return true;
}

function handleTurnstileTimeout() {
	clearTurnstileToken();
	showTurnstileError('Security verification timed out. Please try again.');
	resetTurnstile();
}

function handleTurnstileUnsupported() {
	clearTurnstileToken();
	showTurnstileError('Security verification is not supported in this browser.');
}

function clearTurnstileToken() {
	elements.turnstileResponse.value = '';
	state.tokenIssuedAt = 0;
	setSubmitEnabled(false);
}

function showTurnstileError(message) {
	elements.turnstileError.textContent = message;
	elements.turnstileError.style.display = 'block';
}

function hideTurnstileError() {
	elements.turnstileError.style.display = 'none';
}

function resetTurnstile() {
	clearTurnstileToken();

	if (!window.turnstile || !state.turnstileWidget) {
		return;
	}

	try {
		window.turnstile.reset(state.turnstileWidget);
	} catch (error) {
		console.error('Error resetting Turnstile:', error);
		showTurnstileError('Security verification failed to reset. Please refresh the page.');
	}
}

function setSubmitEnabled(enabled) {
	elements.submitBtn.disabled = !enabled || state.isSubmitting;
}

function setupFormValidation() {
	const urlInput = document.getElementById('url');
	urlInput.addEventListener('blur', function () {
		validateField('url');
	});

	urlInput.addEventListener('input', function () {
		clearFieldError('url');
	});

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

	['name', 'category', 'source'].forEach((fieldId) => {
		const field = document.getElementById(fieldId);
		field.addEventListener('input', () => clearFieldError(fieldId));
		field.addEventListener('change', () => clearFieldError(fieldId));
	});
}

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
			} else if (!isValidHttpUrl(value)) {
				errorMessage = 'Please enter a valid URL that starts with http:// or https://';
				isValid = false;
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

function validateForm() {
	const fields = ['name', 'category', 'source', 'url'];
	let isValid = true;

	fields.forEach((fieldId) => {
		if (!validateField(fieldId)) {
			isValid = false;
		}
	});

	const description = document.getElementById('description').value;
	if (description.length > 500) {
		showFieldError('description', 'Description must be 500 characters or less');
		document.getElementById('description').classList.add('error');
		isValid = false;
	}

	if (!elements.turnstileResponse.value) {
		showError('Please complete the security verification');
		isValid = false;
	} else if (Date.now() - state.tokenIssuedAt > TURNSTILE_TOKEN_TTL_MS) {
		showError('Security verification expired. Please complete it again.');
		resetTurnstile();
		isValid = false;
	}

	return isValid;
}

function isValidHttpUrl(value) {
	try {
		const parsed = new URL(value);
		return ['http:', 'https:'].includes(parsed.protocol) && Boolean(parsed.hostname);
	} catch {
		return false;
	}
}

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

function setupFormSubmission() {
	elements.form.addEventListener('submit', async function (e) {
		e.preventDefault();

		if (state.isSubmitting) {
			return;
		}

		hideError();
		hideWarning();

		if (!validateForm()) {
			return;
		}

		await submitForm();
	});
}

async function submitForm() {
	state.isSubmitting = true;
	elements.submitBtn.classList.add('loading');
	setSubmitEnabled(false);

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
			handleSubmissionSuccess(data);
		} else {
			handleSubmissionError(data);
		}
	} catch (error) {
		console.error('Submission error:', error);
		showError('Network error. Please check your connection and try again.');
	} finally {
		state.isSubmitting = false;
		elements.submitBtn.classList.remove('loading');
		setSubmitEnabled(Boolean(elements.turnstileResponse.value));
	}
}

function handleSubmissionSuccess(data) {
	elements.form.reset();
	resetTurnstile();

	const existingResult = document.querySelector('.result-container');
	if (existingResult) {
		existingResult.remove();
	}

	const resultContainer = createElement('div', { className: 'result-container' });
	resultContainer.appendChild(createElement('h2', { text: 'Submission Successful' }));

	const details = createElement('div', { className: 'result-details' });
	const reportIdRow = createResultRow('Report ID');
	const code = createElement('span', { className: 'result-code', text: data.id || 'Unknown' });
	reportIdRow.appendChild(code);
	details.appendChild(reportIdRow);

	const apiResults = [
		{
			value: data.urlscan_uuid,
			name: 'URLScan.io Analysis',
			url: (id) => `https://urlscan.io/result/${encodeURIComponent(id)}/`,
			text: 'View detailed scan results',
		},
		{
			value: data.virustotal_scan_id,
			name: 'VirusTotal Scan',
			url: (id) => `https://www.virustotal.com/gui/url/${encodeURIComponent(id)}`,
			text: 'View malware analysis',
		},
		{
			value: data.cloudflare_scan_uuid,
			name: 'Cloudflare Radar Scan',
			url: (id) => `https://radar.cloudflare.com/scan/${encodeURIComponent(id)}/summary`,
			text: 'View security report',
		},
	];

	apiResults.forEach((result) => {
		if (!result.value) {
			return;
		}

		const row = createResultRow(result.name);
		const link = createElement('a', {
			text: result.text,
			attrs: {
				href: result.url(result.value),
				target: '_blank',
				rel: 'nofollow noopener noreferrer external',
			},
		});
		row.appendChild(link);
		details.appendChild(row);
	});

	if (Array.isArray(data.apiErrors) && data.apiErrors.length > 0) {
		const errorDetails = createElement('details', { className: 'api-error-details' });
		errorDetails.appendChild(createElement('summary', { text: `Some API calls had issues (${data.apiErrors.length})` }));

		const list = createElement('ul');
		data.apiErrors.forEach((error) => {
			const item = createElement('li');
			item.appendChild(createElement('strong', { text: `${error.api || 'API'}: ` }));
			item.appendChild(document.createTextNode(error.message || 'Unknown error'));
			list.appendChild(item);
		});
		errorDetails.appendChild(list);
		details.appendChild(errorDetails);
	}

	resultContainer.appendChild(details);
	elements.form.parentNode.insertBefore(resultContainer, elements.form.nextSibling);

	setTimeout(() => {
		resultContainer.scrollIntoView({ behavior: 'smooth', block: 'center' });
	}, 100);
}

function createResultRow(label) {
	const row = createElement('p');
	row.appendChild(createElement('strong', { text: label }));
	return row;
}

function handleSubmissionError(data) {
	const errorMsg = data.error || 'Submission failed. Please try again.';
	showError(errorMsg);

	if (data.code === 'INVALID_TURNSTILE' || errorMsg.toLowerCase().includes('turnstile')) {
		resetTurnstile();
	}
}

function setupAnimations() {
	if (window.matchMedia('(prefers-reduced-motion: reduce)').matches) {
		return;
	}

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

	document.querySelectorAll('.form-group, .quick-link').forEach((el, index) => {
		el.style.opacity = '0';
		el.style.transform = 'translateY(20px)';
		el.style.transition = 'opacity 0.5s ease, transform 0.5s ease';
		el.style.transitionDelay = `${index * 0.05}s`;
		observer.observe(el);
	});
}

document.addEventListener('visibilitychange', function () {
	if (!document.hidden && elements.turnstileResponse?.value && Date.now() - state.tokenIssuedAt > TURNSTILE_TOKEN_TTL_MS) {
		resetTurnstile();
	}
});

function createElement(tagName, options = {}) {
	const element = document.createElement(tagName);

	if (options.className) {
		element.className = options.className;
	}

	if (options.text !== undefined) {
		element.textContent = options.text;
	}

	if (options.attrs) {
		for (const [name, value] of Object.entries(options.attrs)) {
			element.setAttribute(name, value);
		}
	}

	return element;
}
