const state = {
	turnstileWidget: null,
	turnstileLoaded: false,
	isSubmitting: false,
	retryCount: 0,
	maxRetries: 3,
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

	if (window.turnstile && !state.turnstileWidget) {
		renderTurnstileWidget();
	}

	setTimeout(() => {
		if (!state.turnstileLoaded) {
			console.error('Turnstile failed to load within timeout');
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
}

function renderTurnstileWidget() {
	if (typeof turnstile === 'undefined' || !window.turnstile) {
		console.error('Turnstile library not available');
		showTurnstileError('Security verification not available. Please refresh the page.');
		return;
	}

	if (state.turnstileWidget) {
		try {
			turnstile.remove(state.turnstileWidget);
		} catch (e) {
			console.warn('Error removing Turnstile widget:', e);
		}
		state.turnstileWidget = null;
	}

	hideTurnstileError();

	const sitekey = elements.turnstileContainer?.dataset?.sitekey;
	if (!sitekey) {
		console.error('Missing data-sitekey on Turnstile container');
		showTurnstileError('Security verification misconfigured.');
		return;
	}

	try {
		state.turnstileWidget = turnstile.render('#turnstile-container', {
			sitekey,
			action: 'submit-report',
			theme: 'auto',
			size: 'normal',
			callback: handleTurnstileSuccess,
			'expired-callback': handleTurnstileExpired,
			'error-callback': handleTurnstileError,
			'timeout-callback': handleTurnstileTimeout,
			'unsupported-callback': handleTurnstileUnsupported,
		});

		state.turnstileLoaded = true;
		state.retryCount = 0;
	} catch (error) {
		console.error('Error rendering Turnstile:', error);
		handleTurnstileError();
	}
}

function handleTurnstileSuccess(token) {
	elements.turnstileResponse.value = token;
	elements.submitBtn.disabled = false;
	hideTurnstileError();
	hideError();
}

function handleTurnstileExpired() {
	elements.turnstileResponse.value = '';
	elements.submitBtn.disabled = true;
	showTurnstileError('Security verification expired. Refreshing…');
	resetTurnstile();
}

function handleTurnstileError() {
	elements.turnstileResponse.value = '';
	elements.submitBtn.disabled = true;

	if (state.retryCount < state.maxRetries) {
		state.retryCount++;
		showTurnstileError(`Security verification failed. Retrying (${state.retryCount}/${state.maxRetries})…`);
		setTimeout(renderTurnstileWidget, 2000);
	} else {
		showTurnstileError('Security verification unavailable. Please refresh the page.');
	}
}

function handleTurnstileTimeout() {
	elements.turnstileResponse.value = '';
	elements.submitBtn.disabled = true;
	showTurnstileError('Security verification timed out. Refreshing…');
	resetTurnstile();
}

function handleTurnstileUnsupported() {
	console.error('Turnstile not supported');
	showTurnstileError('Security verification not supported in this browser.');
}

function showTurnstileError(message) {
	elements.turnstileError.textContent = message;
	elements.turnstileError.style.display = 'block';
}

function hideTurnstileError() {
	elements.turnstileError.style.display = 'none';
}

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
			renderTurnstileWidget();
		}
	} else {
		renderTurnstileWidget();
	}
}

function setupFormValidation() {
	const urlInput = document.getElementById('url');
	urlInput.addEventListener('blur', () => validateField('url'));
	urlInput.addEventListener('input', () => clearFieldError('url'));

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

function isValidHttpUrl(value) {
	if (!value || value.length > 2048) return false;
	let parsed;
	try {
		parsed = new URL(value);
	} catch {
		return false;
	}
	return parsed.protocol === 'http:' || parsed.protocol === 'https:';
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
				errorMessage = 'Please enter a valid URL (must start with http:// or https://)';
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
		if (!validateField(fieldId)) isValid = false;
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
	}

	return isValid;
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
	if (errorElement) errorElement.style.display = 'none';
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

function hideWarning() {
	elements.warningMessage.style.display = 'none';
}

function setupFormSubmission() {
	elements.form.addEventListener('submit', async function (e) {
		e.preventDefault();
		if (state.isSubmitting) return;
		hideError();
		hideWarning();
		if (!validateForm()) return;
		await submitForm();
	});
}

async function submitForm() {
	state.isSubmitting = true;
	elements.submitBtn.disabled = true;
	elements.submitBtn.classList.add('loading');

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
			headers: { 'Content-Type': 'application/json' },
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
		elements.submitBtn.disabled = false;
	}
}

function buildResultRow(label, value, { mono = false } = {}) {
	const p = document.createElement('p');
	const strong = document.createElement('strong');
	strong.textContent = label;
	p.appendChild(strong);

	const span = document.createElement('span');
	if (mono) span.className = 'result-mono';
	span.textContent = value;
	p.appendChild(span);
	return p;
}

function buildResultLink(label, href, linkText) {
	const p = document.createElement('p');
	const strong = document.createElement('strong');
	strong.textContent = label;
	p.appendChild(strong);

	const a = document.createElement('a');
	a.href = href;
	a.target = '_blank';
	a.rel = 'nofollow noreferrer noopener external';
	a.textContent = linkText;
	p.appendChild(a);
	return p;
}

function handleSubmissionSuccess(data) {
	elements.form.reset();
	resetTurnstile();

	document.querySelector('.result-container')?.remove();

	const resultContainer = document.createElement('div');
	resultContainer.className = 'result-container';

	const heading = document.createElement('h2');
	heading.textContent = '✅ Submission Successful!';
	resultContainer.appendChild(heading);

	const details = document.createElement('div');
	details.className = 'result-details';
	details.appendChild(buildResultRow('Report ID', String(data.id || ''), { mono: true }));

	if (data.urlscan_uuid) {
		details.appendChild(
			buildResultLink('URLScan.io Analysis', `https://urlscan.io/result/${encodeURIComponent(data.urlscan_uuid)}/`, 'View detailed scan results →')
		);
	}
	if (data.virustotal_scan_id) {
		details.appendChild(
			buildResultLink(
				'VirusTotal Scan',
				`https://www.virustotal.com/gui/url/${encodeURIComponent(data.virustotal_scan_id)}`,
				'View malware analysis →'
			)
		);
	}
	if (data.cloudflare_scan_uuid) {
		details.appendChild(
			buildResultLink(
				'Cloudflare Radar Scan',
				`https://radar.cloudflare.com/scan/${encodeURIComponent(data.cloudflare_scan_uuid)}/summary`,
				'View security report →'
			)
		);
	}

	if (Array.isArray(data.apiErrors) && data.apiErrors.length > 0) {
		const detailsEl = document.createElement('details');
		detailsEl.className = 'result-api-errors';
		const summary = document.createElement('summary');
		summary.textContent = `⚠️ Some API calls had issues (${data.apiErrors.length})`;
		detailsEl.appendChild(summary);

		const ul = document.createElement('ul');
		data.apiErrors.forEach((err) => {
			const li = document.createElement('li');
			const apiName = document.createElement('strong');
			apiName.textContent = `${err.api}: `;
			li.appendChild(apiName);
			li.appendChild(document.createTextNode(String(err.message || '')));
			ul.appendChild(li);
		});
		detailsEl.appendChild(ul);
		details.appendChild(detailsEl);
	}

	resultContainer.appendChild(details);
	elements.form.parentNode.insertBefore(resultContainer, elements.form.nextSibling);

	setTimeout(() => resultContainer.scrollIntoView({ behavior: 'smooth', block: 'center' }), 100);
}

function handleSubmissionError(data) {
	const errorMsg = data.error || 'Submission failed. Please try again.';
	showError(errorMsg);
	if (data.code === 'INVALID_TURNSTILE' || errorMsg.toLowerCase().includes('turnstile')) {
		resetTurnstile();
	}
}

function setupAnimations() {
	if (window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches) return;

	const targets = document.querySelectorAll('.form-group, .quick-link');
	targets.forEach((el) => {
		el.style.opacity = '0';
		el.style.transform = 'translateY(20px)';
		el.style.transition = 'opacity 0.5s ease, transform 0.5s ease';
	});

	requestAnimationFrame(() => {
		targets.forEach((el, index) => {
			setTimeout(() => {
				el.style.opacity = '1';
				el.style.transform = 'translateY(0)';
			}, index * 50);
		});
	});
}

document.addEventListener('visibilitychange', function () {
	if (!document.hidden && state.turnstileLoaded && window.turnstile) {
		if (!elements.turnstileResponse.value) {
			setTimeout(() => {
				if (!elements.turnstileResponse.value) resetTurnstile();
			}, 1000);
		}
	}
});
