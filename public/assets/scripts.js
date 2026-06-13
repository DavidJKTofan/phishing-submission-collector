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
	submitHint: null,
	turnstileContainer: null,
	turnstileError: null,
	turnstileResponse: null,
};

window.onloadTurnstileCallback = function () {
	state.turnstileLoaded = true;
	renderTurnstileWidget();
};

function currentSiteTheme() {
	return document.documentElement.getAttribute('data-theme') === 'dark' ? 'dark' : 'light';
}

// Keep the Turnstile widget's theme in sync with the site theme toggle.
// Turnstile has no live "set theme" API, so we re-render the widget. We do
// this even if a token is already held: the managed challenge re-issues a
// token automatically (usually without interaction), so this matches the
// old live theme-switching behavior. We clear the stale token first and let
// the success callback re-enable submission once the new widget completes.
document.addEventListener('themechange', function () {
	if (!window.turnstile || state.turnstileWidget === null) return;
	try {
		window.turnstile.remove(state.turnstileWidget);
		state.turnstileWidget = null;
		clearTurnstileToken();
		renderTurnstileWidget();
	} catch (error) {
		console.error('Error re-rendering Turnstile after theme change:', error);
	}
});

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
	elements.submitHint = document.getElementById('submit-hint');
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

	const sitekey = elements.turnstileContainer.dataset.sitekey;
	if (!sitekey) {
		console.error('Missing data-sitekey on Turnstile container');
		showTurnstileError('Security verification misconfigured.');
		return;
	}

	try {
		state.turnstileWidget = window.turnstile.render('#turnstile-container', {
			sitekey,
			action: 'submit-report',
			// Follow the site's manual theme toggle rather than the OS setting.
			theme: currentSiteTheme(),
			size: 'flexible',
			retry: 'auto',
			'retry-interval': 8000,
			'refresh-expired': 'manual',
			'refresh-timeout': 'manual',
			'response-field': false,
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
	if (!elements.submitHint) return;
	if (state.isSubmitting) {
		elements.submitHint.textContent = 'Submitting report...';
	} else if (enabled) {
		elements.submitHint.textContent = 'Security check complete. You can submit the report.';
	} else {
		elements.submitHint.textContent = 'Complete the security check above to enable submission.';
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

function isValidUrlOrHostname(value) {
	if (!value || value.length > 2048) return false;
	try {
		const parsed = new URL(/^[a-z][a-z0-9+.-]*:\/\//i.test(value) ? value : `https://${value}`);
		const hostname = parsed.hostname.toLowerCase().replace(/\.+$/, '');
		return (
			['http:', 'https:'].includes(parsed.protocol) &&
			hostname.includes('.') &&
			hostname !== 'localhost' &&
			!hostname.includes('*') &&
			!hostname.includes(':') &&
			!/^\d{1,3}(?:\.\d{1,3}){3}$/.test(hostname) &&
			hostname.length <= 253 &&
			hostname.split('.').every((label) => label && label.length <= 63 && /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(label))
		);
	} catch {
		return false;
	}
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
				errorMessage = 'URL or domain is required';
				isValid = false;
			} else if (!isValidUrlOrHostname(value)) {
				errorMessage = 'Please enter a valid URL or hostname';
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
	let firstInvalidField = null;

	fields.forEach((fieldId) => {
		if (!validateField(fieldId)) firstInvalidField = firstInvalidField || fieldId;
	});

	const description = document.getElementById('description').value;
	if (description.length > 500) {
		showFieldError('description', 'Description must be 500 characters or less');
		document.getElementById('description').classList.add('error');
		firstInvalidField = firstInvalidField || 'description';
	}

	// Move focus to the first invalid field so keyboard and screen-reader
	// users land on the problem instead of staying on the submit button.
	if (firstInvalidField) {
		document.getElementById(firstInvalidField).focus();
		return false;
	}

	let isValid = true;

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

function showFieldError(fieldId, message) {
	const errorElement = document.getElementById(`${fieldId}-error`);
	if (errorElement) {
		errorElement.textContent = message;
		errorElement.style.display = 'block';
	}
	document.getElementById(fieldId).setAttribute('aria-invalid', 'true');
}

function clearFieldError(fieldId) {
	const errorElement = document.getElementById(`${fieldId}-error`);
	if (errorElement) errorElement.style.display = 'none';
	const field = document.getElementById(fieldId);
	field.classList.remove('error');
	field.removeAttribute('aria-invalid');
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
	elements.submitBtn.classList.add('loading');
	setSubmitEnabled(false);

	// The UI presents positive "run this service" toggles; the API expects
	// inverted skip_* flags.
	const formData = {
		name: document.getElementById('name').value.trim(),
		category: document.getElementById('category').value,
		source: document.getElementById('source').value,
		url: document.getElementById('url').value.trim(),
		description: document.getElementById('description').value.trim(),
		skip_urlscan: !document.getElementById('run_urlscan').checked,
		skip_virustotal: !document.getElementById('run_virustotal').checked,
		skip_ipqualityscore: !document.getElementById('run_ipqualityscore').checked,
		skip_cloudflare: !document.getElementById('run_cloudflare').checked,
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
		setSubmitEnabled(Boolean(elements.turnstileResponse.value));
	}
}

function createElement(tagName, options = {}) {
	const element = document.createElement(tagName);
	if (options.className) element.className = options.className;
	if (options.text !== undefined) element.textContent = options.text;
	if (options.attrs) {
		for (const [name, value] of Object.entries(options.attrs)) {
			element.setAttribute(name, value);
		}
	}
	return element;
}

function createResultRow(label) {
	const row = createElement('p');
	row.appendChild(createElement('strong', { text: label }));
	return row;
}

function handleSubmissionSuccess(data) {
	elements.form.reset();
	resetTurnstile();

	document.querySelector('.result-container')?.remove();

	const resultContainer = createElement('div', { className: 'result-container' });
	resultContainer.appendChild(createElement('h2', { text: '✅ Submission Successful!' }));

	const details = createElement('div', { className: 'result-details' });
	const reportIdRow = createResultRow('Report ID');
	reportIdRow.appendChild(createElement('span', { className: 'result-mono', text: data.id || 'Unknown' }));
	details.appendChild(reportIdRow);

	if (data.submitted_url) {
		// Google does not offer an API for phishing submissions, so the reporter
		// must finish this step manually. Make it the prominent next action.
		const cta = createElement('div', { className: 'result-cta' });

		const ctaTitle = createElement('h3', { className: 'result-cta-title' });
		ctaTitle.appendChild(createElement('span', { className: 'result-cta-icon', text: '👉', attrs: { 'aria-hidden': 'true' } }));
		ctaTitle.appendChild(document.createTextNode('One more step: report to Google Safe Browsing'));
		cta.appendChild(ctaTitle);

		// A <div> (not <p>) so the generic `.result-details p` card styling
		// does not apply to this explanatory text.
		cta.appendChild(
			createElement('div', {
				className: 'result-cta-text',
				text: 'Google requires phishing URLs to be submitted manually. Open the pre-filled report form to help protect Chrome, Android, and Gmail users.',
			})
		);

		cta.appendChild(
			createElement('a', {
				className: 'result-cta-button',
				text: 'Report to Google Safe Browsing →',
				attrs: {
					href: `https://safebrowsing.google.com/safebrowsing/report_phish/?hl=en&url=${encodeURIComponent(data.submitted_url)}`,
					target: '_blank',
					rel: 'nofollow noopener noreferrer external',
				},
			})
		);

		details.appendChild(cta);
	}

	renderAbuseContacts(details, data);

	const apiResults = [
		{
			value: data.urlscan_uuid,
			name: 'URLScan.io Analysis',
			url: (id) => `https://urlscan.io/result/${encodeURIComponent(id)}/`,
			text: 'View detailed scan results →',
		},
		{
			value: data.virustotal_scan_id,
			name: 'VirusTotal Scan',
			url: (id) => `https://www.virustotal.com/gui/url/${encodeURIComponent(id)}`,
			text: 'View malware analysis →',
		},
		{
			value: data.cloudflare_scan_uuid,
			name: 'Cloudflare Radar Scan',
			url: (id) => `https://radar.cloudflare.com/scan/${encodeURIComponent(id)}/summary`,
			text: 'View security report →',
		},
	];

	apiResults.forEach((result) => {
		if (!result.value) return;
		const row = createResultRow(result.name);
		row.appendChild(
			createElement('a', {
				text: result.text,
				attrs: {
					href: result.url(result.value),
					target: '_blank',
					rel: 'nofollow noopener noreferrer external',
				},
			})
		);
		details.appendChild(row);
	});

	if (Array.isArray(data.apiErrors) && data.apiErrors.length > 0) {
		const errorDetails = createElement('details', { className: 'result-api-errors' });
		errorDetails.appendChild(createElement('summary', { text: `⚠️ Some API calls had issues (${data.apiErrors.length})` }));
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
	// Focusable so we can move screen-reader/keyboard focus to the outcome.
	resultContainer.setAttribute('tabindex', '-1');
	elements.form.parentNode.insertBefore(resultContainer, elements.form.nextSibling);

	setTimeout(() => {
		resultContainer.scrollIntoView({ behavior: 'smooth', block: 'center' });
		resultContainer.focus({ preventScroll: true });
	}, 100);
}

// Renders an optional "notify the provider's abuse contact" call-to-action when
// the backend resolved a registrar and/or hosting abuse email via RDAP. Each
// becomes a pre-filled mailto so the reporter can escalate directly.
function renderAbuseContacts(details, data) {
	const contacts = data.abuse_contacts;
	if (!contacts || (!contacts.registrar && !contacts.host)) return;

	const section = createElement('div', { className: 'result-contacts' });

	const title = createElement('h3', { className: 'result-contacts-title' });
	title.appendChild(createElement('span', { className: 'result-contacts-icon', text: '📨', attrs: { 'aria-hidden': 'true' } }));
	title.appendChild(document.createTextNode('Notify the provider abuse contacts'));
	section.appendChild(title);

	section.appendChild(
		createElement('div', {
			className: 'result-contacts-text',
			text: 'If you have confirmed this is malicious, you can also email the hosting and registrar abuse contacts on record. Reporting to the provider is often the fastest route to takedown.',
		})
	);

	const list = createElement('div', { className: 'result-contacts-list' });
	[
		{ contact: contacts.registrar, role: 'Registrar abuse' },
		{ contact: contacts.host, role: 'Hosting abuse' },
	].forEach((entry) => {
		if (!entry.contact || !entry.contact.email) return;
		list.appendChild(buildAbuseContactButton(entry.role, entry.contact, data));
	});

	section.appendChild(list);
	details.appendChild(section);
}

function buildAbuseContactButton(role, contact, data) {
	const subject = `Phishing/abuse report: ${data.normalized_hostname || data.submitted_url || ''}`;
	const body = [
		'Hello,',
		'',
		'I am reporting a suspected phishing / malicious website associated with your service:',
		'',
		`URL: ${data.submitted_url || ''}`,
		`Hostname: ${data.normalized_hostname || ''}`,
		`Report reference: ${data.id || ''}`,
		'',
		'Please investigate and take appropriate action.',
		'',
		'Thank you.',
	].join('\n');
	const href = `mailto:${contact.email}?subject=${encodeURIComponent(subject)}&body=${encodeURIComponent(body)}`;

	const link = createElement('a', { className: 'result-contact-button', attrs: { href } });
	link.appendChild(createElement('span', { className: 'result-contact-role', text: role }));
	const target = contact.name ? `${contact.name} · ${contact.email}` : contact.email;
	link.appendChild(createElement('span', { className: 'result-contact-email', text: target }));
	return link;
}

function handleSubmissionError(data) {
	const errorMsg = data.error || 'Submission failed. Please try again.';
	showError(errorMsg);
	resetTurnstile();
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
	if (!document.hidden && elements.turnstileResponse?.value && Date.now() - state.tokenIssuedAt > TURNSTILE_TOKEN_TTL_MS) {
		resetTurnstile();
	}
});
