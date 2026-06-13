document.addEventListener('DOMContentLoaded', function () {
	const reportForm = document.getElementById('reportStatusForm');
	const reportIdInput = document.getElementById('reportId');
	const resultContainer = document.getElementById('reportResult');
	const errorMessage = document.getElementById('errorMessage');
	const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

	reportForm.addEventListener('submit', async function (e) {
		e.preventDefault();
		const reportId = reportIdInput.value.trim();

		if (!reportId) {
			showError('Please enter a Report ID.');
			return;
		}
		if (!UUID_RE.test(reportId)) {
			showError('Report ID must be a valid UUID.');
			return;
		}

		resultContainer.replaceChildren();
		errorMessage.style.display = 'none';
		resultContainer.style.display = 'none';

		const submitButton = reportForm.querySelector('button');
		submitButton.disabled = true;
		submitButton.textContent = 'Searching...';

		try {
			const response = await fetch(`/api/report/${encodeURIComponent(reportId)}`);
			const data = await response.json();

			if (response.ok) {
				displayReport(data);
			} else {
				showError(data.error || 'An unknown error occurred.');
			}
		} catch (error) {
			showError('Failed to fetch the report. Please check your network connection.');
		} finally {
			submitButton.disabled = false;
			submitButton.textContent = 'Check Status';
		}
	});

	function showError(message) {
		errorMessage.textContent = message;
		errorMessage.style.display = 'block';
	}

	function makeItem(label, value, opts) {
		const div = document.createElement('div');
		div.className = 'report-item' + (opts && opts.fullWidth ? ' full-width' : '');
		const strong = document.createElement('strong');
		strong.textContent = label;
		div.appendChild(strong);
		div.appendChild(document.createTextNode(String(value ?? '')));
		return div;
	}

	const APPROVAL_BADGES = {
		approved: { label: 'Approved', cls: 'badge-success' },
		denied: { label: 'Denied', cls: 'badge-danger' },
		expired: { label: 'Expired (no decision)', cls: 'badge-neutral' },
		pending: { label: 'Pending approval', cls: 'badge-pending' },
		workflow_failed: { label: 'Workflow failed', cls: 'badge-danger' },
	};

	const LIST_BADGES = {
		added: { label: 'Added to blocklist', cls: 'badge-success' },
		skipped_duplicate: { label: 'Already on blocklist', cls: 'badge-neutral' },
		failed: { label: 'Blocklist update failed', cls: 'badge-danger' },
		not_started: { label: 'Not started', cls: 'badge-neutral' },
	};

	function makeBadge(prefix, text, cls) {
		const badge = document.createElement('span');
		badge.className = 'status-badge ' + cls;
		const label = document.createElement('span');
		label.className = 'status-badge-label';
		label.textContent = prefix;
		badge.appendChild(label);
		badge.appendChild(document.createTextNode(text));
		return badge;
	}

	function makeSectionHeading(text) {
		const heading = document.createElement('h4');
		heading.className = 'report-section-heading';
		heading.textContent = text;
		return heading;
	}

	function formatTimestamp(value) {
		if (!value) return null;
		const date = new Date(value);
		return Number.isNaN(date.getTime()) ? String(value) : date.toLocaleString();
	}

	function makeJsonSummary(value) {
		if (!value) return 'N/A';
		try {
			const parsed = typeof value === 'string' ? JSON.parse(value) : value;
			const parts = [];
			if (parsed.risk_score !== undefined) parts.push(`Risk score: ${parsed.risk_score}`);
			if (parsed.unsafe !== undefined) parts.push(`Unsafe: ${parsed.unsafe ? 'Yes' : 'No'}`);
			if (parsed.phishing !== undefined) parts.push(`Phishing: ${parsed.phishing ? 'Yes' : 'No'}`);
			if (parsed.malware !== undefined) parts.push(`Malware: ${parsed.malware ? 'Yes' : 'No'}`);
			if (parsed.domain) parts.push(`Domain: ${parsed.domain}`);
			return parts.length ? parts.join(' | ') : 'Stored';
		} catch (_) {
			return 'Stored';
		}
	}

	function makeApiErrorsSummary(value) {
		if (!value) return 'N/A';
		try {
			const parsed = typeof value === 'string' ? JSON.parse(value) : value;
			if (Array.isArray(parsed)) {
				return parsed.map((item) => `${item.api || 'API'}: ${item.message || 'Unknown error'}`).join(' | ');
			}
		} catch (_) {}
		return String(value);
	}

	function providerName(value) {
		const names = {
			netcraft: 'Netcraft',
			cloudflare_abuse: 'Cloudflare Abuse',
			microsoft_msrc: 'Microsoft MSRC',
		};
		return names[value] || value || 'Provider';
	}

	function providerSummary(report) {
		const parts = [report.status || 'unknown'];
		if (report.reference_id) parts.push(`ref ${report.reference_id}`);
		if (report.eligibility_reason) parts.push(report.eligibility_reason);
		if (report.error) parts.push(report.error);
		return parts.join(' - ');
	}

	function displayReport(report) {
		resultContainer.replaceChildren();
		resultContainer.style.display = 'block';

		const heading = document.createElement('h3');
		heading.className = 'report-heading';
		heading.appendChild(document.createTextNode('Report '));
		const idSpan = document.createElement('span');
		idSpan.className = 'report-id';
		idSpan.textContent = report.id || '';
		heading.appendChild(idSpan);
		resultContainer.appendChild(heading);

		// Status badges first: the Discord approval outcome and the resulting
		// Cloudflare One blocklist state are the headline answer to "what
		// happened to my report?".
		const statusRow = document.createElement('div');
		statusRow.className = 'status-row';
		const approval = APPROVAL_BADGES[report.approval_status] || { label: report.approval_status || 'Unknown', cls: 'badge-neutral' };
		statusRow.appendChild(makeBadge('Approval', approval.label, approval.cls));
		if (report.approval_status === 'approved') {
			const list = LIST_BADGES[report.cloudflare_list_status] || { label: report.cloudflare_list_status || 'Unknown', cls: 'badge-neutral' };
			statusRow.appendChild(makeBadge('Blocklist', list.label, list.cls));
		}
		resultContainer.appendChild(statusRow);

		// Brief, non-revealing explanation of the Approval badge — enough for a
		// reporter to understand the status without exposing the review process.
		const hint = document.createElement('p');
		hint.className = 'status-hint';
		hint.textContent = 'Approval shows whether a reviewer has accepted this report for follow-up action.';
		resultContainer.appendChild(hint);

		const decidedAt = formatTimestamp(report.approval_decided_at);
		if (decidedAt) {
			const note = document.createElement('p');
			note.className = 'status-note';
			note.textContent = `Decision recorded ${decidedAt}`;
			resultContainer.appendChild(note);
		}

		resultContainer.appendChild(makeSectionHeading('Submission'));
		const grid = document.createElement('div');
		grid.className = 'report-grid';
		grid.appendChild(makeItem('Name', report.name));
		grid.appendChild(makeItem('Category', report.category));
		grid.appendChild(makeItem('Source', report.source));
		grid.appendChild(makeItem('Submission success', report.submission_success ? 'Yes' : 'No'));
		if (report.normalized_hostname) grid.appendChild(makeItem('Hostname', report.normalized_hostname));
		const submittedAt = formatTimestamp(report.timestamp);
		if (submittedAt) grid.appendChild(makeItem('Submitted', submittedAt));
		grid.appendChild(makeItem('URL', report.url, { fullWidth: true }));
		grid.appendChild(makeItem('Description', report.description || 'N/A', { fullWidth: true }));
		resultContainer.appendChild(grid);

		const analysis = document.createElement('div');
		analysis.className = 'report-grid';
		if (report.urlscan_uuid) analysis.appendChild(makeItem('URLScan UUID', report.urlscan_uuid));
		if (report.virustotal_scan_id) analysis.appendChild(makeItem('VirusTotal Scan ID', report.virustotal_scan_id));
		if (report.cloudflare_scan_uuid) analysis.appendChild(makeItem('Cloudflare Scan UUID', report.cloudflare_scan_uuid));
		if (report.ipqs_scan) analysis.appendChild(makeItem('IPQualityScore', makeJsonSummary(report.ipqs_scan), { fullWidth: true }));
		if (report.api_errors) analysis.appendChild(makeItem('API errors', makeApiErrorsSummary(report.api_errors), { fullWidth: true }));
		if (analysis.children.length > 0) {
			resultContainer.appendChild(makeSectionHeading('Analysis results'));
			resultContainer.appendChild(analysis);
		}

		if (Array.isArray(report.provider_reports) && report.provider_reports.length > 0) {
			resultContainer.appendChild(makeSectionHeading('Provider reporting'));
			const providerGrid = document.createElement('div');
			providerGrid.className = 'report-grid';
			report.provider_reports.forEach((providerReport) => {
				providerGrid.appendChild(makeItem(providerName(providerReport.provider), providerSummary(providerReport), { fullWidth: true }));
			});
			resultContainer.appendChild(providerGrid);
		}

		appendReportActions(report);

		// Move focus to the result so keyboard and screen-reader users land on it.
		resultContainer.focus();
	}

	function makeActionLink(text, href, variant) {
		const link = document.createElement('a');
		link.className = 'report-cta-link ' + variant;
		link.textContent = text;
		link.href = href;
		link.target = '_blank';
		link.rel = 'nofollow noopener noreferrer external';
		return link;
	}

	// Reminds the reporter that reporting directly to the providers involved
	// (host, registrar, Google) is usually the fastest path to takedown.
	function appendReportActions(report) {
		const section = document.createElement('div');
		section.className = 'report-cta';

		const title = document.createElement('h4');
		title.className = 'report-cta-title';
		title.textContent = 'Report it directly to speed up takedown';
		section.appendChild(title);

		const desc = document.createElement('p');
		desc.className = 'report-cta-text';
		desc.textContent =
			'Blocklists take time to propagate. Reporting straight to the hosting provider, the domain registrar, and Google Safe Browsing is often the fastest way to get a malicious site removed.';
		section.appendChild(desc);

		const actions = document.createElement('div');
		actions.className = 'report-cta-actions';
		if (report.url) {
			actions.appendChild(
				makeActionLink(
					'Report to Google Safe Browsing →',
					`https://safebrowsing.google.com/safebrowsing/report_phish/?hl=en&url=${encodeURIComponent(report.url)}`,
					'primary'
				)
			);
		}
		actions.appendChild(
			makeActionLink(
				'Find hosting & registrar abuse contacts →',
				report.url ? `https://phish.report/analysis?url=${encodeURIComponent(report.url)}` : 'https://phish.report/',
				'secondary'
			)
		);
		section.appendChild(actions);

		const note = document.createElement('p');
		note.className = 'report-cta-note';
		note.textContent = 'More reporting destinations are listed higher up on this page.';
		section.appendChild(note);

		resultContainer.appendChild(section);
	}
});
