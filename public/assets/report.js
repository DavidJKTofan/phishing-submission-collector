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
		strong.textContent = label + ' ';
		div.appendChild(strong);
		div.appendChild(document.createTextNode(String(value ?? '')));
			return div;
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

	function displayReport(report) {
		resultContainer.replaceChildren();
		resultContainer.style.display = 'block';

		const heading = document.createElement('h3');
		heading.textContent = `Report Details (ID: ${report.id || ''})`;
		resultContainer.appendChild(heading);

		const grid = document.createElement('div');
		grid.className = 'report-grid';
		grid.appendChild(makeItem('Name:', report.name));
		grid.appendChild(makeItem('Category:', report.category));
		grid.appendChild(makeItem('Source:', report.source));
		grid.appendChild(makeItem('URL:', report.url, { fullWidth: true }));
		grid.appendChild(makeItem('Description:', report.description || 'N/A', { fullWidth: true }));
		grid.appendChild(makeItem('Submission Success:', report.submission_success ? 'Yes' : 'No'));
		resultContainer.appendChild(grid);

			if (report.urlscan_uuid) resultContainer.appendChild(makeItem('URLScan UUID:', report.urlscan_uuid));
			if (report.virustotal_scan_id) resultContainer.appendChild(makeItem('VirusTotal Scan ID:', report.virustotal_scan_id));
			if (report.ipqs_scan) resultContainer.appendChild(makeItem('IPQualityScore:', makeJsonSummary(report.ipqs_scan), { fullWidth: true }));
			if (report.cloudflare_scan_uuid) resultContainer.appendChild(makeItem('Cloudflare Scan UUID:', report.cloudflare_scan_uuid));
			if (report.api_errors) resultContainer.appendChild(makeItem('API Errors:', makeApiErrorsSummary(report.api_errors), { fullWidth: true }));
		}
	});
