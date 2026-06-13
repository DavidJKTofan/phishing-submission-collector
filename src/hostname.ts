const MAX_HOSTNAME_LENGTH = 253;
const MAX_LABEL_LENGTH = 63;
const LABEL_REGEX = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;
const IPV4_REGEX = /^(?:\d{1,3}\.){3}\d{1,3}$/;

export class HostnameNormalizationError extends Error {
	constructor(message: string) {
		super(message);
		this.name = 'HostnameNormalizationError';
	}
}

export function normalizeReportedHostname(input: string): string {
	const trimmed = input.trim();
	if (!trimmed) throw new HostnameNormalizationError('Hostname is required');

	const hostname = extractHostname(trimmed).toLowerCase().replace(/\.+$/, '');
	validateHostname(hostname);
	return hostname;
}

export function buildScanUrl(input: string, normalizedHostname: string): string {
	const trimmed = input.trim();
	try {
		const parsedUrl = new URL(/^[a-z][a-z0-9+.-]*:\/\//i.test(trimmed) ? trimmed : `https://${trimmed}`);
		if (!['http:', 'https:'].includes(parsedUrl.protocol)) return `https://${normalizedHostname}/`;
		parsedUrl.username = '';
		parsedUrl.password = '';
		return parsedUrl.href;
	} catch {
		return `https://${normalizedHostname}/`;
	}
}

function extractHostname(input: string): string {
	try {
		if (/^[a-z][a-z0-9+.-]*:\/\//i.test(input)) {
			const parsedUrl = new URL(input);
			if (!['http:', 'https:'].includes(parsedUrl.protocol)) {
				throw new HostnameNormalizationError('URL must use http:// or https://');
			}
			return parsedUrl.hostname;
		}

		return new URL(`https://${input}`).hostname;
	} catch (error) {
		if (error instanceof HostnameNormalizationError) throw error;
		throw new HostnameNormalizationError('Invalid hostname format');
	}
}

function validateHostname(hostname: string): void {
	if (!hostname || hostname.length > MAX_HOSTNAME_LENGTH) {
		throw new HostnameNormalizationError('Invalid hostname length');
	}
	if (hostname === 'localhost') {
		throw new HostnameNormalizationError('localhost is not allowed');
	}
	if (hostname.startsWith('*.') || hostname.includes('*')) {
		throw new HostnameNormalizationError('Wildcard hostnames are not allowed');
	}
	if (hostname.includes(':') || IPV4_REGEX.test(hostname) || isIpv4MappedHostname(hostname)) {
		throw new HostnameNormalizationError('IP addresses are not allowed');
	}

	const labels = hostname.split('.');
	if (labels.length < 2 || labels.some((label) => label.length === 0 || label.length > MAX_LABEL_LENGTH || !LABEL_REGEX.test(label))) {
		throw new HostnameNormalizationError('Invalid hostname label');
	}
}

function isIpv4MappedHostname(hostname: string): boolean {
	if (!IPV4_REGEX.test(hostname)) return false;
	return hostname.split('.').every((part) => {
		const value = Number(part);
		return Number.isInteger(value) && value >= 0 && value <= 255;
	});
}
