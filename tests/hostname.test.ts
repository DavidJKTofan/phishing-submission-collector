import assert from 'node:assert/strict';
import { it as test } from 'vitest';

import { HostnameNormalizationError, buildScanUrl, normalizeReportedHostname } from '../src/hostname';

test('normalizes full URLs to exact hostnames', () => {
	assert.equal(normalizeReportedHostname('https://Login.Bad.Example/path?x=1'), 'login.bad.example');
	assert.equal(normalizeReportedHostname('http://login.bad.example:8080/a'), 'login.bad.example');
});

test('normalizes bare hostnames and trailing dots', () => {
	assert.equal(normalizeReportedHostname('Login.Bad.Example.'), 'login.bad.example');
	assert.equal(normalizeReportedHostname('login.bad.example/path?q=1'), 'login.bad.example');
});

test('normalizes IDNs through URL parsing', () => {
	assert.equal(normalizeReportedHostname('https://bücher.example/path'), 'xn--bcher-kva.example');
});

test('builds scan URLs without credentials', () => {
	assert.equal(buildScanUrl('login.bad.example/path?q=1', 'login.bad.example'), 'https://login.bad.example/path?q=1');
	assert.equal(buildScanUrl('https://user:pass@login.bad.example/path', 'login.bad.example'), 'https://login.bad.example/path');
});

test('rejects disallowed hostnames', () => {
	const invalidValues = ['localhost', '*.bad.example', 'bad.*.example', '192.0.2.1', 'https://[2001:db8::1]/', 'bad..example', '-bad.example'];

	for (const value of invalidValues) {
		assert.throws(() => normalizeReportedHostname(value), HostnameNormalizationError, value);
	}
});

test('rejects labels over 63 characters', () => {
	const longLabel = `${'a'.repeat(64)}.example`;
	assert.throws(() => normalizeReportedHostname(longLabel), HostnameNormalizationError);
});
