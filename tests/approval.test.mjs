import assert from 'node:assert/strict';
import test, { afterEach, before } from 'node:test';

import {
	addHostnameToCloudflareOneList,
	handleDiscordInteraction,
	sendDiscordApprovalMessage,
} from '/private/tmp/phishing-submission-collector-tests/src/approval.js';

const originalFetch = globalThis.fetch;
let keyPair;
let publicKeyHex;

before(async () => {
	keyPair = await crypto.subtle.generateKey({ name: 'Ed25519' }, true, ['sign', 'verify']);
	const publicKey = await crypto.subtle.exportKey('raw', keyPair.publicKey);
	publicKeyHex = toHex(publicKey);
});

afterEach(() => {
	globalThis.fetch = originalFetch;
});

test('answers Discord PING interactions', async () => {
	const env = makeDiscordEnv(makeWorkflowInstance('waiting'));
	const response = await handleDiscordInteraction(await signedDiscordRequest({ type: 1 }), env);

	assert.equal(response.status, 200);
	assert.deepEqual(await response.json(), { type: 1 });
});

test('sends approval event for Discord approve button', async () => {
	const instance = makeWorkflowInstance('waiting');
	const env = makeDiscordEnv(instance);
	const response = await handleDiscordInteraction(
		await signedDiscordRequest({
			id: 'interaction-1',
			type: 3,
			data: { custom_id: 'approve:workflow-1' },
			member: { user: { id: 'user-1', username: 'alice' } },
			message: { id: 'message-1', content: 'Approval request' },
		}),
		env
	);

	const body = await response.json();
	assert.equal(response.status, 200);
	assert.equal(body.type, 7);
	assert.equal(body.data.flags, 4);
	assert.equal(instance.events.length, 1);
	assert.deepEqual(instance.events[0], {
		type: 'hostname-approval',
		payload: {
			approved: true,
			actorId: 'user-1',
			actorUsername: 'alice',
			messageId: 'message-1',
			interactionId: 'interaction-1',
		},
	});
	assert.match(body.data.content, /Decision:\*\* Approved/);
});

test('sends denial event for Discord deny button', async () => {
	const instance = makeWorkflowInstance('running');
	const env = makeDiscordEnv(instance);
	const response = await handleDiscordInteraction(
		await signedDiscordRequest({
			id: 'interaction-2',
			type: 3,
			data: { custom_id: 'deny:workflow-1' },
			user: { id: 'user-2', global_name: 'Bob' },
			message: { id: 'message-2', content: 'Approval request' },
		}),
		env
	);

	const body = await response.json();
	assert.equal(response.status, 200);
	assert.equal(body.type, 7);
	assert.equal(body.data.flags, 4);
	assert.equal(instance.events[0].payload.approved, false);
	assert.equal(instance.events[0].payload.actorUsername, 'Bob');
	assert.match(body.data.content, /Decision:\*\* Denied/);
});

test('defers Discord button clicks when execution context is available', async () => {
	const instance = makeWorkflowInstance('waiting');
	const env = makeDiscordEnv(instance);
	const waitUntilPromises = [];
	const calls = mockFetch(() => jsonResponse({}));
	const response = await handleDiscordInteraction(
		await signedDiscordRequest({
			id: 'interaction-3',
			application_id: 'app-1',
			token: 'interaction-token',
			type: 3,
			data: { custom_id: 'approve:workflow-1' },
			member: { user: { id: 'user-3', username: 'carol' } },
			message: { id: 'message-3', content: 'Approval request' },
		}),
		env,
		{ waitUntil: (promise) => waitUntilPromises.push(promise) }
	);

	assert.equal(response.status, 200);
	assert.deepEqual(await response.json(), { type: 6 });
	assert.equal(waitUntilPromises.length, 1);
	await Promise.all(waitUntilPromises);
	assert.equal(instance.events.length, 1);
	assert.equal(instance.events[0].payload.approved, true);
	assert.equal(calls[0].url, 'https://discord.com/api/v10/webhooks/app-1/interaction-token/messages/@original');
	assert.equal(calls[0].init.method, 'PATCH');
	const updateBody = JSON.parse(calls[0].init.body);
	assert.equal(updateBody.flags, 4);
	assert.match(updateBody.content, /Decision:\*\* Approved/);
});

test('sends formatted Discord approval messages with scanner report links', async () => {
	const calls = mockFetch(() => jsonResponse({ id: 'discord-message-1' }));
	const report = {
		reportId: '60e1a458-4ad0-44c4-a4be-d211bb321d7a',
		name: 'Ali Anza portal',
		category: 'Phishing',
		source: 'Website',
		submittedUrl: 'https://portalalianza.azurewebsites.net/',
		normalizedHostname: 'portalalianza.azurewebsites.net',
		description: 'Impersonating a financial institution.',
		urlscanUuid: '019cf7ef-8a8c-7618-a8c1-cd3b11390427',
		virustotalScanId: 'aHR0cHM6Ly9wb3J0YWxhbGlhbnphLmF6dXJld2Vic2l0ZXMubmV0Lw',
		cloudflareScanUuid: '095be615-a8ad-4c33-8e9c-c7612fbf6c9f',
	};

	const result = await sendDiscordApprovalMessage(makeDiscordEnv(makeWorkflowInstance('waiting')), report, 'workflow-1');
	const body = JSON.parse(calls[0].init.body);

	assert.deepEqual(result, { id: 'discord-message-1' });
	assert.equal(calls[0].url, 'https://discord.com/api/v10/channels/channel-1/messages');
	assert.match(body.content, /\*\*Phishing hostname approval required\*\*/);
	assert.match(body.content, /\*\*Submission\*\*/);
	assert.match(body.content, /\*\*Review links\*\*/);
	assert.match(body.content, /https:\/\/radar.cloudflare.com\/scan\/095be615-a8ad-4c33-8e9c-c7612fbf6c9f\/summary/);
	assert.match(body.content, /https:\/\/urlscan.io\/result\/019cf7ef-8a8c-7618-a8c1-cd3b11390427\//);
	assert.match(body.content, /https:\/\/www.virustotal.com\/gui\/url\/aHR0cHM6Ly9wb3J0YWxhbGlhbnphLmF6dXJld2Vic2l0ZXMubmV0Lw/);
	assert.equal(body.flags, 4);
	assert.deepEqual(body.allowed_mentions, { parse: [] });
	assert.equal(body.components[0].components[0].custom_id, 'approve:workflow-1');
});

test('rejects Discord interactions with invalid signatures', async () => {
	const env = makeDiscordEnv(makeWorkflowInstance('waiting'));
	const response = await handleDiscordInteraction(
		await signedDiscordRequest({ type: 3, data: { custom_id: 'approve:workflow-1' } }, { signature: '00'.repeat(64) }),
		env
	);

	assert.equal(response.status, 401);
	assert.equal(await response.text(), 'invalid request signature');
});

test('returns a server error when Discord public key secret is missing', async () => {
	const env = makeDiscordEnv(makeWorkflowInstance('waiting'));
	delete env.DISCORD_APPLICATION_PUBLIC_KEY;
	const response = await handleDiscordInteraction(await signedDiscordRequest({ type: 1 }), env);

	assert.equal(response.status, 500);
	assert.equal(await response.text(), 'invalid request signature');
});

test('returns an ephemeral response for unknown workflow instances', async () => {
	const env = makeDiscordEnv(null, async () => {
		throw new Error('not found');
	});
	const response = await handleDiscordInteraction(
		await signedDiscordRequest({ type: 3, data: { custom_id: 'approve:missing-workflow' } }),
		env
	);

	const body = await response.json();
	assert.equal(response.status, 200);
	assert.equal(body.type, 4);
	assert.equal(body.data.flags, 64);
	assert.match(body.data.content, /no longer waiting/);
});

test('returns an ephemeral response for duplicate clicks', async () => {
	const env = makeDiscordEnv(makeWorkflowInstance('complete'));
	const response = await handleDiscordInteraction(
		await signedDiscordRequest({ type: 3, data: { custom_id: 'approve:workflow-1' } }),
		env
	);

	const body = await response.json();
	assert.equal(response.status, 200);
	assert.equal(body.type, 4);
	assert.equal(body.data.flags, 64);
	assert.match(body.data.content, /no longer waiting/);
});

test('returns an ephemeral response when the approval event cannot be sent', async () => {
	const env = makeDiscordEnv(
		makeWorkflowInstance('waiting', async () => {
			throw new Error('event rejected');
		})
	);
	const response = await handleDiscordInteraction(
		await signedDiscordRequest({ type: 3, data: { custom_id: 'approve:workflow-1' } }),
		env
	);

	const body = await response.json();
	assert.equal(response.status, 200);
	assert.equal(body.type, 4);
	assert.equal(body.data.flags, 64);
	assert.match(body.data.content, /could not be recorded/);
});

test('appends approved hostname to the Cloudflare One DOMAIN list', async () => {
	const calls = mockFetch((url, init, index) => {
		if (index === 0) {
			assert.equal(url, 'https://api.cloudflare.com/client/v4/accounts/account-1/gateway/lists?type=DOMAIN');
			return jsonResponse({ success: true, result: [{ id: 'list-1', name: 'Custom_Hostname_List', type: 'DOMAIN' }] });
		}
		if (index === 1) {
			assert.equal(url, 'https://api.cloudflare.com/client/v4/accounts/account-1/gateway/lists/list-1/items');
			return jsonResponse({ success: true, result: [] });
		}
		return jsonResponse({ success: true, result: { id: 'list-1' } });
	});

	const result = await addHostnameToCloudflareOneList(
		makeCloudflareEnv({ CLOUDFLARE_GATEWAY_HOSTNAME_LIST_NAME: 'Custom_Hostname_List' }),
		'report-1',
		'login.bad.example'
	);

	assert.deepEqual(result, { status: 'added', error: null });
	assert.equal(calls.length, 3);
	assert.equal(calls[2].url, 'https://api.cloudflare.com/client/v4/accounts/account-1/gateway/lists/list-1');
	assert.equal(calls[2].init.method, 'PATCH');
	assert.deepEqual(JSON.parse(calls[2].init.body), {
		append: [{ value: 'login.bad.example', description: 'Report report-1' }],
	});
});

test('fails when the phishing hostname list is missing', async () => {
	mockFetch(() => jsonResponse({ success: true, result: [{ id: 'list-2', name: 'Other', type: 'DOMAIN' }] }));

	await assert.rejects(
		() => addHostnameToCloudflareOneList(makeCloudflareEnv(), 'report-1', 'login.bad.example'),
		/Cloudflare One hostname list not found/
	);
});

test('fails when the Cloudflare Gateway hostname list name is not configured', async () => {
	await assert.rejects(
		() =>
			addHostnameToCloudflareOneList(
				makeCloudflareEnv({ CLOUDFLARE_GATEWAY_HOSTNAME_LIST_NAME: '' }),
				'report-1',
				'login.bad.example'
			),
		/Missing CLOUDFLARE_GATEWAY_HOSTNAME_LIST_NAME/
	);
});

test('skips duplicate hostnames without patching the list', async () => {
	const calls = mockFetch((url, init, index) => {
		if (index === 0) return jsonResponse({ success: true, result: [{ id: 'list-1', name: '0_PHISHING_Hostnames', type: 'DOMAIN' }] });
		return jsonResponse({ success: true, result: [{ value: 'login.bad.example' }] });
	});

	const result = await addHostnameToCloudflareOneList(makeCloudflareEnv(), 'report-1', 'login.bad.example');

	assert.deepEqual(result, { status: 'skipped_duplicate', error: null });
	assert.equal(calls.length, 2);
});

test('surfaces Cloudflare API failures while appending', async () => {
	mockFetch((url, init, index) => {
		if (index === 0) return jsonResponse({ success: true, result: [{ id: 'list-1', name: '0_PHISHING_Hostnames', type: 'DOMAIN' }] });
		if (index === 1) return jsonResponse({ success: true, result: [] });
		return jsonResponse({ success: false, errors: [{ message: 'append failed' }] }, 500);
	});

	await assert.rejects(() => addHostnameToCloudflareOneList(makeCloudflareEnv(), 'report-1', 'login.bad.example'), /append failed/);
});

async function signedDiscordRequest(payload, overrides = {}) {
	const body = JSON.stringify(payload);
	const timestamp = overrides.timestamp || Math.floor(Date.now() / 1000).toString();
	const data = new TextEncoder().encode(timestamp + body);
	const signature = overrides.signature || toHex(await crypto.subtle.sign({ name: 'Ed25519' }, keyPair.privateKey, data));

	return new Request('https://example.com/discord/interactions', {
		method: 'POST',
		headers: {
			'Content-Type': 'application/json',
			'X-Signature-Ed25519': signature,
			'X-Signature-Timestamp': timestamp,
		},
		body,
	});
}

function makeDiscordEnv(instance, get = async () => instance) {
	return {
		DISCORD_APPLICATION_PUBLIC_KEY: publicKeyHex,
		CLOUDFLARE_ACCOUNT_ID: 'account-1',
		CLOUDFLARE_API_TOKEN: 'token-1',
		DISCORD_BOT_TOKEN: 'discord-token',
		DISCORD_APPROVAL_CHANNEL_ID: 'channel-1',
		PHISHING_HOSTNAME_WORKFLOW: { get },
	};
}

function makeWorkflowInstance(status, sendEvent) {
	const instance = {
		events: [],
		status: async () => ({ status }),
		sendEvent: async (event) => {
			if (sendEvent) return sendEvent(event);
			instance.events.push(event);
		},
	};
	return instance;
}

function makeCloudflareEnv(overrides = {}) {
	return {
		CLOUDFLARE_ACCOUNT_ID: 'account-1',
		CLOUDFLARE_API_TOKEN: 'token-1',
		CLOUDFLARE_GATEWAY_HOSTNAME_LIST_NAME: '0_PHISHING_Hostnames',
		PHISHING_HOSTNAME_WORKFLOW: { get: async () => makeWorkflowInstance('waiting') },
		...overrides,
	};
}

function mockFetch(handler) {
	const calls = [];
	globalThis.fetch = async (url, init = {}) => {
		const call = { url: String(url), init };
		calls.push(call);
		return handler(call.url, init, calls.length - 1);
	};
	return calls;
}

function jsonResponse(body, status = 200) {
	return new Response(JSON.stringify(body), {
		status,
		headers: { 'Content-Type': 'application/json' },
	});
}

function toHex(buffer) {
	return Buffer.from(buffer).toString('hex');
}
