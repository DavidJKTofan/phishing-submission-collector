const SECURITY_HEADERS = {
	'X-Content-Type-Options': 'nosniff',
	'Referrer-Policy': 'strict-origin-when-cross-origin',
	'X-Frame-Options': 'DENY',
	'Permissions-Policy': 'geolocation=(), microphone=(), camera=()',
} as const;

const MAX_BODY_BYTES = 50_000;
const DISCORD_API_BASE = 'https://discord.com/api/v10';
const CLOUDFLARE_API_BASE = 'https://api.cloudflare.com/client/v4';
const DISCORD_INTERACTION_PING = 1;
const DISCORD_INTERACTION_MESSAGE_COMPONENT = 3;
const DISCORD_RESPONSE_PONG = 1;
const DISCORD_RESPONSE_CHANNEL_MESSAGE = 4;
const DISCORD_RESPONSE_DEFERRED_UPDATE_MESSAGE = 6;
const DISCORD_RESPONSE_UPDATE_MESSAGE = 7;
const DISCORD_EPHEMERAL_FLAG = 1 << 6;

export const APPROVAL_EVENT_TYPE = 'hostname-approval';

export type ApprovalStatus = 'pending' | 'approved' | 'denied' | 'expired' | 'workflow_failed';
export type CloudflareListStatus = 'not_started' | 'added' | 'skipped_duplicate' | 'failed';

export type PhishingHostnameWorkflowParams = {
	reportId: string;
	name: string;
	category: string;
	source: string;
	submittedUrl: string;
	normalizedHostname: string;
	description: string;
};

export type ApprovalEventPayload = {
	approved: boolean;
	actorId: string;
	actorUsername: string;
	messageId?: string;
	interactionId: string;
};

type ApprovalWorkflowInstance = {
	status: () => Promise<{ status?: string }>;
	sendEvent: (event: { type: string; payload: ApprovalEventPayload }) => Promise<unknown>;
};

type ApprovalWorkflowBinding = {
	get: (instanceId: string) => Promise<ApprovalWorkflowInstance>;
};

type WaitUntilContext = {
	waitUntil: (promise: Promise<unknown>) => void;
};

type ApprovalEnv = {
	CLOUDFLARE_ACCOUNT_ID?: string;
	CLOUDFLARE_API_TOKEN?: string;
	CLOUDFLARE_GATEWAY_HOSTNAME_LIST_NAME?: string;
	DISCORD_APPLICATION_PUBLIC_KEY?: string;
	DISCORD_BOT_TOKEN?: string;
	DISCORD_APPROVAL_CHANNEL_ID?: string;
	PHISHING_HOSTNAME_WORKFLOW: ApprovalWorkflowBinding;
};

type DiscordInteraction = {
	id?: string;
	application_id?: string;
	type?: number;
	token?: string;
	data?: {
		custom_id?: string;
		component_type?: number;
	};
	member?: {
		user?: DiscordUser;
	};
	user?: DiscordUser;
	message?: {
		id?: string;
		content?: string;
	};
};

type DiscordDecisionResult =
	| { ok: true; approved: boolean; actorId: string }
	| { ok: false; message: string };

type DiscordUser = {
	id?: string;
	username?: string;
	global_name?: string | null;
};

type DiscordMessage = {
	id?: string;
};

type CloudflareZeroTrustList = {
	id?: string;
	name?: string;
	type?: string;
};

type CloudflareZeroTrustListItem = {
	value?: string;
	description?: string;
};

type CloudflareApiResponse<T> = {
	success?: boolean;
	result?: T;
	errors?: Array<{ message?: string }>;
};

type DiscordVerificationResult =
	| { ok: true }
	| { ok: false; reason: string; status: 401 | 500 };

class HttpError extends Error {
	readonly status: number;
	readonly code: string;

	constructor(status: number, message: string, code = 'BAD_REQUEST') {
		super(message);
		this.name = 'HttpError';
		this.status = status;
		this.code = code;
	}
}

export async function handleDiscordInteraction(request: Request, env: ApprovalEnv, ctx?: WaitUntilContext): Promise<Response> {
	const body = await readTextBody(request, MAX_BODY_BYTES);
	const verification = await verifyDiscordRequest(request, body, env);
	if (!verification.ok) {
		console.error(JSON.stringify({ event: 'discord_interaction_verification_failed', reason: verification.reason }));
		return new Response('invalid request signature', { status: verification.status, headers: SECURITY_HEADERS });
	}

	const interaction = JSON.parse(body) as DiscordInteraction;
	if (interaction.type === DISCORD_INTERACTION_PING) {
		return jsonResponse({ type: DISCORD_RESPONSE_PONG }, 200);
	}

	if (interaction.type !== DISCORD_INTERACTION_MESSAGE_COMPONENT) {
		return discordEphemeralResponse('Unsupported Discord interaction.');
	}

	const customId = interaction.data?.custom_id || '';
	const [action = '', instanceId = ''] = customId.split(':');
	if (!instanceId || !['approve', 'deny'].includes(action)) {
		return discordEphemeralResponse('Unknown approval action.');
	}

	if (ctx) {
		ctx.waitUntil(handleDiscordDecisionAsync(interaction, env, action, instanceId));
		return jsonResponse({ type: DISCORD_RESPONSE_DEFERRED_UPDATE_MESSAGE }, 200);
	}

	const result = await recordDiscordDecision(interaction, env, action, instanceId);
	if (!result.ok) return discordEphemeralResponse(result.message);
	return discordUpdateMessageResponse(interaction, result.approved, result.actorId);
}

async function handleDiscordDecisionAsync(interaction: DiscordInteraction, env: ApprovalEnv, action: string, instanceId: string): Promise<void> {
	const result = await recordDiscordDecision(interaction, env, action, instanceId);
	if (result.ok) {
		await editDiscordInteractionOriginalMessage(interaction, result.approved, result.actorId);
		return;
	}

	await sendDiscordInteractionFollowup(interaction, result.message);
}

async function recordDiscordDecision(
	interaction: DiscordInteraction,
	env: ApprovalEnv,
	action: string,
	instanceId: string
): Promise<DiscordDecisionResult> {
	const actor = getDiscordActor(interaction);
	let instance: ApprovalWorkflowInstance;
	try {
		instance = await env.PHISHING_HOSTNAME_WORKFLOW.get(instanceId);
		const status = await instance.status();
		if (status.status !== 'waiting' && status.status !== 'running') {
			return { ok: false, message: 'This approval is no longer waiting for a decision.' };
		}
	} catch {
		return { ok: false, message: 'This approval is no longer waiting for a decision.' };
	}

	try {
		await instance.sendEvent({
			type: APPROVAL_EVENT_TYPE,
			payload: {
				approved: action === 'approve',
				actorId: actor.id,
				actorUsername: actor.username,
				messageId: interaction.message?.id,
				interactionId: interaction.id || crypto.randomUUID(),
			},
		});
	} catch {
		return { ok: false, message: 'This approval could not be recorded. Please try again or check the report status.' };
	}

	return { ok: true, approved: action === 'approve', actorId: actor.id };
}

export async function sendDiscordApprovalMessage(
	env: ApprovalEnv,
	report: PhishingHostnameWorkflowParams,
	instanceId: string
): Promise<DiscordMessage> {
	const response = await fetch(`${DISCORD_API_BASE}/channels/${requireSecret(env.DISCORD_APPROVAL_CHANNEL_ID, 'DISCORD_APPROVAL_CHANNEL_ID')}/messages`, {
		method: 'POST',
		headers: {
			Authorization: `Bot ${requireSecret(env.DISCORD_BOT_TOKEN, 'DISCORD_BOT_TOKEN')}`,
			'Content-Type': 'application/json',
		},
		body: JSON.stringify({
			content: buildDiscordApprovalContent(report),
			allowed_mentions: { parse: [] },
			components: buildDiscordApprovalComponents(instanceId, false),
		}),
	});

	const data = (await response.json().catch(() => ({}))) as DiscordMessage & { message?: string };
	if (!response.ok) throw new Error(data.message || `Discord API HTTP ${response.status}`);
	return data;
}

export function formatDiscordActor(payload: ApprovalEventPayload): string {
	return `${payload.actorUsername} (${payload.actorId})`;
}

export async function addHostnameToCloudflareOneList(
	env: ApprovalEnv,
	reportId: string,
	hostname: string
): Promise<{ status: CloudflareListStatus; error: string | null }> {
	const list = await getCloudflareOneHostnameList(env);
	const existingItems = await fetchCloudflareOneListItems(env, list.id);
	if (existingItems.some((item) => item.value?.toLowerCase() === hostname)) {
		console.log(JSON.stringify({ event: 'cloudflare_one_list_duplicate', reportId, listId: list.id, hostname }));
		return { status: 'skipped_duplicate', error: null };
	}

	const response = await fetch(
		`${CLOUDFLARE_API_BASE}/accounts/${requireSecret(env.CLOUDFLARE_ACCOUNT_ID, 'CLOUDFLARE_ACCOUNT_ID')}/gateway/lists/${list.id}`,
		{
			method: 'PATCH',
			headers: {
				Authorization: `Bearer ${requireSecret(env.CLOUDFLARE_API_TOKEN, 'CLOUDFLARE_API_TOKEN')}`,
				'Content-Type': 'application/json',
			},
			body: JSON.stringify({
				append: [{ value: hostname, description: `Report ${reportId}` }],
			}),
		}
	);

	const data = (await response.json().catch(() => ({}))) as CloudflareApiResponse<unknown>;
	if (!response.ok || data.success === false) throw new Error(cloudflareApiError(data, response.status));

	console.log(JSON.stringify({ event: 'cloudflare_one_list_hostname_added', reportId, listId: list.id, hostname }));
	return { status: 'added', error: null };
}

async function getCloudflareOneHostnameList(env: ApprovalEnv): Promise<{ id: string; name: string }> {
	const accountId = requireSecret(env.CLOUDFLARE_ACCOUNT_ID, 'CLOUDFLARE_ACCOUNT_ID');
	const listName = requireConfig(env.CLOUDFLARE_GATEWAY_HOSTNAME_LIST_NAME, 'CLOUDFLARE_GATEWAY_HOSTNAME_LIST_NAME');
	const response = await fetch(`${CLOUDFLARE_API_BASE}/accounts/${accountId}/gateway/lists?type=DOMAIN`, {
		headers: { Authorization: `Bearer ${requireSecret(env.CLOUDFLARE_API_TOKEN, 'CLOUDFLARE_API_TOKEN')}` },
	});
	const data = (await response.json().catch(() => ({}))) as CloudflareApiResponse<CloudflareZeroTrustList[]>;
	if (!response.ok || data.success === false) throw new Error(cloudflareApiError(data, response.status));

	const list = (data.result || []).find((item) => item.name === listName && item.type === 'DOMAIN');
	if (!list?.id || !list.name) throw new Error(`Cloudflare One hostname list not found: ${listName}`);
	return { id: list.id, name: list.name };
}

async function fetchCloudflareOneListItems(env: ApprovalEnv, listId: string): Promise<CloudflareZeroTrustListItem[]> {
	const accountId = requireSecret(env.CLOUDFLARE_ACCOUNT_ID, 'CLOUDFLARE_ACCOUNT_ID');
	const response = await fetch(`${CLOUDFLARE_API_BASE}/accounts/${accountId}/gateway/lists/${listId}/items`, {
		headers: { Authorization: `Bearer ${requireSecret(env.CLOUDFLARE_API_TOKEN, 'CLOUDFLARE_API_TOKEN')}` },
	});
	const data = (await response.json().catch(() => ({}))) as CloudflareApiResponse<CloudflareZeroTrustListItem[]>;
	if (!response.ok || data.success === false) throw new Error(cloudflareApiError(data, response.status));
	return data.result || [];
}

function buildDiscordApprovalContent(report: PhishingHostnameWorkflowParams): string {
	const description = report.description ? `\nDescription: ${truncateDiscordLine(report.description, 300)}` : '';
	return [
		'Phishing hostname approval required',
		`Report: ${report.reportId}`,
		`Hostname: ${report.normalizedHostname}`,
		`Submitted: ${truncateDiscordLine(report.submittedUrl, 500)}`,
		`Category: ${report.category}`,
		`Source: ${report.source}${description}`,
	].join('\n');
}

function buildDiscordApprovalComponents(instanceId: string, disabled: boolean): Array<{ type: number; components: unknown[] }> {
	return [
		{
			type: 1,
			components: [
				{ type: 2, style: 3, label: 'Approve', custom_id: `approve:${instanceId}`, disabled },
				{ type: 2, style: 4, label: 'Deny', custom_id: `deny:${instanceId}`, disabled },
			],
		},
	];
}

function discordUpdateMessageResponse(interaction: DiscordInteraction, approved: boolean, actorId: string): Response {
	return jsonResponse({ type: DISCORD_RESPONSE_UPDATE_MESSAGE, data: buildDiscordDecisionMessageData(interaction, approved, actorId) }, 200);
}

function buildDiscordDecisionMessageData(interaction: DiscordInteraction, approved: boolean, actorId: string): Record<string, unknown> {
	const currentContent = interaction.message?.content || 'Phishing hostname approval';
	const decision = approved ? 'Approved' : 'Denied';
	const customId = interaction.data?.custom_id || '';
	const instanceId = customId.split(':')[1] || '';
	return {
		content: `${currentContent}\n\nDecision: ${decision} by <@${actorId}>`,
		allowed_mentions: { parse: [] },
		components: buildDiscordApprovalComponents(instanceId, true),
	};
}

async function editDiscordInteractionOriginalMessage(interaction: DiscordInteraction, approved: boolean, actorId: string): Promise<void> {
	const applicationId = interaction.application_id;
	const token = interaction.token;
	if (!applicationId || !token) return;

	await fetch(`${DISCORD_API_BASE}/webhooks/${applicationId}/${token}/messages/@original`, {
		method: 'PATCH',
		headers: { 'Content-Type': 'application/json' },
		body: JSON.stringify(buildDiscordDecisionMessageData(interaction, approved, actorId)),
	});
}

async function sendDiscordInteractionFollowup(interaction: DiscordInteraction, content: string): Promise<void> {
	const applicationId = interaction.application_id;
	const token = interaction.token;
	if (!applicationId || !token) return;

	await fetch(`${DISCORD_API_BASE}/webhooks/${applicationId}/${token}`, {
		method: 'POST',
		headers: { 'Content-Type': 'application/json' },
		body: JSON.stringify({ content, flags: DISCORD_EPHEMERAL_FLAG, allowed_mentions: { parse: [] } }),
	});
}

function discordEphemeralResponse(content: string): Response {
	return jsonResponse(
		{
			type: DISCORD_RESPONSE_CHANNEL_MESSAGE,
			data: { content, flags: DISCORD_EPHEMERAL_FLAG, allowed_mentions: { parse: [] } },
		},
		200
	);
}

function getDiscordActor(interaction: DiscordInteraction): { id: string; username: string } {
	const user = interaction.member?.user || interaction.user || {};
	return {
		id: user.id || 'unknown',
		username: user.global_name || user.username || 'unknown',
	};
}

async function verifyDiscordRequest(request: Request, body: string, env: ApprovalEnv): Promise<DiscordVerificationResult> {
	const signature = request.headers.get('X-Signature-Ed25519');
	const timestamp = request.headers.get('X-Signature-Timestamp');
	if (!signature || !timestamp) return { ok: false, reason: 'missing_signature_headers', status: 401 };

	const timestampSeconds = Number(timestamp);
	if (!Number.isFinite(timestampSeconds)) return { ok: false, reason: 'invalid_signature_timestamp', status: 401 };
	if (Math.abs(Date.now() / 1000 - timestampSeconds) > 300) return { ok: false, reason: 'stale_signature_timestamp', status: 401 };
	if (!env.DISCORD_APPLICATION_PUBLIC_KEY) return { ok: false, reason: 'missing_discord_public_key_secret', status: 500 };

	try {
		const signatureBytes = hexToBytes(signature);
		const publicKeyBytes = hexToBytes(env.DISCORD_APPLICATION_PUBLIC_KEY);
		const data = new TextEncoder().encode(timestamp + body);
		const ok = await verifyEd25519Signature(publicKeyBytes, signatureBytes, data);
		return ok ? { ok: true } : { ok: false, reason: 'signature_mismatch', status: 401 };
	} catch (error) {
		const message = error instanceof Error ? error.message : String(error);
		return { ok: false, reason: `verification_error:${message}`, status: 401 };
	}
}

async function verifyEd25519Signature(publicKeyBytes: Uint8Array, signatureBytes: Uint8Array, data: Uint8Array): Promise<boolean> {
	const publicKey = toArrayBuffer(publicKeyBytes);
	const signature = toArrayBuffer(signatureBytes);
	const payload = toArrayBuffer(data);
	try {
		const key = await crypto.subtle.importKey('raw', publicKey, { name: 'Ed25519' }, false, ['verify']);
		return await crypto.subtle.verify('Ed25519', key, signature, payload);
	} catch {
		const key = await crypto.subtle.importKey('raw', publicKey, { name: 'NODE-ED25519', namedCurve: 'NODE-ED25519' }, false, [
			'verify',
		]);
		return crypto.subtle.verify('NODE-ED25519', key, signature, payload);
	}
}

async function readTextBody(request: Request, maxBytes: number): Promise<string> {
	const contentLength = request.headers.get('Content-Length');
	if (contentLength) {
		const declaredLength = Number(contentLength);
		if (!Number.isFinite(declaredLength) || declaredLength < 0) {
			throw new HttpError(400, 'Invalid Content-Length', 'INVALID_CONTENT_LENGTH');
		}
		if (declaredLength > maxBytes) {
			throw new HttpError(413, 'Request body too large', 'BODY_TOO_LARGE');
		}
	}

	if (!request.body) throw new HttpError(400, 'Request body required', 'INVALID_JSON');

	const reader = request.body.getReader();
	const chunks: Uint8Array[] = [];
	let totalBytes = 0;

	try {
		while (true) {
			const { done, value } = await reader.read();
			if (done) break;
			if (!value) continue;
			totalBytes += value.byteLength;
			if (totalBytes > maxBytes) {
				throw new HttpError(413, 'Request body too large', 'BODY_TOO_LARGE');
			}
			chunks.push(value);
		}
	} finally {
		reader.releaseLock();
	}

	const bodyBytes = new Uint8Array(totalBytes);
	let offset = 0;
	for (const chunk of chunks) {
		bodyBytes.set(chunk, offset);
		offset += chunk.byteLength;
	}

	return new TextDecoder().decode(bodyBytes);
}

function jsonResponse(body: unknown, status: number): Response {
	return new Response(JSON.stringify(body), {
		status,
		headers: {
			'Content-Type': 'application/json; charset=utf-8',
			...SECURITY_HEADERS,
		},
	});
}

function requireSecret(value: string | undefined, name: string): string {
	if (!value) throw new Error(`Missing ${name}`);
	return value;
}

function requireConfig(value: string | undefined, name: string): string {
	const trimmed = value?.trim();
	if (!trimmed) throw new Error(`Missing ${name}`);
	return trimmed;
}

function cloudflareApiError(data: CloudflareApiResponse<unknown>, status: number): string {
	return data.errors?.map((error) => error.message).filter(Boolean).join('; ') || `Cloudflare API HTTP ${status}`;
}

function hexToBytes(hex: string): Uint8Array {
	if (!/^[0-9a-f]+$/i.test(hex) || hex.length % 2 !== 0) throw new HttpError(401, 'Invalid Discord signature', 'INVALID_DISCORD_SIGNATURE');
	const bytes = new Uint8Array(hex.length / 2);
	for (let i = 0; i < bytes.length; i += 1) {
		bytes[i] = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16);
	}
	return bytes;
}

function toArrayBuffer(bytes: Uint8Array): ArrayBuffer {
	const copy = new Uint8Array(bytes.byteLength);
	copy.set(bytes);
	return copy.buffer;
}

function truncateDiscordLine(value: string, maxLength: number): string {
	const compact = value.replace(/\s+/g, ' ').trim();
	return compact.length > maxLength ? `${compact.slice(0, maxLength - 3)}...` : compact;
}
