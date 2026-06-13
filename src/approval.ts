import {
	HttpError,
	MAX_BODY_BYTES,
	SECURITY_HEADERS,
	errorMessage,
	isRecord,
	jsonResponse,
	readTextBody,
	requireConfig,
	requireSecret,
} from './shared.js';

const DISCORD_API_BASE = 'https://discord.com/api/v10';
const CLOUDFLARE_API_BASE = 'https://api.cloudflare.com/client/v4';
// Discord webhook follow-ups run inside ctx.waitUntil (outside any Workflow
// step timeout), so they need their own bound (Workers best practices: set
// reasonable timeouts on outbound requests).
const DISCORD_WEBHOOK_TIMEOUT_MS = 10_000;
const DISCORD_INTERACTION_PING = 1;
const DISCORD_INTERACTION_MESSAGE_COMPONENT = 3;
const DISCORD_RESPONSE_PONG = 1;
const DISCORD_RESPONSE_CHANNEL_MESSAGE = 4;
const DISCORD_RESPONSE_DEFERRED_UPDATE_MESSAGE = 6;
const DISCORD_RESPONSE_UPDATE_MESSAGE = 7;
const DISCORD_SUPPRESS_EMBEDS_FLAG = 1 << 2;
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
	urlscanUuid?: string;
	virustotalScanId?: string;
	cloudflareScanUuid?: string;
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
	type: number;
	token?: string;
	data?: {
		custom_id?: string;
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

type CloudflareApiResponse<T> = {
	success?: boolean;
	result?: T;
	errors?: Array<{ message?: string }>;
};

type DiscordVerificationResult =
	| { ok: true }
	| { ok: false; reason: string; status: 401 | 500 };

export async function handleDiscordInteraction(request: Request, env: ApprovalEnv, ctx?: WaitUntilContext): Promise<Response> {
	const body = await readTextBody(request, MAX_BODY_BYTES);
	const verification = await verifyDiscordRequest(request, body, env);
	if (!verification.ok) {
		console.error(JSON.stringify({ event: 'discord_interaction_verification_failed', reason: verification.reason }));
		return new Response('invalid request signature', { status: verification.status, headers: SECURITY_HEADERS });
	}

	// The signature has been verified at this point, but the payload shape is
	// still external input: validate it instead of trusting a type assertion.
	const interaction = parseDiscordInteraction(body);
	if (!interaction) {
		console.error(JSON.stringify({ event: 'discord_interaction_malformed_payload' }));
		return jsonResponse({ error: 'Malformed interaction payload' }, 400);
	}

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

// checkExisting makes a retried send idempotent: a retry after a lost response
// could otherwise post a duplicate approval message. The caller sets it from
// WorkflowStepContext.attempt so the extra lookup only happens on retries.
export async function sendDiscordApprovalMessage(
	env: ApprovalEnv,
	report: PhishingHostnameWorkflowParams,
	instanceId: string,
	checkExisting = false
): Promise<DiscordMessage> {
	const channelId = requireSecret(env.DISCORD_APPROVAL_CHANNEL_ID, 'DISCORD_APPROVAL_CHANNEL_ID');
	const botToken = requireSecret(env.DISCORD_BOT_TOKEN, 'DISCORD_BOT_TOKEN');

	if (checkExisting) {
		const existing = await findExistingDiscordApprovalMessage(channelId, botToken, instanceId);
		if (existing) {
			console.log(JSON.stringify({ event: 'discord_approval_message_already_sent', reportId: report.reportId, messageId: existing.id }));
			return existing;
		}
	}

	const response = await fetch(`${DISCORD_API_BASE}/channels/${channelId}/messages`, {
		method: 'POST',
		headers: {
			Authorization: `Bot ${botToken}`,
			'Content-Type': 'application/json',
		},
		body: JSON.stringify({
			content: buildDiscordApprovalContent(report),
			flags: DISCORD_SUPPRESS_EMBEDS_FLAG,
			allowed_mentions: { parse: [] },
			components: buildDiscordApprovalComponents(instanceId, false),
		}),
	});

	const data = (await response.json().catch(() => ({}))) as DiscordMessage & { message?: string };
	if (!response.ok) throw new Error(data.message || `Discord API HTTP ${response.status}`);
	return data;
}

// Best-effort duplicate detection: scan recent channel messages for the approve
// button carrying this instance ID. Any failure (for example, a bot without the
// Read Message History permission) falls back to posting normally.
async function findExistingDiscordApprovalMessage(channelId: string, botToken: string, instanceId: string): Promise<DiscordMessage | null> {
	try {
		const response = await fetch(`${DISCORD_API_BASE}/channels/${channelId}/messages?limit=50`, {
			headers: { Authorization: `Bot ${botToken}` },
			signal: AbortSignal.timeout(DISCORD_WEBHOOK_TIMEOUT_MS),
		});
		if (!response.ok) return null;
		const messages = (await response.json()) as unknown;
		if (!Array.isArray(messages)) return null;
		const approveId = `approve:${instanceId}`;
		for (const message of messages) {
			if (isRecord(message) && typeof message.id === 'string' && messageHasCustomId(message, approveId)) {
				return { id: message.id };
			}
		}
		return null;
	} catch (error) {
		console.error(JSON.stringify({ event: 'discord_approval_dedupe_check_failed', error: errorMessage(error) }));
		return null;
	}
}

function messageHasCustomId(message: Record<string, unknown>, customId: string): boolean {
	if (!Array.isArray(message.components)) return false;
	for (const row of message.components) {
		if (!isRecord(row) || !Array.isArray(row.components)) continue;
		for (const component of row.components) {
			if (isRecord(component) && component.custom_id === customId) return true;
		}
	}
	return false;
}

export function formatDiscordActor(payload: ApprovalEventPayload): string {
	return `${payload.actorUsername} (${payload.actorId})`;
}

// Append-first write: attempting the append and mapping the API's duplicate
// error to skipped_duplicate is atomic on the API side. The previous
// read-then-write pattern only saw the first page of the paginated items
// endpoint and was racy under concurrent approvals (TOCTOU).
export async function addHostnameToCloudflareOneList(
	env: ApprovalEnv,
	reportId: string,
	hostname: string
): Promise<{ status: CloudflareListStatus; error: string | null }> {
	const list = await getCloudflareOneHostnameList(env);

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
	if (!response.ok || data.success === false) {
		if (isDuplicateListItemError(data)) {
			console.log(JSON.stringify({ event: 'cloudflare_one_list_duplicate', reportId, listId: list.id, hostname }));
			return { status: 'skipped_duplicate', error: null };
		}
		throw new Error(cloudflareApiError(data, response.status));
	}

	console.log(JSON.stringify({ event: 'cloudflare_one_list_hostname_added', reportId, listId: list.id, hostname }));
	return { status: 'added', error: null };
}

function isDuplicateListItemError(data: CloudflareApiResponse<unknown>): boolean {
	return (data.errors || []).some((error) => /duplicate|already exist/i.test(error.message || ''));
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

function buildDiscordApprovalContent(report: PhishingHostnameWorkflowParams): string {
	const description = report.description
		? `\n- **Description:** ${escapeDiscordMarkdown(truncateDiscordLine(report.description, 240))}`
		: '';
	return [
		'**Phishing hostname approval required**',
		'',
		'**Submission**',
		`- **Report ID:** \`${report.reportId}\``,
		`- **Title:** ${escapeDiscordMarkdown(truncateDiscordLine(report.name, 120))}`,
		`- **Hostname:** \`${report.normalizedHostname}\``,
		`- **Submitted URL:** ${formatDiscordUrl(report.submittedUrl, 360)}`,
		`- **Category:** ${report.category}`,
		`- **Source:** ${report.source}${description}`,
		'',
		'**Review links**',
		...buildDiscordReviewLinks(report),
	].join('\n');
}

function buildDiscordReviewLinks(report: PhishingHostnameWorkflowParams): string[] {
	const cloudflareLabel = report.cloudflareScanUuid ? 'Open report' : 'Search or scan URL';
	const cloudflareUrl = report.cloudflareScanUuid
		? cloudflareUrlScannerReportUrl(report.cloudflareScanUuid)
		: cloudflareUrlScannerSearchUrl(report.submittedUrl);
	const links = [`- **Cloudflare URL Scanner:** ${formatDiscordLink(cloudflareLabel, cloudflareUrl)}`];

	if (report.urlscanUuid) {
		const urlscanResultUrl = `https://urlscan.io/result/${report.urlscanUuid}/`;
		links.push(`- **urlscan.io:** ${formatDiscordLink('Open report', urlscanResultUrl)}`);
	}
	if (report.virustotalScanId) {
		const virusTotalResultUrl = `https://www.virustotal.com/gui/url/${report.virustotalScanId}`;
		links.push(`- **VirusTotal:** ${formatDiscordLink('Open report', virusTotalResultUrl)}`);
	}

	return links;
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
		content: `${currentContent}\n\n**Decision:** ${decision} by <@${actorId}>`,
		flags: DISCORD_SUPPRESS_EMBEDS_FLAG,
		allowed_mentions: { parse: [] },
		components: buildDiscordApprovalComponents(instanceId, true),
	};
}

async function editDiscordInteractionOriginalMessage(interaction: DiscordInteraction, approved: boolean, actorId: string): Promise<void> {
	const applicationId = interaction.application_id;
	const token = interaction.token;
	if (!applicationId || !token) return;

	await discordWebhookRequest(
		'PATCH',
		`${DISCORD_API_BASE}/webhooks/${applicationId}/${token}/messages/@original`,
		buildDiscordDecisionMessageData(interaction, approved, actorId),
		'discord_original_message_update_failed'
	);
}

async function sendDiscordInteractionFollowup(interaction: DiscordInteraction, content: string): Promise<void> {
	const applicationId = interaction.application_id;
	const token = interaction.token;
	if (!applicationId || !token) return;

	await discordWebhookRequest(
		'POST',
		`${DISCORD_API_BASE}/webhooks/${applicationId}/${token}`,
		{ content, flags: DISCORD_EPHEMERAL_FLAG, allowed_mentions: { parse: [] } },
		'discord_followup_failed'
	);
}

// These calls run inside ctx.waitUntil where an unchecked failure is invisible:
// check the response and log so a moderator-facing update that never landed is
// at least observable. The webhook URL embeds the interaction token, so log
// only the event name and status.
async function discordWebhookRequest(method: 'POST' | 'PATCH', url: string, body: Record<string, unknown>, failureEvent: string): Promise<void> {
	try {
		const response = await fetch(url, {
			method,
			headers: { 'Content-Type': 'application/json' },
			body: JSON.stringify(body),
			signal: AbortSignal.timeout(DISCORD_WEBHOOK_TIMEOUT_MS),
		});
		if (!response.ok) {
			console.error(JSON.stringify({ event: failureEvent, status: response.status }));
		}
	} catch (error) {
		console.error(JSON.stringify({ event: failureEvent, error: errorMessage(error) }));
	}
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

// Runtime validation for the externally supplied interaction payload.
// Unknown fields are dropped; only the fields this Worker consumes survive.
function parseDiscordInteraction(body: string): DiscordInteraction | null {
	let parsed: unknown;
	try {
		parsed = JSON.parse(body);
	} catch {
		return null;
	}
	if (!isRecord(parsed) || typeof parsed.type !== 'number') return null;

	return {
		id: optionalString(parsed.id),
		application_id: optionalString(parsed.application_id),
		type: parsed.type,
		token: optionalString(parsed.token),
		data: isRecord(parsed.data) ? { custom_id: optionalString(parsed.data.custom_id) } : undefined,
		member: isRecord(parsed.member) ? { user: parseDiscordUser(parsed.member.user) } : undefined,
		user: parseDiscordUser(parsed.user),
		message: isRecord(parsed.message) ? { id: optionalString(parsed.message.id), content: optionalString(parsed.message.content) } : undefined,
	};
}

function parseDiscordUser(value: unknown): DiscordUser | undefined {
	if (!isRecord(value)) return undefined;
	return {
		id: optionalString(value.id),
		username: optionalString(value.username),
		global_name: typeof value.global_name === 'string' ? value.global_name : null,
	};
}

function optionalString(value: unknown): string | undefined {
	return typeof value === 'string' ? value : undefined;
}

// Workflows does not validate waitForEvent payloads against the TypeScript
// type parameter (see Workflows "Events and parameters" docs), so the Workflow
// validates the payload before acting on it.
export function isApprovalEventPayload(value: unknown): value is ApprovalEventPayload {
	return (
		isRecord(value) &&
		typeof value.approved === 'boolean' &&
		typeof value.actorId === 'string' &&
		typeof value.actorUsername === 'string' &&
		typeof value.interactionId === 'string' &&
		(value.messageId === undefined || typeof value.messageId === 'string')
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

function escapeDiscordMarkdown(value: string): string {
	return value.replace(/([\\*_`~|])/g, '\\$1');
}

function formatDiscordUrl(url: string, maxLength: number): string {
	const compact = truncateDiscordLine(url, maxLength);
	return compact === url.trim() && isHttpUrl(compact) ? `<${compact}>` : escapeDiscordMarkdown(compact);
}

function formatDiscordLink(label: string, url: string): string {
	return `[${label}](${url})`;
}

function cloudflareUrlScannerReportUrl(uuid: string): string {
	return `https://radar.cloudflare.com/scan/${encodeURIComponent(uuid)}/summary`;
}

function cloudflareUrlScannerSearchUrl(submittedUrl: string): string {
	return `https://radar.cloudflare.com/scan?url=${encodeURIComponent(submittedUrl)}`;
}

function isHttpUrl(value: string): boolean {
	try {
		const url = new URL(value);
		return url.protocol === 'http:' || url.protocol === 'https:';
	} catch {
		return false;
	}
}
