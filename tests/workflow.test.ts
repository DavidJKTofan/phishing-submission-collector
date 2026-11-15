// Drives PhishingHostnameWorkflow.run inside workerd through the Workflows
// introspection API (@cloudflare/vitest-plugin >= 1.3). The steps that call
// external services (Discord, the Gateway list, the reporting providers) are
// mocked by step name; the D1 steps run for real against the migrated test
// database, so each case asserts the actual reports_v2 / provider_reports
// state the Workflow leaves behind. Step names are therefore part of the test
// contract: renaming one in src/index.ts means updating it here.
import { introspectWorkflowInstance } from 'cloudflare:test';
import { env } from 'cloudflare:workers';
import { expect, it } from 'vitest';

import type { ApprovalEventPayload, PhishingHostnameWorkflowParams } from '../src/approval';

type Introspector = Awaited<ReturnType<typeof introspectWorkflowInstance>>;
type Modifier = Parameters<Parameters<Introspector['modify']>[0]>[0];

type ReportRow = {
	approval_status: string;
	approval_actor: string | null;
	approval_decided_at: string | null;
	approval_error: string | null;
	cloudflare_list_status: string;
	cloudflare_list_error: string | null;
};

type ProviderRow = { provider: string; status: string; reference_id: string | null; error: string | null };

const STEP_DISCORD = 'send Discord approval request';
const STEP_WAIT = 'wait for hostname approval';
const STEP_LIST = 'add hostname to Cloudflare One list';
const STEP_PROVIDERS = {
	netcraft: 'report to Netcraft',
	cloudflare_abuse: 'report to Cloudflare Abuse',
	microsoft_msrc: 'report to Microsoft MSRC',
} as const;

const APPROVED: ApprovalEventPayload = { approved: true, actorId: 'user-1', actorUsername: 'alice', messageId: 'message-1', interactionId: 'interaction-1' };
const DENIED: ApprovalEventPayload = { ...APPROVED, approved: false };

it('approve: records the decision, the list result and every provider outcome', async () => {
	const params = await seedReport();

	const output = await runWorkflow(params, async (m) => {
		await m.mockStepResult({ name: STEP_DISCORD }, { id: 'discord-message-1' });
		await m.mockEvent({ type: 'hostname-approval', payload: APPROVED });
		await m.mockStepResult({ name: STEP_LIST }, { status: 'added', error: null });
		await m.mockStepResult({ name: STEP_PROVIDERS.netcraft }, { provider: 'netcraft', status: 'submitted', referenceId: 'nc-1', httpStatus: 200 });
		await m.mockStepResult({ name: STEP_PROVIDERS.cloudflare_abuse }, { provider: 'cloudflare_abuse', status: 'skipped', eligibilityReason: 'No Cloudflare nameservers found.' });
		await m.mockStepResult({ name: STEP_PROVIDERS.microsoft_msrc }, { provider: 'microsoft_msrc', status: 'submitted', referenceId: 'ms-1', httpStatus: 200 });
	});

	expect(output).toMatchObject({ status: 'added', reportId: params.reportId, hostname: params.normalizedHostname });
	const row = await readReport(params.reportId);
	expect(row).toMatchObject({ approval_status: 'approved', approval_actor: 'alice (user-1)', approval_error: null, cloudflare_list_status: 'added', cloudflare_list_error: null });
	expect(row.approval_decided_at).not.toBeNull();
	expect(await readProviderRows(params.reportId)).toEqual([
		{ provider: 'cloudflare_abuse', status: 'skipped', reference_id: null, error: null },
		{ provider: 'microsoft_msrc', status: 'submitted', reference_id: 'ms-1', error: null },
		{ provider: 'netcraft', status: 'submitted', reference_id: 'nc-1', error: null },
	]);
});

it('deny: only updates the approval fields and never touches the list or providers', async () => {
	const params = await seedReport();

	const output = await runWorkflow(params, async (m) => {
		await m.mockStepResult({ name: STEP_DISCORD }, { id: 'discord-message-1' });
		await m.mockEvent({ type: 'hostname-approval', payload: DENIED });
	});

	expect(output).toEqual({ status: 'denied', reportId: params.reportId });
	const row = await readReport(params.reportId);
	expect(row).toMatchObject({ approval_status: 'denied', approval_actor: 'alice (user-1)', cloudflare_list_status: 'not_started' });
	expect(row.approval_decided_at).not.toBeNull();
	expect(await readProviderRows(params.reportId)).toEqual([]);
});

it('expired: a waitForEvent timeout is recorded as expired, not as a failure', async () => {
	const params = await seedReport();

	const output = await runWorkflow(params, async (m) => {
		await m.mockStepResult({ name: STEP_DISCORD }, { id: 'discord-message-1' });
		await m.forceEventTimeout({ name: STEP_WAIT });
	});

	expect(output).toEqual({ status: 'expired', reportId: params.reportId });
	const row = await readReport(params.reportId);
	// If the runtime's timeout error ever stops matching isWaitForEventTimeout
	// in src/index.ts, this shows up here as workflow_failed with the message.
	expect(row).toMatchObject({ approval_status: 'expired', approval_error: null, cloudflare_list_status: 'not_started' });
	expect(row.approval_decided_at).not.toBeNull();
});

it('workflow_failed: a Discord send that fails every attempt is recorded with its error', async () => {
	const params = await seedReport();

	const output = await runWorkflow(params, async (m) => {
		await m.mockStepError({ name: STEP_DISCORD }, new Error('Discord API HTTP 503'));
	});

	expect(output).toMatchObject({ status: 'workflow_failed', reportId: params.reportId });
	const row = await readReport(params.reportId);
	expect(row.approval_status).toBe('workflow_failed');
	expect(row.approval_error).toContain('Discord API HTTP 503');
	expect(row.cloudflare_list_status).toBe('not_started');
});

it('degraded approve: a failed list write and a failed provider are recorded, the other providers still run', async () => {
	const params = await seedReport();

	const output = await runWorkflow(params, async (m) => {
		await m.mockStepResult({ name: STEP_DISCORD }, { id: 'discord-message-1' });
		await m.mockEvent({ type: 'hostname-approval', payload: APPROVED });
		await m.mockStepError({ name: STEP_LIST }, new Error('Cloudflare API HTTP 500'));
		await m.mockStepError({ name: STEP_PROVIDERS.netcraft }, new Error('Netcraft: HTTP 502 (HTTP 502)'));
		await m.mockStepResult({ name: STEP_PROVIDERS.cloudflare_abuse }, { provider: 'cloudflare_abuse', status: 'skipped', eligibilityReason: 'No Cloudflare nameservers found.' });
		await m.mockStepResult({ name: STEP_PROVIDERS.microsoft_msrc }, { provider: 'microsoft_msrc', status: 'skipped', eligibilityReason: 'Resolved IPs are not owned by Microsoft.' });
	});

	expect(output).toMatchObject({ status: 'failed', reportId: params.reportId });
	const row = await readReport(params.reportId);
	expect(row).toMatchObject({ approval_status: 'approved', cloudflare_list_status: 'failed' });
	expect(row.cloudflare_list_error).toContain('Cloudflare API HTTP 500');
	const providers = await readProviderRows(params.reportId);
	expect(providers.map((item) => [item.provider, item.status])).toEqual([
		['cloudflare_abuse', 'skipped'],
		['microsoft_msrc', 'skipped'],
		['netcraft', 'failed'],
	]);
	expect(providers.find((item) => item.provider === 'netcraft')?.error).toContain('Netcraft: HTTP 502');
});

// Creates the pending reports_v2 row the Workflow updates and returns the
// matching Workflow params. Each test gets its own id and hostname.
async function seedReport(): Promise<PhishingHostnameWorkflowParams> {
	const reportId = crypto.randomUUID();
	const normalizedHostname = `wf-${reportId.slice(0, 8)}.bad.example`;
	const submittedUrl = `https://${normalizedHostname}/login`;
	await env.DB.prepare(
		`INSERT INTO reports_v2 (id, name, category, source, url, normalized_hostname, approval_status, cloudflare_list_status)
		 VALUES (?, 'Workflow test', 'Phishing', 'Email', ?, ?, 'pending', 'not_started')`
	)
		.bind(reportId, submittedUrl, normalizedHostname)
		.run();
	return { reportId, name: 'Workflow test', category: 'Phishing', source: 'Email', submittedUrl, normalizedHostname, description: '' };
}

// Introspect first (the introspector must exist before the instance), apply
// the test's mocks with retry delays disabled, create the instance with the
// report id as instance id (as /submit does), and wait for it to finish.
async function runWorkflow(params: PhishingHostnameWorkflowParams, modify: (m: Modifier) => Promise<void>): Promise<unknown> {
	const instance = await introspectWorkflowInstance(env.PHISHING_HOSTNAME_WORKFLOW, params.reportId);
	try {
		await instance.modify(async (m) => {
			await m.disableRetryDelays();
			await modify(m);
		});
		await env.PHISHING_HOSTNAME_WORKFLOW.create({ id: params.reportId, params });
		await instance.waitForStatus('complete');
		return await instance.getOutput();
	} finally {
		await instance.dispose();
	}
}

async function readReport(reportId: string): Promise<ReportRow> {
	const row = await env.DB.prepare(
		`SELECT approval_status, approval_actor, approval_decided_at, approval_error, cloudflare_list_status, cloudflare_list_error
		 FROM reports_v2 WHERE id = ?`
	)
		.bind(reportId)
		.first<ReportRow>();
	if (!row) throw new Error(`report ${reportId} is missing`);
	return row;
}

async function readProviderRows(reportId: string): Promise<ProviderRow[]> {
	const { results } = await env.DB.prepare('SELECT provider, status, reference_id, error FROM provider_reports WHERE report_id = ? ORDER BY provider')
		.bind(reportId)
		.all<ProviderRow>();
	return results;
}
