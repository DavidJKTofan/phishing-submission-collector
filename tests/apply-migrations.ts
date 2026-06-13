import { applyD1Migrations, env } from 'cloudflare:test';
import type { D1Migration } from 'cloudflare:test';
import { beforeAll } from 'vitest';

// The pool's D1 database starts empty. Apply the project migrations (injected as
// the TEST_MIGRATIONS binding by vitest.config.mts) so read-path tests run
// against the real reports_v2 / provider_reports schema. applyD1Migrations
// records applied state, so running it per test file is idempotent.
beforeAll(async () => {
	const migrations = (env as unknown as { TEST_MIGRATIONS: D1Migration[] }).TEST_MIGRATIONS;
	await applyD1Migrations(env.DB, migrations);
});
