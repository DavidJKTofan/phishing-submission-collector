import { cloudflarePool, cloudflareTest, readD1Migrations } from '@cloudflare/vitest-pool-workers';
import { defineConfig } from 'vitest/config';

const wrangler = { configPath: './wrangler.jsonc' };

// Runs tests inside workerd with the bindings from wrangler.jsonc, so tests
// exercise the same runtime semantics as production (Workers best practices:
// test with @cloudflare/vitest-pool-workers).
export default defineConfig(async () => {
	// Read migrations on the Node side and inject them as a binding so the
	// in-workerd setup file can apply them to the ephemeral test D1.
	const migrations = await readD1Migrations('migrations');
	return {
		plugins: [cloudflareTest({ wrangler, miniflare: { bindings: { TEST_MIGRATIONS: migrations } } })],
		test: {
			include: ['tests/**/*.test.ts'],
			setupFiles: ['./tests/apply-migrations.ts'],
			pool: cloudflarePool({ wrangler }),
		},
	};
});
