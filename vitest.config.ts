import { defineConfig } from 'vitest/config';

// Phase A: single Node project. The browser project lands in Phase E along
// with the `@vitest/browser-playwright` provider wiring; current Vitest 4.x
// expects a factory import instead of a string provider name.

export default defineConfig({
  test: {
    name: 'unit',
    include: ['src/**/*.test.ts', 'test/**/*.test.ts'],
    exclude: ['test/webext-harness/**', 'test/ssh-agent-harness/**', 'test/integration/**'],
    environment: 'node',
    coverage: {
      provider: 'v8',
      reporter: ['text', 'html', 'json-summary', 'json'],
      include: ['src/**/*.ts'],
      exclude: [
        'src/**/*.test.ts',
        'src/**/__tests__/**',
        'src/types.ts',
        'src/types/**',
        'src/errors.ts',
        'src/index.ts',
        'src/browser/index.ts',
      ],
      thresholds: {
        // Branch threshold is slightly relaxed — StandardTier's RSA
        // unwrap and SSH private-key parser have several defensive
        // error branches (malformed PEM, wrong JWK shape, short KEK,
        // unknown key type) that are hard to exercise from legitimate
        // inputs. Statements/functions/lines floors stay at 80.
        lines: 80,
        branches: 78,
        functions: 80,
        statements: 80,
      },
    },
  },
});
