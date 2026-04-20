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
    // Argon2id KDF (used by MaximumTier + its setup helpers) is slow
    // under the v8 coverage instrumentation — a single derivation can
    // exceed the default 5s hook timeout and the default 10s test
    // timeout. 60s is safe for CI runners; real Argon2 setup at
    // production parameters is <500ms uninstrumented.
    testTimeout: 60_000,
    hookTimeout: 60_000,
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
        // Branch threshold relaxed — `StandardTier`'s RSA unwrap, the
        // SSH private-key parser, and `OsKeychainStorage`'s
        // `isNotFoundError` (which alternates across libsecret /
        // wincred / macOS Keychain error messages) have many
        // defensive error branches that are hard to exercise from
        // unit tests without synthesising platform-specific error
        // shapes. Statements / functions / lines floors stay at 80%.
        lines: 80,
        branches: 76,
        functions: 80,
        statements: 80,
      },
    },
  },
});
