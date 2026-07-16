import { defineConfig } from "vitest/config";

// Shared by both projects below — project configs don't inherit these from the root.
const shared = {
  environment: "node",
  include: ["src/**/*.test.ts", "*.test.ts"],
  // Vector suites drive hundreds of real WebCrypto AES-GCM calls per file
  // (multi-megabyte vectors, decrypt + byte-exact re-encrypt). GitHub's
  // runners are ~3x slower than local (observed 36s vs 12s), so the
  // ceiling accommodates CI, not local.
  testTimeout: 120000,
};

export default defineConfig({
  test: {
    coverage: {
      provider: "v8",
    },
    projects: [
      { test: { ...shared, name: "default" } },
      // Second pass with the node:crypto fast path forced off, so Node and
      // Bun exercise the WebCrypto implementations on every run. Skipped on
      // Deno, where the fast path is off anyway and this would only
      // duplicate the default project.
      ...("Deno" in globalThis
        ? []
        : [
            {
              test: {
                ...shared,
                name: "forced-webcrypto",
                env: { COBBLESTONE_FORCE_WEBCRYPTO: "1" },
              },
            },
          ]),
    ],
  },
});
