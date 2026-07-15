import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    environment: "node",
    include: ["src/**/*.test.ts", "*.test.ts"],
    // Vector suites drive hundreds of real WebCrypto AES-GCM calls per file
    // (multi-megabyte vectors, decrypt + byte-exact re-encrypt). GitHub's
    // runners are ~3x slower than local (observed 36s vs 12s), so the
    // ceiling accommodates CI, not local.
    testTimeout: 120000,
    coverage: {
      provider: "v8",
    },
  },
});
