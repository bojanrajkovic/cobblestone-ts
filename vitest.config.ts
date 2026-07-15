import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    environment: "node",
    include: ["src/**/*.test.ts", "*.test.ts"],
    // Vector suites drive hundreds of real WebCrypto AES-GCM calls per file
    // (multi-megabyte vectors, decrypt + byte-exact re-encrypt) — the 5s
    // default isn't enough.
    testTimeout: 20000,
    coverage: {
      provider: "v8",
    },
  },
});
