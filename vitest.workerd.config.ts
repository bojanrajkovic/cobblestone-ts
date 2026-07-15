import { defineConfig } from "vitest/config";
import { cloudflareTest } from "@cloudflare/vitest-pool-workers";

export default defineConfig({
  plugins: [
    cloudflareTest({
      miniflare: {
        compatibilityDate: "2025-09-01",
      },
    }),
  ],
  test: {
    // aes-gcm.test.ts is excluded by design: it cross-checks our WebCrypto
    // AEAD against node:crypto's createCipheriv, a Node-only oracle.
    include: ["src/**/*.test.ts", "*.test.ts"],
    exclude: ["**/node_modules/**", "src/internal/aes-gcm.test.ts"],
    testTimeout: 120000,
    // workerd reports rejections from inside TransformStream plumbing that
    // every other runtime (Node, Bun, Deno, Chromium, WebKit) marks as
    // handled. The negative-path vector tests intentionally trigger these,
    // so ignore exactly this package's error classes — anything else
    // (TypeError, workerd internals) still fails the run.
    onUnhandledError(error) {
      const expected = new Set([
        "AuthenticationError",
        "CommitmentMismatchError",
        "CounterOverflowError",
        "InvalidKeyError",
        "InvalidSizeError",
        "TruncationError",
      ]);
      if (expected.has((error as { name?: string }).name ?? "")) return false;
      return;
    },
  },
});
