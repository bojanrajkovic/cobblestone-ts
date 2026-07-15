import { defineConfig } from "vitest/config";
import { playwright } from "@vitest/browser-playwright";

export default defineConfig({
  test: {
    // aes-gcm.test.ts is excluded by design: it cross-checks our WebCrypto
    // AEAD against node:crypto's createCipheriv, a Node-only oracle.
    include: ["src/**/*.test.ts", "*.test.ts"],
    exclude: ["**/node_modules/**", "src/internal/aes-gcm.test.ts"],
    testTimeout: 120000,
    browser: {
      enabled: true,
      headless: true,
      provider: playwright(),
      instances: [{ browser: "chromium" }, { browser: "webkit" }, { browser: "firefox" }],
    },
  },
});
