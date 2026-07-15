import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    environment: "node",
    include: ["src/**/*.test.ts", "*.test.ts"],
    coverage: {
      provider: "v8",
    },
    // ponytail: passWithNoTests is temporary — there are no tests yet, this
    // flips to false (or is removed) once phase 2 adds the first test file.
    passWithNoTests: true,
  },
});
