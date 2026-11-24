import { defineConfig } from "vitest/config";
import react from "@vitejs/plugin-react";
import viteConfig from "./vite.config";

// The Admin UI test runner (ADR-0036, ADR-0137 §9). Kept separate from vite.config.ts so that a
// change to the preview/dev server (BASE44_PREVIEW_MODE, proxy, base path) cannot alter how the
// tests resolve modules, and so that `npm test` and `make ui-test` run the same configuration.
// The build-time constants are taken from vite.config.ts itself: a test that imports the legal
// notice or the login page would otherwise fail on an undefined global, and two definitions
// would drift.
export default defineConfig({
  define: viteConfig.define,
  plugins: [react()],
  resolve: { dedupe: ["react", "react-dom"], preserveSymlinks: true },
  test: {
    environment: "jsdom",
    globals: true,
    setupFiles: ["./src/test-setup.ts"],
    include: ["src/**/*.test.{ts,tsx}"],
  },
});
