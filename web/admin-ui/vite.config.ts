import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// Served by the Gateway under /ui/ (ADR-0036), under a policy that allows no inline script and
// no inline data beyond images: nothing is inlined into the page.
export default defineConfig({
  base: "/ui/",
  plugins: [react()],
  build: {
    outDir: "dist",
    assetsInlineLimit: 0,
    modulePreload: { polyfill: false },
    sourcemap: false,
  },
  test: {
    environment: "jsdom",
    globals: true,
  },
});
