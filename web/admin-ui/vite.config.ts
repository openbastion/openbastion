import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// Base44 sandbox only (docker-compose.base44.yml sets BASE44_PREVIEW_MODE=1): the dev server is
// the entry point on its own port instead of the Gateway's /ui/, so it answers at the root and
// forwards the public API paths to the Gateway — the UI keeps ONE origin, as in production.
// Unset (every other environment, including `vite build`), nothing below applies.
const preview = process.env.BASE44_PREVIEW_MODE === "1";
const gateway = process.env.BASE44_GATEWAY_URL ?? "http://api-gateway:8080";
const apiPaths = ["/auth", "/sessions", "/vault", "/policies", "/healthz"];
// The preview proxy reaches this server as 3000-<sandbox id>.<sandbox domain>: Vite refuses an
// unknown Host, so that domain (and the public suffix) is allowed — nothing wider.
const previewHosts = [process.env.BASE44_SANDBOX_HOST_DOMAIN, process.env.BASE44_PUBLIC_HOST_SUFFIX]
  .filter((h): h is string => Boolean(h))
  .map((h) => `.${h}`);

// Served by the Gateway under /ui/ (ADR-0036), under a policy that allows no inline script and
// no inline data beyond images: nothing is inlined into the page.
export default defineConfig({
  base: preview ? "/" : "/ui/",
  define: {
    __OPENBASTION_SOURCE_REPOSITORY__: JSON.stringify(
      process.env.OPENBASTION_SOURCE_REPOSITORY ?? "https://github.com/openbastion/openbastion",
    ),
    __OPENBASTION_SOURCE_REVISION__: JSON.stringify(
      process.env.OPENBASTION_SOURCE_REVISION ?? process.env.GITHUB_SHA ?? "unknown",
    ),
  },
  plugins: [react()],
  resolve: { dedupe: ["react", "react-dom"], preserveSymlinks: true },
  server: preview
    ? {
        host: "0.0.0.0",
        port: 3000,
        allowedHosts: previewHosts,
        proxy: Object.fromEntries(apiPaths.map((p) => [p, { target: gateway, ws: p === "/sessions" }])),
      }
    : undefined,
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
