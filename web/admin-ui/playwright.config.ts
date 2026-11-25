import { defineConfig, devices } from "@playwright/test";

// End-to-end tests of the Admin UI against a RUNNING stack (the Base44 preview serves it on
// :3000; a real installation serves it under /ui/ on the Gateway). Nothing is started here.
//   E2E_BASE_URL   default http://localhost:3000/   (keep the trailing slash: it is the router basename)
//   E2E_USERNAME / E2E_PASSWORD   default: the development account created by the seed
export default defineConfig({
  testDir: "./e2e",
  fullyParallel: false,
  workers: 1, // the Gateway rate-limits sign-ins per address
  retries: 0,
  reporter: [["list"]],
  use: {
    baseURL: process.env.E2E_BASE_URL ?? "http://localhost:3000/",
    trace: "retain-on-failure",
  },
  projects: [{ name: "chromium", use: { ...devices["Desktop Chrome"] } }],
});
