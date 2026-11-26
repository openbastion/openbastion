import { expect, test } from "@playwright/test";
import { pathnameOf, signIn } from "./support";

// PR E / ADR-0137 §1-§4: addressable routes under the basename, explicit 404, Back/Forward, the
// requested address restored after authentication, and no token in any storage.
test.describe.configure({ mode: "serial" });

test("a deep link signs in and then lands on the requested address, not the default screen", async ({ browser, baseURL }) => {
  const basePath = new URL(baseURL!).pathname;
  const page = await signIn(browser, baseURL!, "operator", "sessions");
  await expect.poll(() => pathnameOf(page, basePath)).toBe("/sessions/live");
  await expect(page.getByRole("navigation", { name: "Sections" }).locator('[aria-current="page"]')).toHaveAccessibleName("Sessions");

  // Back/Forward follow the address.
  await page.getByRole("navigation", { name: "Sections" }).getByRole("button", { name: "Infrastructure", exact: true }).click();
  await expect.poll(() => pathnameOf(page, basePath)).toBe("/infrastructure");
  await page.goBack();
  await expect.poll(() => pathnameOf(page, basePath)).toBe("/sessions/live");
  await page.goForward();
  await expect.poll(() => pathnameOf(page, basePath)).toBe("/infrastructure");

  // Every destination is its own address, taken from navigation.ts.
  for (const [label, path] of [["Vue d’ensemble", "/overview"], ["Accès privilégiés", "/access"], ["Audit & conformité", "/audit/journal"], ["Sécurité", "/security"], ["Paramètres", "/settings"]]) {
    await page.getByRole("navigation", { name: "Sections" }).getByRole("button", { name: label, exact: true }).click();
    await expect.poll(() => pathnameOf(page, basePath)).toBe(path);
  }

  // The access token lives in memory only.
  const stored = await page.evaluate(() => JSON.stringify({ ...localStorage }) + JSON.stringify({ ...sessionStorage }) + document.cookie);
  expect(stored).not.toMatch(/eyJ[A-Za-z0-9_-]{10,}\./);
  expect(stored.toLowerCase()).not.toContain("token");

  // A reload signs out (memory only) and keeps the requested address for after the next sign-in.
  await page.reload();
  await expect(page.getByLabel("Utilisateur")).toBeVisible();
  expect(pathnameOf(page, basePath)).toBe("/settings/general");
  await page.close();
});

test("the router and the palette share the one navigation table", async ({ browser, baseURL }) => {
  const basePath = new URL(baseURL!).pathname;
  const page = await signIn(browser, baseURL!);
  await page.keyboard.press("Control+k");
  const palette = page.getByRole("dialog", { name: /palette|commande/i });
  await expect(palette).toBeVisible();
  await page.keyboard.type("Infra");
  await page.keyboard.press("Enter");
  await expect.poll(() => pathnameOf(page, basePath)).toBe("/infrastructure");
  await page.close();
});
