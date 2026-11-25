import { expect, test, type Page } from "@playwright/test";
import { moveTo, signIn } from "./support";

// PR C / ADR-0137 §5: refusals are explicit, generic and named; an error stays inside its screen.
let page: Page;
let basePath: string;
test.describe.configure({ mode: "serial" });

test.beforeAll(async ({ browser, baseURL }) => {
  basePath = new URL(baseURL!).pathname;
  page = await signIn(browser, baseURL!, "auditor");
});
test.afterAll(async () => page.close());

test("a destination without the capability answers 403 and names the capability (never another screen)", async () => {
  await moveTo(page, basePath, "/security");
  const refusal = page.locator('[data-status="403"]');
  await expect(refusal).toBeVisible();
  await expect(refusal).toHaveAttribute("role", "alert");
  await expect(refusal).toContainText("accounts.list");
  await expect(page.getByRole("navigation", { name: "Sections" }).locator('[aria-current="page"]')).toHaveCount(0);
});

test("the refused destination is not offered in the navigation", async () => {
  await expect(page.getByRole("navigation", { name: "Sections" }).getByRole("button", { name: "Sécurité" })).toHaveCount(0);
});

test("an unknown address answers an explicit 404 status page inside the shell", async () => {
  await moveTo(page, basePath, "/nope");
  const notFound = page.locator('[data-status="404"]');
  await expect(notFound).toBeVisible();
  await expect(notFound).toContainText("Page introuvable");
  await expect(page.getByRole("navigation", { name: "Sections" })).toBeVisible();
});

test("an allowed destination still renders after a refusal (the refusal does not stick)", async () => {
  await moveTo(page, basePath, "/overview");
  await expect(page.locator("[data-status]")).toHaveCount(0);
  await expect(page.getByRole("main")).toBeVisible();
});
