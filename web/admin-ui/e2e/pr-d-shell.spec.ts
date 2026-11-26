import { expect, test, type Page } from "@playwright/test";
import { moveTo, pathnameOf, signIn } from "./support";

// PR D / ADR-0137 §8: the shell is composed from @openbastion/ui; the application only supplies slots.
let page: Page;
let basePath: string;
test.describe.configure({ mode: "serial" });

test.beforeAll(async ({ browser, baseURL }) => {
  basePath = new URL(baseURL!).pathname;
  page = await signIn(browser, baseURL!);
});
test.afterAll(async () => page.close());
test.beforeEach(async () => {
  await page.setViewportSize({ width: 1280, height: 800 });
  await moveTo(page, basePath, "/overview");
});

test("one skip link, one navigation, one main landmark, one legal footer", async () => {
  await expect(page.locator("a.skip-link")).toHaveCount(1);
  await expect(page.getByRole("navigation", { name: "Sections" })).toHaveCount(1);
  await expect(page.locator("main#main-content")).toHaveCount(1);
  await expect(page.getByRole("contentinfo")).toHaveCount(1);
  await expect(page.locator("aside#admin-navigation")).toHaveCount(1);
});

test("the shell is not rebuilt between destinations (same sidebar node)", async () => {
  await page.evaluate(() => { (document.querySelector("#admin-navigation") as any).__marker = "kept"; });
  await page.getByRole("navigation", { name: "Sections" }).getByRole("button", { name: "Sessions", exact: true }).click();
  await expect.poll(() => pathnameOf(page, basePath)).toBe("/sessions/live");
  expect(await page.evaluate(() => (document.querySelector("#admin-navigation") as any).__marker)).toBe("kept");
  await expect(page.locator("main#main-content")).toBeFocused();
});

test("a favorite is toggled from the package navigation and listed in the Favoris group", async () => {
  const nav = page.getByRole("navigation", { name: "Sections" });
  await nav.getByRole("button", { name: "Ajouter Sessions aux favoris" }).click();
  const favorites = nav.locator(".nav-group", { has: page.getByRole("heading", { name: "Favoris" }) });
  await expect(favorites.getByRole("button", { name: "Sessions", exact: true })).toBeVisible();
  await favorites.locator(".nav-entry").hover();
  await favorites.getByRole("button", { name: "Retirer Sessions des favoris" }).click(); // restore the stored preference
  await expect(nav.getByRole("heading", { name: "Favoris" })).toHaveCount(0);
});

test("the sidebar collapses and the collapse control reports it", async () => {
  const toggle = page.locator(".sidebar-collapse-toggle");
  await toggle.click();
  await expect(page.locator(".app-workspace")).toHaveClass(/sidebar-collapsed/);
  await expect(toggle).toHaveAttribute("aria-expanded", "false");
  await toggle.click();
  await expect(page.locator(".app-workspace")).not.toHaveClass(/sidebar-collapsed/);
});

test("mobile navigation: one backdrop, modal dialog, Escape closes and returns the focus", async () => {
  await page.setViewportSize({ width: 390, height: 800 });
  const opener = page.locator(".mobile-menu-toggle");
  await opener.click();
  await expect(page.locator("aside#admin-navigation")).toHaveAttribute("role", "dialog");
  await expect(page.locator(".navigation-backdrop")).toHaveCount(1);
  await expect(page.locator("main#main-content")).toHaveAttribute("inert", "");
  await page.keyboard.press("Escape");
  await expect(page.locator(".navigation-backdrop")).toHaveCount(0);
  await expect(opener).toBeFocused();
});

test("mobile navigation: choosing a destination navigates and closes", async () => {
  await page.setViewportSize({ width: 390, height: 800 });
  await page.locator(".mobile-menu-toggle").click();
  await page.getByRole("navigation", { name: "Sections" }).getByRole("button", { name: "Sessions", exact: true }).click();
  await expect.poll(() => pathnameOf(page, basePath)).toBe("/sessions/live");
  await expect(page.locator(".navigation-backdrop")).toHaveCount(0);
});

test("the user menu is a slot of the sidebar and signs out last", async () => {
  await page.locator("aside#admin-navigation .user-menu-trigger, aside#admin-navigation [aria-haspopup]").first().click();
  await expect(page.getByRole("button", { name: /Se déconnecter|Déconnexion/, exact: true })).toBeVisible();
  await page.keyboard.press("Escape");
});
