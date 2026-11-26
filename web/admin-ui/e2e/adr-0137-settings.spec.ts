import { expect, test, type Page } from "@playwright/test";
import { expectTabsAreAddresses, pathnameOf, signIn } from "./support";

// ADR-0137 — Paramètres : onglets = sous-routes de /settings.
test.describe.configure({ mode: "serial" });

let page: Page;
let basePath: string;

test.beforeAll(async ({ browser, baseURL }) => {
  basePath = new URL(baseURL!).pathname;
  page = await signIn(browser, baseURL!, "operator", "settings/integrations");
});
test.afterAll(async () => page.close());

test("a deep link to a Settings tab is restored after the sign-in", async () => {
  await expect.poll(() => pathnameOf(page, basePath)).toBe("/settings/integrations");
  await expect(page.getByRole("tab", { selected: true })).toBeVisible();
});

test("the tabs are addresses, Back/Forward walk them and an unknown tab is a 404", async () => {
  await expectTabsAreAddresses(page, basePath, {
    root: "/settings",
    destination: "Paramètres",
    tabs: [
      { id: "general", label: /Général/ },
      { id: "security", label: /Sécurité/ },
      { id: "identities", label: /Identités/ },
      { id: "integrations", label: /Intégrations/ },
      { id: "notifications", label: /Notifications/ },
    ],
  });
});
