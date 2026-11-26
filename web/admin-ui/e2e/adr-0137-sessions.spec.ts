import { expect, test, type Page } from "@playwright/test";
import { expectTabsAreAddresses, moveTo, pathnameOf, signIn } from "./support";

// ADR-0137 — Sessions : onglets = sous-routes de /sessions ; la session ouverte vit dans un
// contexte React, jamais dans l'URL (§6) ; aucun jeton dans l'adresse.
test.describe.configure({ mode: "serial" });

let page: Page;
let basePath: string;

test.beforeAll(async ({ browser, baseURL }) => {
  basePath = new URL(baseURL!).pathname;
  page = await signIn(browser, baseURL!, "operator", "sessions/history");
});
test.afterAll(async () => page.close());

test("a deep link to a Sessions tab is restored after the sign-in", async () => {
  await expect.poll(() => pathnameOf(page, basePath)).toBe("/sessions/history");
  await expect(page.getByRole("tab", { name: /Historique/ })).toHaveAttribute("aria-selected", "true");
});

test("the tabs are addresses, Back/Forward walk them and an unknown tab is a 404", async () => {
  await expectTabsAreAddresses(page, basePath, {
    root: "/sessions",
    destination: "Sessions",
    tabs: [
      { id: "live", label: /En direct/ },
      { id: "history", label: /Historique/ },
      { id: "alerts", label: /Alertes/ },
    ],
  });
});

test("the address carries neither a session identifier, nor a token, nor a search", async () => {
  await moveTo(page, basePath, "/sessions/live");
  const url = new URL(page.url());
  expect(url.search).toBe("");
  expect(url.pathname + url.hash).not.toMatch(/sess_|eyJ/);
});
