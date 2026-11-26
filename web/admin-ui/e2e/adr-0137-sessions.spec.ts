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

// ADR-0142 — les éléments de la maquette sans contrat d'API sont simulés ET signalés.
test("the simulated live sessions are marked, inspectable and taken over without any API call", async () => {
  await moveTo(page, basePath, "/sessions/live");
  const panel = page.getByRole("region", { name: "Sessions actives" });
  await expect(panel.getByText("Données simulées").first()).toBeVisible();
  await expect(panel.getByRole("cell", { name: /24 ms/ })).toBeVisible();

  const writes: string[] = [];
  page.on("request", (request) => { if (request.method() !== "GET") writes.push(request.url()); });

  await panel.getByRole("button", { name: /Inspecter la session sim_8f21c0/ }).click();
  const drawer = page.getByRole("dialog", { name: /Inspection de sim_8f21c0/ });
  await expect(drawer).toBeVisible();
  await page.keyboard.press("Escape");
  await expect(drawer).toBeHidden();

  await panel.getByRole("button", { name: /Prise en main \(Partagé\) de la session sim_a93d77/ }).click();
  await page.getByRole("alertdialog").getByRole("button", { name: "Prendre la main" }).click();
  await expect(panel.getByText(/Prise en main · Partagé/)).toBeVisible();

  expect(writes).toEqual([]);
  expect(pathnameOf(page, basePath)).toBe("/sessions/live");
});
