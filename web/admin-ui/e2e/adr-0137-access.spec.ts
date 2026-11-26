import { expect, test, type Page } from "@playwright/test";
import { expectTabsAreAddresses, moveTo, pathnameOf, signIn } from "./support";

// ADR-0137 — Accès privilégiés : onglets = sous-routes de /access, deep link restauré après la
// connexion, refus explicite (403) sans la capacité, 404 pour un onglet inconnu.
test.describe.configure({ mode: "serial" });

let page: Page;
let basePath: string;

test.beforeAll(async ({ browser, baseURL }) => {
  basePath = new URL(baseURL!).pathname;
  // The deep link is the first thing asked: the sign-in must return to it.
  page = await signIn(browser, baseURL!, "operator", "access/accounts");
});
test.afterAll(async () => page.close());

test("a deep link to an Access tab is restored after the sign-in", async () => {
  await expect.poll(() => pathnameOf(page, basePath)).toBe("/access/accounts");
  await expect(page.getByRole("tab", { name: /Comptes/ })).toHaveAttribute("aria-selected", "true");
  await expect(page.getByRole("navigation", { name: "Sections" }).locator('[aria-current="page"]')).toHaveAccessibleName("Accès privilégiés");
});

test("the tabs are addresses, Back/Forward walk them and an unknown tab is a 404", async () => {
  await expectTabsAreAddresses(page, basePath, {
    root: "/access",
    destination: "Accès privilégiés",
    tabs: [
      { id: "resources", label: /Ressources/ },
      { id: "accounts", label: /Comptes/ },
      { id: "policies", label: /Politiques/ },
    ],
  });
});

test("the confirmation of a privileged action is the shared alert dialog", async () => {
  await moveTo(page, basePath, "/access/accounts");
  const action = page.getByRole("button", { name: /Désactiver|Renouveler/ }).first();
  test.skip(!(await action.isEnabled().catch(() => false)), "no account to act on in this stack");
  await action.click();
  const dialog = page.getByRole("alertdialog");
  await expect(dialog).toBeVisible();
  // Focus starts on Cancel, never on the destructive control; Escape cancels without a request.
  await expect(dialog.getByRole("button", { name: "Annuler" })).toBeFocused();
  await page.keyboard.press("Escape");
  await expect(dialog).toBeHidden();
});

test("without the capability the address answers 403 naming it, and the navigation stays", async ({ browser, baseURL }) => {
  const auditor = await signIn(browser, baseURL!, process.env.E2E_AUDITOR_USERNAME ?? "auditor", "access/policies");
  await expect(auditor.getByText("Accès refusé")).toBeVisible();
  await expect(auditor.getByRole("main").getByText(/accounts\.list|policies\.create|sessions\.approve/)).toBeVisible();
  expect(pathnameOf(auditor, basePath)).toBe("/access/policies");
  await auditor.close();
});
