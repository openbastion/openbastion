import { expect, test, type Page } from "@playwright/test";
import { expectTabsAreAddresses, pathnameOf, signIn } from "./support";

// ADR-0137 — Audit & conformité : onglets = sous-routes de /audit (le nom de domaine est `audit`,
// la page « Sécurité » est /security — les clés stockées sont inversées, pas les URL).
test.describe.configure({ mode: "serial" });

let page: Page;
let basePath: string;

test.beforeAll(async ({ browser, baseURL }) => {
  basePath = new URL(baseURL!).pathname;
  page = await signIn(browser, baseURL!, "operator", "audit/evidence");
});
test.afterAll(async () => page.close());

test("a deep link to an Audit tab is restored after the sign-in", async () => {
  await expect.poll(() => pathnameOf(page, basePath)).toBe("/audit/evidence");
  await expect(page.getByRole("tab", { name: /Preuves/ })).toHaveAttribute("aria-selected", "true");
});

test("the tabs are addresses, Back/Forward walk them and an unknown tab is a 404", async () => {
  await expectTabsAreAddresses(page, basePath, {
    root: "/audit",
    destination: "Audit & conformité",
    tabs: [
      { id: "journal", label: /Journal d’audit/ },
      { id: "reports", label: /Rapports/ },
      { id: "evidence", label: /Preuves/ },
      { id: "retention", label: /rétention/ },
    ],
  });
});
