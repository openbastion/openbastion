import { expect, test, type Page } from "@playwright/test";

// ADR-0137 §3: Ctrl/Meta+K opens the command palette; Alt+Shift+1..6 open the first six destinations
// of the single navigation declaration (app/navigation.ts), in sidebar order.
const destinations = [
  { digit: "1", path: "/overview", label: "Vue d’ensemble" },
  { digit: "2", path: "/access", label: "Accès privilégiés" },
  { digit: "3", path: "/sessions", label: "Sessions" },
  { digit: "4", path: "/infrastructure", label: "Infrastructure" },
  { digit: "5", path: "/audit", label: "Audit & conformité" },
  { digit: "6", path: "/security", label: "Sécurité" },
];

// The Gateway allows 5 sign-ins at once, then 1 per minute per address: sign in ONCE and share the page
// (the token lives in memory, so a reload would sign out). Tests move between screens with the
// history API, which the router follows like the Back button.
let page: Page;
let basePath: string;

test.describe.configure({ mode: "serial" });

test.beforeAll(async ({ browser, baseURL }) => {
  basePath = new URL(baseURL!).pathname;
  page = await browser.newPage();
  await page.addInitScript(() => window.localStorage.clear());
  await page.goto(baseURL!);
  await page.getByLabel("Utilisateur").fill(process.env.E2E_USERNAME ?? "operator");
  await page.getByLabel("Mot de passe").fill(process.env.E2E_PASSWORD ?? "openbastion-demo");
  await page.getByText("Se connecter").click();
  await expect(page.getByRole("navigation", { name: "Sections" })).toBeVisible();
});

test.afterAll(async () => page.close());

const pathname = () => new URL(page.url()).pathname.replace(basePath, "/");
const current = () => page.getByRole("navigation", { name: "Sections" }).locator('[aria-current="page"]');
const palette = () => page.getByRole("dialog", { name: /palette|commande/i });

async function moveTo(path: string) {
  await page.evaluate(([to]) => {
    window.history.pushState({}, "", to);
    window.dispatchEvent(new PopStateEvent("popstate"));
  }, [basePath.replace(/\/$/, "") + path]);
  await expect.poll(() => pathname().startsWith(path)).toBe(true);
  await page.locator("body").click({ position: { x: 1, y: 1 } }); // focus out of any control
}

test.beforeEach(async () => moveTo("/overview"));

for (const modifier of ["Control", "Meta"] as const) {
  test(`${modifier}+K opens the command palette and Escape closes it`, async () => {
    await page.keyboard.press(`${modifier}+k`);
    await expect(palette()).toBeVisible();
    await page.keyboard.press("Escape");
    await expect(palette()).toBeHidden();
  });
}

test("the root address lands on the stored default screen", async () => {
  await moveTo("/");
  await expect.poll(pathname).toBe("/overview");
  await expect(current()).toHaveAccessibleName("Vue d’ensemble");
});

for (const { digit, path, label } of destinations) {
  test(`Alt+Shift+${digit} opens ${label}`, async () => {
    // Start elsewhere so that the shortcut is observed to move, not to stay.
    await moveTo(destinations[Number(digit) % destinations.length].path);
    await page.keyboard.press(`Alt+Shift+${digit}`);
    await expect.poll(() => pathname().startsWith(path)).toBe(true);
    await expect(current()).toHaveAccessibleName(label);
  });
}

test("Alt+Shift+7 is not a destination shortcut", async () => {
  await page.keyboard.press("Alt+Shift+7");
  await page.waitForTimeout(300);
  expect(pathname()).toBe("/overview");
});

test("destination shortcuts are suspended while the palette is open", async () => {
  await page.keyboard.press("Control+k");
  await expect(palette()).toBeVisible();
  await page.keyboard.press("Alt+Shift+3");
  await page.waitForTimeout(300);
  expect(pathname()).toBe("/overview");
  await page.keyboard.press("Escape");
});

test("Back returns to the previous destination (the address is the state)", async () => {
  await page.keyboard.press("Alt+Shift+3");
  await expect.poll(pathname).toBe("/sessions/live");
  await page.goBack();
  await expect.poll(pathname).toBe("/overview");
});

test("an unknown address is an explicit 404, not another screen", async () => {
  await moveTo("/nope");
  await expect(page.getByText("Page introuvable")).toBeVisible();
  await expect(current()).toHaveCount(0);
});
