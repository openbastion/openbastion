import { expect, type Browser, type Page } from "@playwright/test";

// The Gateway allows 5 sign-ins at once, then 1 per minute per address: each spec signs in once.
export async function signIn(browser: Browser, baseURL: string, username = "operator", path = ""): Promise<Page> {
  const page = await browser.newPage();
  await page.goto(new URL(path.replace(/^\//, ""), baseURL).toString());
  await page.getByLabel("Utilisateur").fill(username === "operator" ? process.env.E2E_USERNAME ?? "operator" : username);
  await page.getByLabel("Mot de passe").fill(process.env.E2E_PASSWORD ?? "openbastion-demo");
  await page.getByText("Se connecter").click();
  await expect(page.getByRole("navigation", { name: "Sections" })).toBeVisible();
  return page;
}

export const pathnameOf = (page: Page, basePath: string) => new URL(page.url()).pathname.replace(basePath, "/");

// Moves like the Back button does: through the history API, which the router follows.
export async function moveTo(page: Page, basePath: string, path: string) {
  await page.evaluate(([to]) => {
    window.history.pushState({}, "", to);
    window.dispatchEvent(new PopStateEvent("popstate"));
  }, [basePath.replace(/\/$/, "") + path]);
  // A destination with tabs redirects to its first tab: the address settles under `path`.
  await expect.poll(() => pathnameOf(page, basePath).startsWith(path)).toBe(true);
}

// ADR-0137 conformity of a page whose tabs are sub-routes: the bare address redirects to the first
// tab, each tab is its own address that Back/Forward walk, a deep link is restored, and an unknown
// tab answers with an explicit 404 that leaves no destination current.
export async function expectTabsAreAddresses(
  page: Page,
  basePath: string,
  { root, tabs, destination, secondTab }: {
    root: string;
    tabs: { id: string; label: RegExp }[];
    destination: string;
    secondTab?: string;
  },
) {
  const here = () => pathnameOf(page, basePath);
  const sections = page.getByRole("navigation", { name: "Sections" });

  // The bare address redirects (replace) to the first tab.
  await page.evaluate(([to]) => {
    window.history.pushState({}, "", to);
    window.dispatchEvent(new PopStateEvent("popstate"));
  }, [basePath.replace(/\/$/, "") + root]);
  await expect.poll(here).toBe(`${root}/${tabs[0].id}`);
  await expect(sections.locator('[aria-current="page"]')).toHaveAccessibleName(destination);
  await expect(page.getByRole("tab", { name: tabs[0].label })).toHaveAttribute("aria-selected", "true");

  // Choosing a tab changes the address; the address selects the tab.
  for (const tab of tabs.slice(1)) {
    await page.getByRole("tab", { name: tab.label }).click();
    await expect.poll(here).toBe(`${root}/${tab.id}`);
    await expect(page.getByRole("tab", { name: tab.label })).toHaveAttribute("aria-selected", "true");
  }

  // Back/Forward walk the tabs (the redirect replaced the bare address: Back never lands on it).
  const last = tabs[tabs.length - 1];
  const previous = tabs[tabs.length - 2];
  await page.goBack();
  await expect.poll(here).toBe(`${root}/${previous.id}`);
  await expect(page.getByRole("tab", { name: previous.label })).toHaveAttribute("aria-selected", "true");
  await page.goForward();
  await expect.poll(here).toBe(`${root}/${last.id}`);

  // A deep link to a tab opens that tab.
  const target = secondTab ?? tabs[1].id;
  await moveTo(page, basePath, `${root}/${target}`);
  await expect(page.getByRole("tab", { selected: true })).toBeVisible();
  await expect(page.getByRole("tab", { name: tabs.find((tab) => tab.id === target)!.label })).toHaveAttribute("aria-selected", "true");

  // An unknown tab is a 404, not another tab, and no destination is current.
  await moveTo(page, basePath, `${root}/nope`);
  await expect(page.getByText("Page introuvable")).toBeVisible();
  await expect(sections.locator('[aria-current="page"]')).toHaveCount(0);
}
