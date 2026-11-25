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
  await expect.poll(() => pathnameOf(page, basePath)).toBe(path);
}
