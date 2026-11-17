import { describe, expect, it, vi } from "vitest";
import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { App } from "./App";
import { fakeApi, fakeToken } from "../test-helpers";

describe("App", () => {
  it("keeps the token across renders when no client is given — the next call is authenticated", async () => {
    const token = fakeToken("alice", ["platform-admin"]);
    // Each call with the header it carried; the login page asks GET /auth/ldap first (ADR-0061).
    const calls: { path: string; auth: string | null }[] = [];
    const fetchSpy = vi.spyOn(globalThis, "fetch").mockImplementation(async (input, init) => {
      const headers = (init?.headers ?? {}) as Record<string, string>;
      calls.push({ path: String(input), auth: headers["Authorization"] ?? null });
      if (String(input) === "/auth/login") return new Response(JSON.stringify({ accessToken: token, expiresIn: 3600 }));
      return new Response(JSON.stringify({ items: [], page: 1, pageSize: 20, totalItems: 0 }));
    });
    render(<App location={{ pathname: "/ui/", search: "" } as Location} navigate={vi.fn()} />);
    fireEvent.change(screen.getByLabelText("Utilisateur"), { target: { value: "alice" } });
    fireEvent.change(screen.getByLabelText("Mot de passe"), { target: { value: "pw" } });
    fireEvent.click(screen.getByText("Se connecter"));
    const login = () => calls.findIndex((c) => c.path === "/auth/login");
    await waitFor(() => expect(login() >= 0 && calls.length > login() + 1).toBe(true));
    expect(calls[login() + 1].auth).toBe(`Bearer ${token}`);
    fetchSpy.mockRestore();
  });

  it("shows the login, then the tabs once signed in, and forgets the token on sign-out", async () => {
    const token = fakeToken("alice", ["platform-admin"]);
    const { api } = fakeApi({ "POST /auth/login": { body: { accessToken: token, expiresIn: 3600 } }, "GET /vault/accounts": { body: { items: [], page: 1, pageSize: 20, totalItems: 0 } } });
    render(<App api={api} location={{ pathname: "/ui/", search: "" } as Location} navigate={vi.fn()} />);
    fireEvent.change(screen.getByLabelText("Utilisateur"), { target: { value: "alice" } });
    fireEvent.change(screen.getByLabelText("Mot de passe"), { target: { value: "pw" } });
    fireEvent.click(screen.getByText("Se connecter"));
    expect(await screen.findByRole("button", { name: /alice.*platform-admin/ })).toBeTruthy();
    const navigation = screen.getByRole("navigation", { name: "Sections" });
    expect(within(navigation).getByRole("button", { name: "Vue générale" }).getAttribute("aria-current")).toBe("page");
    expect(screen.getByRole("link", { name: "Aller au contenu principal" }).getAttribute("href")).toBe("#main-content");
    expect(screen.getByRole("main").parentElement?.classList.contains("app-content")).toBe(true);
    for (const label of ["Vue générale", "Comptes", "Politiques", "Sessions", "Enregistrements", "Centre de sécurité"]) {
      const button = within(navigation).getByRole("button", { name: label });
      expect(button.querySelector("svg")?.getAttribute("aria-hidden")).toBe("true");
    }
    expect(window.localStorage.length + window.sessionStorage.length).toBe(0);
    expect(screen.getByRole("button", { name: "Ouvrir la recherche et les commandes" })).toBeTruthy();
    expect(screen.getByRole("link", { name: "Documentation" }).getAttribute("href")).toContain("/tree/main/docs");
    expect(screen.getByRole("link", { name: "Centre d'aide" }).getAttribute("href")).toContain("/tree/main/docs/user-guide");
    const notifications = screen.getByRole("button", { name: "Ouvrir les notifications" });
    fireEvent.click(notifications);
    expect(screen.getByRole("region", { name: "Notifications" })).toBeTruthy();
    expect(screen.getByText("Aucune notification à afficher")).toBeTruthy();
    expect(screen.getByText(/Aucune alerte n'est simulée/)).toBeTruthy();
    fireEvent.keyDown(document, { key: "Escape" });
    expect(screen.queryByRole("region", { name: "Notifications" })).toBeNull();

    // The shell exposes accessible collapse, mobile and theme controls without persisting state.
    const collapse = screen.getByRole("button", { name: "Réduire la navigation" });
    fireEvent.click(collapse);
    expect(screen.getByRole("button", { name: "Développer la navigation" })).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: "Développer la navigation" }));
    fireEvent.click(screen.getByRole("button", { name: /alice.*platform-admin/ }));
    const darkTheme = screen.getByRole("button", { name: "Activer le thème sombre" });
    fireEvent.click(darkTheme);
    expect(document.documentElement.dataset.theme).toBe("dark");
    expect(screen.getByRole("button", { name: "Activer le thème clair" })).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: "Activer le thème clair" }));
    expect(document.documentElement.dataset.theme).toBe("light");
    fireEvent.click(screen.getByRole("button", { name: /alice.*platform-admin/ }));
    const openNavigation = screen.getByRole("button", { name: "Ouvrir la navigation" });
    fireEvent.click(openNavigation);
    const mobileDialog = screen.getByRole("dialog", { name: "Navigation principale" });
    expect(mobileDialog.getAttribute("aria-modal")).toBe("true");
    expect(screen.getAllByRole("banner")[0].hasAttribute("inert")).toBe(true);
    expect(screen.getByRole("main").hasAttribute("inert")).toBe(true);
    const mobileNavigation = within(mobileDialog).getByRole("navigation", { name: "Sections" });
    const firstNavigationItem = within(mobileNavigation).getByRole("button", { name: "Vue générale" });
    expect(document.activeElement).toBe(firstNavigationItem);
    const sidebarUserMenu = within(mobileDialog).getByRole("button", { name: /alice.*platform-admin/ });
    fireEvent.keyDown(firstNavigationItem, { key: "Tab", shiftKey: true });
    expect(document.activeElement).toBe(sidebarUserMenu);
    fireEvent.keyDown(sidebarUserMenu, { key: "Tab" });
    expect(document.activeElement).toBe(firstNavigationItem);
    fireEvent.keyDown(document, { key: "Escape" });
    const restoredMenuButton = screen.getByRole("button", { name: "Ouvrir la navigation" });
    expect(restoredMenuButton).toBeTruthy();
    expect(document.activeElement).toBe(restoredMenuButton);
    expect(screen.getByRole("main").hasAttribute("inert")).toBe(false);

    fireEvent.click(restoredMenuButton);
    const accountsNavigationItem = within(screen.getByRole("dialog", { name: "Navigation principale" }))
      .getByRole("button", { name: "Comptes" });
    fireEvent.click(accountsNavigationItem);
    expect(document.activeElement).toBe(restoredMenuButton);
    expect(screen.getByRole("main").hasAttribute("inert")).toBe(false);

    const legalFooter = screen.getByRole("contentinfo", { name: "Informations légales" });
    expect(legalFooter.parentElement?.classList.contains("app-workspace")).toBe(true);
    expect(legalFooter.classList.contains("legal-notice")).toBe(true);
    expect(screen.getByRole("main").parentElement?.classList.contains("app-content")).toBe(true);
    expect(screen.getByRole("link", { name: /Code source/ }).getAttribute("href")).toContain("github.com/openbastion/openbastion");
    expect(screen.getByRole("link", { name: "Texte de la licence" }).getAttribute("href")).toContain("/LICENSE");
    fireEvent.click(screen.getByRole("button", { name: /alice.*platform-admin/ }));
    fireEvent.click(screen.getByRole("button", { name: "Se déconnecter" }));
    await waitFor(() => expect(screen.getByLabelText("Utilisateur")).toBeTruthy());
    expect(api.hasToken()).toBe(false);
  });

  it("shows the AGPL source and licence links alongside the login legal links", () => {
    render(<App location={{ pathname: "/ui/", search: "" } as Location} navigate={vi.fn()} />);
    expect(screen.queryByRole("contentinfo", { name: "Informations légales" })).toBeNull();
    const source = screen.getByRole("link", { name: /Code source/ });
    const license = screen.getByRole("link", { name: "Texte de la licence" });
    expect(source.parentElement?.classList.contains("login-license-links")).toBe(true);
    expect(license.parentElement).toBe(source.parentElement);
    expect(screen.getByText(/GNU Affero General Public License v3.0/)).toBeTruthy();
  });

  it("is the OIDC return page at /ui/oidc/callback", async () => {
    vi.spyOn(window.history, "replaceState").mockImplementation(() => {});
    const { api } = fakeApi({ "POST /auth/oidc/callback": { body: { accessToken: fakeToken("oidc:sub-1", ["dba"]), expiresIn: 3600 } }, "GET /vault/accounts": { body: { items: [], page: 1, pageSize: 20, totalItems: 0 } } });
    render(<App api={api} location={{ pathname: "/ui/oidc/callback", search: "?code=c&state=s" } as Location} navigate={vi.fn()} />);
    expect(await screen.findByRole("button", { name: /oidc:sub-1.*dba/ })).toBeTruthy();
  });
});

describe("Command palette — ADR-0073 UX-02", () => {
  async function signIn(api: ReturnType<typeof fakeApi>["api"]) {
    render(<App api={api} location={{ pathname: "/ui/", search: "" } as Location} navigate={vi.fn()} />);
    fireEvent.change(screen.getByLabelText("Utilisateur"), { target: { value: "alice" } });
    fireEvent.change(screen.getByLabelText("Mot de passe"), { target: { value: "pw" } });
    fireEvent.click(screen.getByText("Se connecter"));
    expect(await screen.findByRole("button", { name: /alice.*platform-admin/ })).toBeTruthy();
  }

  it("opens with Ctrl+K, searches a session through the public API and displays its detail", async () => {
    const session = {
      id: "sess_42", status: "active", protocol: "ssh", requestedBy: "alice", privilegedAccountId: "acc_prod",
      justification: "incident 42", breakGlass: false, expiresAt: "2026-11-12T11:00:00Z",
    };
    const { api, calls } = fakeApi({
      "POST /auth/login": { body: { accessToken: fakeToken("alice", ["platform-admin"]), expiresIn: 3600 } },
      "GET /vault/accounts": { body: { items: [], page: 1, pageSize: 100, totalItems: 0 } },
      "GET /sessions?status=pending_approval": { body: { items: [], page: 1, pageSize: 100, totalItems: 0 } },
      "GET /sessions/sess_42": { body: session },
    });
    await signIn(api);
    fireEvent.keyDown(document, { key: "k", ctrlKey: true });
    const query = await screen.findByRole("combobox", { name: "Rechercher une section ou une session" }); // the palette opens after a render
    expect(document.activeElement).toBe(query);
    fireEvent.change(query, { target: { value: "sess_42" } });
    fireEvent.keyDown(query, { key: "Enter" });
    expect(await screen.findByText("incident 42")).toBeTruthy();
    expect(calls.some((call) => call.method === "GET" && call.path === "/sessions/sess_42")).toBe(true);
    expect(screen.queryByRole("dialog")).toBeNull();
  });

  it("keeps authorization authoritative when a session lookup is refused", async () => {
    const { api, calls } = fakeApi({
      "POST /auth/login": { body: { accessToken: fakeToken("alice", ["platform-admin"]), expiresIn: 3600 } },
      "GET /vault/accounts": { body: { items: [], page: 1, pageSize: 20, totalItems: 0 } },
      "GET /sessions?status=pending_approval": { body: { items: [], page: 1, pageSize: 50, totalItems: 0 } },
      "GET /sessions/private-session": { status: 403, body: "forbidden" },
    });
    await signIn(api);
    fireEvent.keyDown(document, { key: "k", metaKey: true });
    const query = await screen.findByRole("combobox", { name: "Rechercher une section ou une session" }); // the palette opens after a render
    fireEvent.change(query, { target: { value: "private-session" } });
    fireEvent.keyDown(query, { key: "Enter" });
    expect((await screen.findByRole("alert")).textContent).toContain("403 — forbidden");
    expect(calls.some((call) => call.method === "GET" && call.path === "/sessions/private-session")).toBe(true);
  });

  it("filters navigation commands and restores focus when the palette is cancelled", async () => {
    const { api, calls } = fakeApi({
      "POST /auth/login": { body: { accessToken: fakeToken("alice", ["platform-admin"]), expiresIn: 3600 } },
      "GET /vault/accounts": { body: { items: [], page: 1, pageSize: 100, totalItems: 0 } },
      "GET /sessions?status=pending_approval": { body: { items: [], page: 1, pageSize: 100, totalItems: 0 } },
    });
    await signIn(api);
    const trigger = screen.getByRole("button", { name: "Ouvrir la recherche et les commandes" });
    fireEvent.click(trigger);
    const query = await screen.findByRole("combobox", { name: "Rechercher une section ou une session" }); // the palette opens after a render
    fireEvent.change(query, { target: { value: "politiques" } });
    expect(screen.getByRole("option", { name: /Politiques/ })).toBeTruthy();
    expect(screen.queryByRole("option", { name: /Comptes privilégiés/ })).toBeNull();
    fireEvent.keyDown(query, { key: "Tab", shiftKey: true });
    const close = screen.getByRole("button", { name: "Fermer" });
    expect(document.activeElement).toBe(close);
    fireEvent.keyDown(close, { key: "Tab" });
    expect(document.activeElement).toBe(query);
    fireEvent.keyDown(query, { key: "Escape" });
    expect(screen.queryByRole("dialog")).toBeNull();
    await waitFor(() => expect(document.activeElement).toBe(trigger));
    expect(calls.filter((call) => call.method === "GET" && call.path.startsWith("/sessions/")).length).toBe(0);
  });
});
