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
    expect(await screen.findByText("alice (platform-admin)")).toBeTruthy();
    const navigation = screen.getByRole("navigation", { name: "Sections" });
    for (const label of ["Comptes", "Politiques", "Sessions", "Enregistrements"]) {
      const button = within(navigation).getByRole("button", { name: label });
      expect(button.querySelector("svg")?.getAttribute("aria-hidden")).toBe("true");
    }
    expect(window.localStorage.length + window.sessionStorage.length).toBe(0);
    expect(screen.getByRole("contentinfo", { name: "Informations légales" })).toBeTruthy();
    expect(screen.getByRole("link", { name: /Code source/ }).getAttribute("href")).toContain("github.com/openbastion/openbastion");
    expect(screen.getByRole("link", { name: "Texte de la licence" }).getAttribute("href")).toContain("/LICENSE");
    fireEvent.click(screen.getByText("Se déconnecter"));
    await waitFor(() => expect(screen.getByLabelText("Utilisateur")).toBeTruthy());
    expect(api.hasToken()).toBe(false);
  });

  it("shows the AGPL source and licence notice before authentication", () => {
    render(<App location={{ pathname: "/ui/", search: "" } as Location} navigate={vi.fn()} />);
    expect(screen.getByRole("contentinfo", { name: "Informations légales" })).toBeTruthy();
    expect(screen.getByRole("link", { name: /Code source/ })).toBeTruthy();
  });

  it("is the OIDC return page at /ui/oidc/callback", async () => {
    vi.spyOn(window.history, "replaceState").mockImplementation(() => {});
    const { api } = fakeApi({ "POST /auth/oidc/callback": { body: { accessToken: fakeToken("oidc:sub-1", ["dba"]), expiresIn: 3600 } }, "GET /vault/accounts": { body: { items: [], page: 1, pageSize: 20, totalItems: 0 } } });
    render(<App api={api} location={{ pathname: "/ui/oidc/callback", search: "?code=c&state=s" } as Location} navigate={vi.fn()} />);
    expect(await screen.findByText("oidc:sub-1 (dba)")).toBeTruthy();
  });
});
