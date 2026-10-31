import { describe, expect, it, vi } from "vitest";
import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { App } from "./App";
import { fakeApi, fakeToken } from "../test-helpers";

describe("App", () => {
  it("keeps the token across renders when no client is given — the next call is authenticated", async () => {
    const token = fakeToken("alice", ["platform-admin"]);
    const auth: (string | null)[] = [];
    const fetchSpy = vi.spyOn(globalThis, "fetch").mockImplementation(async (input, init) => {
      const headers = (init?.headers ?? {}) as Record<string, string>;
      auth.push(headers["Authorization"] ?? null);
      if (String(input) === "/auth/login") return new Response(JSON.stringify({ accessToken: token, expiresIn: 3600 }));
      return new Response(JSON.stringify({ items: [], page: 1, pageSize: 20, totalItems: 0 }));
    });
    render(<App location={{ pathname: "/ui/", search: "" } as Location} navigate={vi.fn()} />);
    fireEvent.change(screen.getByLabelText("Utilisateur"), { target: { value: "alice" } });
    fireEvent.change(screen.getByLabelText("Mot de passe"), { target: { value: "pw" } });
    fireEvent.click(screen.getByText("Se connecter"));
    await waitFor(() => expect(auth.length).toBeGreaterThanOrEqual(2));
    expect(auth[1]).toBe(`Bearer ${token}`);
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
    fireEvent.click(screen.getByText("Se déconnecter"));
    await waitFor(() => expect(screen.getByLabelText("Utilisateur")).toBeTruthy());
    expect(api.hasToken()).toBe(false);
  });

  it("is the OIDC return page at /ui/oidc/callback", async () => {
    vi.spyOn(window.history, "replaceState").mockImplementation(() => {});
    const { api } = fakeApi({ "POST /auth/oidc/callback": { body: { accessToken: fakeToken("oidc:sub-1", ["dba"]), expiresIn: 3600 } }, "GET /vault/accounts": { body: { items: [], page: 1, pageSize: 20, totalItems: 0 } } });
    render(<App api={api} location={{ pathname: "/ui/oidc/callback", search: "?code=c&state=s" } as Location} navigate={vi.fn()} />);
    expect(await screen.findByText("oidc:sub-1 (dba)")).toBeTruthy();
  });
});
