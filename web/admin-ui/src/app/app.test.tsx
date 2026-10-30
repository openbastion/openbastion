import { describe, expect, it, vi } from "vitest";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { App } from "./App";
import { fakeApi, fakeToken } from "../test-helpers";

describe("App", () => {
  it("shows the login, then the tabs once signed in, and forgets the token on sign-out", async () => {
    const token = fakeToken("alice", ["platform-admin"]);
    const { api } = fakeApi({ "POST /auth/login": { body: { accessToken: token, expiresIn: 3600 } }, "GET /vault/accounts": { body: { items: [], page: 1, pageSize: 20, totalItems: 0 } } });
    render(<App api={api} location={{ pathname: "/ui/", search: "" } as Location} navigate={vi.fn()} />);
    fireEvent.change(screen.getByLabelText("Utilisateur"), { target: { value: "alice" } });
    fireEvent.change(screen.getByLabelText("Mot de passe"), { target: { value: "pw" } });
    fireEvent.click(screen.getByText("Se connecter"));
    expect(await screen.findByText("alice (platform-admin)")).toBeTruthy();
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
