import { describe, expect, it, vi } from "vitest";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { Login } from "./Login";
import { OidcCallback } from "./OidcCallback";
import { fakeApi } from "../../test-helpers";

describe("Login", () => {
  it("logs in with a local account and hands the token on", async () => {
    const { api, calls } = fakeApi({ "POST /auth/login": { body: { accessToken: "tok", expiresIn: 3600 } } });
    const onToken = vi.fn();
    render(<Login api={api} onToken={onToken} navigate={vi.fn()} />);
    fireEvent.change(screen.getByLabelText("Utilisateur"), { target: { value: "alice" } });
    fireEvent.change(screen.getByLabelText("Mot de passe"), { target: { value: "pw-123" } });
    fireEvent.click(screen.getByText("Se connecter"));
    await waitFor(() => expect(onToken).toHaveBeenCalledWith("tok"));
    expect(calls.find((c) => c.method === "POST")?.body).toEqual({ username: "alice", password: "pw-123" });
  });

  it("offers the directory when the Gateway says it is on, and logs in through it by default", async () => {
    const { api, calls } = fakeApi({
      "GET /auth/ldap": { body: { enabled: true } },
      "POST /auth/ldap/login": { body: { accessToken: "dir-tok", expiresIn: 3600 } },
    });
    const onToken = vi.fn();
    render(<Login api={api} onToken={onToken} navigate={vi.fn()} />);
    const directory = await screen.findByLabelText("Annuaire de l'entreprise");
    await waitFor(() => expect((directory as HTMLInputElement).checked).toBe(true));
    fireEvent.change(screen.getByLabelText("Utilisateur"), { target: { value: "alice" } });
    fireEvent.change(screen.getByLabelText("Mot de passe"), { target: { value: "dir-pw" } });
    fireEvent.click(screen.getByText("Se connecter"));
    await waitFor(() => expect(onToken).toHaveBeenCalledWith("dir-tok"));
    const post = calls.filter((c) => c.method === "POST");
    expect(post).toHaveLength(1);
    expect(post[0].path).toBe("/auth/ldap/login");
    expect(post[0].body).toEqual({ username: "alice", password: "dir-pw" });
  });

  it("logs in locally when the local account is chosen, the directory on", async () => {
    const { api, calls } = fakeApi({
      "GET /auth/ldap": { body: { enabled: true } },
      "POST /auth/login": { body: { accessToken: "local-tok", expiresIn: 3600 } },
    });
    const onToken = vi.fn();
    render(<Login api={api} onToken={onToken} navigate={vi.fn()} />);
    fireEvent.click(await screen.findByLabelText("Compte local"));
    fireEvent.change(screen.getByLabelText("Utilisateur"), { target: { value: "admin" } });
    fireEvent.change(screen.getByLabelText("Mot de passe"), { target: { value: "pw" } });
    fireEvent.click(screen.getByText("Se connecter"));
    await waitFor(() => expect(onToken).toHaveBeenCalledWith("local-tok"));
    expect(calls.filter((c) => c.method === "POST").map((c) => c.path)).toEqual(["/auth/login"]);
  });

  it("shows no directory choice when the Gateway does not say it is on", async () => {
    const { api, calls } = fakeApi({ "GET /auth/ldap": { body: { enabled: false } } });
    render(<Login api={api} onToken={vi.fn()} navigate={vi.fn()} />);
    await waitFor(() => expect(calls.some((c) => c.path === "/auth/ldap")).toBe(true));
    expect(screen.queryByLabelText("Annuaire de l'entreprise")).toBeNull();
  });

  it("says why a login is refused", async () => {
    const { api } = fakeApi({ "POST /auth/login": { status: 401, body: "invalid credentials" } });
    render(<Login api={api} onToken={vi.fn()} navigate={vi.fn()} />);
    fireEvent.change(screen.getByLabelText("Utilisateur"), { target: { value: "a" } });
    fireEvent.change(screen.getByLabelText("Mot de passe"), { target: { value: "b" } });
    fireEvent.click(screen.getByText("Se connecter"));
    expect((await screen.findByRole("alert")).textContent).toContain("401 — invalid credentials");
  });

  it("starts a federated login by going to the provider's URL", async () => {
    const { api } = fakeApi({ "POST /auth/oidc/start": { body: { authorizationUrl: "https://idp.example/authorize?state=s" } } });
    const navigate = vi.fn();
    render(<Login api={api} onToken={vi.fn()} navigate={navigate} />);
    fireEvent.click(screen.getByText("Se connecter avec le fournisseur d'identité"));
    await waitFor(() => expect(navigate).toHaveBeenCalledWith("https://idp.example/authorize?state=s"));
  });
});

describe("OidcCallback", () => {
  const at = (search: string) => ({ pathname: "/ui/oidc/callback", search }) as Location;

  it("wipes code and state from the address bar before sending them, once", async () => {
    const order: string[] = [];
    const replace = vi.spyOn(window.history, "replaceState").mockImplementation(() => order.push("replaceState"));
    const { api, calls } = fakeApi({ "POST /auth/oidc/callback": { body: { accessToken: "tok", expiresIn: 3600 } } });
    const request = api.request.bind(api);
    api.request = ((...a: Parameters<typeof request>) => (order.push("request"), request(...a))) as typeof api.request;
    const onToken = vi.fn();
    render(<OidcCallback api={api} onToken={onToken} location={at("?code=c-1&state=s-1")} />);
    await waitFor(() => expect(onToken).toHaveBeenCalledWith("tok"));
    expect(order).toEqual(["replaceState", "request"]);
    expect(replace).toHaveBeenCalledWith(null, "", "/ui/");
    expect(calls).toHaveLength(1);
    expect(calls[0].body).toEqual({ code: "c-1", state: "s-1" });
    replace.mockRestore();
  });

  it("sends nothing when the provider refused, or the return is incomplete", async () => {
    vi.spyOn(window.history, "replaceState").mockImplementation(() => {});
    for (const search of ["?error=access_denied&state=s", "?code=c", "?state=s"]) {
      const { api, calls } = fakeApi({});
      const { unmount } = render(<OidcCallback api={api} onToken={vi.fn()} location={at(search)} />);
      expect(await screen.findByRole("alert")).toBeTruthy();
      expect(calls).toHaveLength(0);
      unmount();
    }
  });
});
