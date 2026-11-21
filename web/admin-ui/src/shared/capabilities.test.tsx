import { describe, expect, it, vi } from "vitest";
import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { ReactNode } from "react";
import { App } from "../app/App";
import { Accounts } from "../features/accounts/Accounts";
import { Sessions } from "../features/sessions/Sessions";
import { SessionDetail } from "../features/sessions/SessionDetail";
import { Api } from "./api";
import { CapabilitiesContext, capabilitiesFrom, parseCapabilities } from "./capabilities";
import { SignedInContext } from "./session";
import { fakeApi, fakeToken } from "../test-helpers";

// ADR-0131 and the owner's rule (2026-11-20): a page or tab with nothing for the caller is
// absent; an action the caller may not take is greyed and says what it needs. The server still
// decides every action: these tests prove what the page shows, never what it may do.

const none = {
  "accounts.list": false, "accounts.onboard": false, "accounts.rotate": false, "accounts.disable": false,
  "accounts.pin": false, "accounts.approval": false, "accounts.screenProfile": false, "accounts.kerberos": false, "policies.create": false, "sessions.create": false,
  "sessions.breakglass": false, "sessions.approve": false, "sessions.read": false, "sessions.terminate": false,
  "secrets.inject": false, "secrets.paste": false, "recordings.read": false, "audit.secretInjections": false,
};
const account = { id: "acc_1", name: "web", username: "root", targetHost: "10.0.0.1:22", protocol: "ssh", rotationPolicy: "manual", createdAt: "2026-01-01T00:00:00Z", hostKeyFingerprint: "SHA256:x" };
const accountsPage = { items: [account], page: 1, pageSize: 20, totalItems: 1 };
const emptyPage = { items: [], page: 1, pageSize: 20, totalItems: 0 };

function signIn(api: Api) {
  render(<App api={api} location={{ pathname: "/ui/", search: "" } as Location} navigate={vi.fn()} />);
  fireEvent.change(screen.getByLabelText("Utilisateur"), { target: { value: "alice" } });
  fireEvent.change(screen.getByLabelText("Mot de passe"), { target: { value: "pw" } });
  fireEvent.click(screen.getByText("Se connecter"));
}

function within_(granted: Partial<typeof none>, node: ReactNode, api: Api, sub = "user_1") {
  return render(
    <SignedInContext.Provider value={{ api, who: { sub, username: "alice", roles: ["ops"], exp: 9999999999 }, signOut: () => {} }}>
      <CapabilitiesContext.Provider value={capabilitiesFrom("ready", { ...none, ...granted })}>{node}</CapabilitiesContext.Provider>
    </SignedInContext.Provider>,
  );
}

describe("capabilities in the Admin UI", () => {
  it("asks GET /auth/me/capabilities after login and leaves out the pages the caller has nothing for", async () => {
    const token = fakeToken("alice", ["ops"]);
    const { api, calls } = fakeApi({
      "POST /auth/login": { body: { accessToken: token, expiresIn: 3600 } },
      "GET /auth/me/capabilities": { body: { capabilities: { ...none, "sessions.create": true } } },
      "GET /sessions": { body: emptyPage },
    });
    signIn(api);
    const navigation = await screen.findByRole("navigation", { name: "Sections" });
    await waitFor(() => expect(within(navigation).queryByRole("button", { name: "Accès privilégiés" })).toBeNull());
    expect(within(navigation).queryByRole("button", { name: "Sécurité" })).toBeNull();
    expect(within(navigation).getByRole("button", { name: "Sessions" })).toBeTruthy();
    expect(calls.find((c) => c.path === "/auth/me/capabilities")?.auth).toBe(`Bearer ${token}`);
    // The overview does not ask for an inventory it would be refused.
    expect(calls.some((c) => c.path.startsWith("/vault/accounts"))).toBe(false);
    // Nor does the palette offer the page.
    fireEvent.click(screen.getByRole("button", { name: "Ouvrir la recherche et les commandes" }));
    expect(screen.queryByRole("option", { name: /Comptes privilégiés/ })).toBeNull();
  });

  it("greys every gated action and says why when the capabilities cannot be read", async () => {
    const token = fakeToken("alice", ["ops"]);
    const { api } = fakeApi({
      "POST /auth/login": { body: { accessToken: token, expiresIn: 3600 } },
      "GET /auth/me/capabilities": { status: 503, body: "capabilities unavailable" },
      "GET /sessions": { body: emptyPage },
    });
    signIn(api);
    expect(await screen.findByText(/Vos droits n'ont pas pu être chargés : les actions sont grisées/)).toBeTruthy();
    const navigation = screen.getByRole("navigation", { name: "Sections" });
    fireEvent.click(within(navigation).getByRole("button", { name: "Sessions" }));
    const request = await screen.findByRole("button", { name: "Nouvelle demande" });
    expect((request as HTMLButtonElement).disabled).toBe(true);
  });

  it("shows on Accès privilégiés only the tabs and actions the caller's policies open", async () => {
    const { api } = fakeApi({ "GET /vault/accounts": { body: accountsPage }, "GET /sessions": { body: emptyPage } });
    within_({ "accounts.list": true, "accounts.rotate": true }, <Accounts />, api);
    expect(await screen.findByRole("tab", { name: /Ressources/ })).toBeTruthy();
    expect(screen.getByRole("tab", { name: /Comptes/ })).toBeTruthy();
    expect(screen.queryByRole("tab", { name: /Politiques/ })).toBeNull();
    expect(screen.queryByRole("tab", { name: /Demandes/ })).toBeNull();
    const onboard = screen.getByRole("button", { name: "Enregistrer un compte" }) as HTMLButtonElement;
    expect(onboard.disabled).toBe(true);
    expect(onboard.closest("[title]")?.getAttribute("title")).toContain("enregistrer un compte");
    fireEvent.mouseDown(screen.getByRole("tab", { name: /Comptes/ }));
    fireEvent.click(screen.getByRole("tab", { name: /Comptes/ }));
    expect(((await screen.findByRole("button", { name: "Renouveler le secret" })) as HTMLButtonElement).disabled).toBe(false);
    expect((screen.getByRole("button", { name: "Désactiver" }) as HTMLButtonElement).disabled).toBe(true);
  });

  it("opens Accès privilégiés on the policies when that is all the caller may do", async () => {
    const { api, calls } = fakeApi({ "GET /sessions": { body: emptyPage } });
    within_({ "policies.create": true }, <Accounts />, api);
    expect(await screen.findByRole("form", { name: "Créer une politique" })).toBeTruthy();
    expect(screen.queryByRole("tab", { name: /Ressources/ })).toBeNull();
    expect(calls.some((c) => c.path.startsWith("/vault/accounts"))).toBe(false);
  });

  it("greys the session request and the decisions, and leaves out the recordings, for a caller without them", async () => {
    const pending = { id: "sess_9", status: "pending_approval", protocol: "ssh", requestedBy: "user_alice", privilegedAccountId: "acc_1", justification: "patch", breakGlass: false, approvalRequired: true, expiresAt: "2030-01-01T00:00:00Z" };
    const { api } = fakeApi({ "GET /sessions": { body: { items: [pending], page: 1, pageSize: 20, totalItems: 1 } } });
    within_({}, <Sessions />, api, "user_bob");
    expect(((await screen.findByRole("button", { name: "Approuver la session sess_9" })) as HTMLButtonElement).disabled).toBe(true);
    expect((screen.getByRole("button", { name: "Nouvelle demande" }) as HTMLButtonElement).disabled).toBe(true);
    expect(screen.queryByRole("tab", { name: "Enregistrements" })).toBeNull();
  });

  it("lets the requester end and open their own session, and greys both for someone else without the right", () => {
    const active = { id: "sess_1", status: "active", protocol: "rdp", requestedBy: "user_alice", privilegedAccountId: "acc_1", justification: "patch", breakGlass: false, expiresAt: "2030-01-01T00:00:00Z" };
    const { api } = fakeApi({});
    const mine = within_({}, <SessionDetail session={active} onOpenScreen={vi.fn()} onTerminate={vi.fn()} />, api, "user_alice");
    expect((screen.getByRole("button", { name: "Mettre fin" }) as HTMLButtonElement).disabled).toBe(false);
    expect((screen.getByRole("button", { name: "Ouvrir l'écran" }) as HTMLButtonElement).disabled).toBe(false);
    expect((screen.getByRole("button", { name: "Saisir le secret Vault" }) as HTMLButtonElement).disabled).toBe(true);
    mine.unmount();
    within_({}, <SessionDetail session={active} onOpenScreen={vi.fn()} onTerminate={vi.fn()} />, api, "user_bob");
    expect((screen.getByRole("button", { name: "Mettre fin" }) as HTMLButtonElement).disabled).toBe(true);
    expect((screen.getByRole("button", { name: "Ouvrir l'écran" }) as HTMLButtonElement).disabled).toBe(true);
  });

  it("takes nothing from the server's answer but known names with boolean values", () => {
    expect(parseCapabilities({ capabilities: { "accounts.list": true, "accounts.rotate": "yes", "root.everything": true } })).toEqual({ "accounts.list": true });
    expect(parseCapabilities(null)).toEqual({});
    const loading = capabilitiesFrom("loading");
    expect(loading.can("accounts.list")).toBe(false);
    expect(loading.visible("accounts.list")).toBe(true);
    expect(capabilitiesFrom("ready", { "accounts.list": false }).visible("accounts.list")).toBe(false);
  });
});
