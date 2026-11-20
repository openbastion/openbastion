import { describe, expect, it, vi } from "vitest";
import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { ReactNode } from "react";
import { Api } from "../shared/api";
import { SignedInContext } from "../shared/session";
import { Accounts } from "./accounts/Accounts";
import { Sessions } from "./sessions/Sessions";
import { screenChoice } from "./sessions/SessionDetail";
import { fakeApi } from "../test-helpers";

const signedIn = (api: Api, node: ReactNode) => render(<SignedInContext.Provider value={{ api, who: null, signOut: () => {} }}>{node}</SignedInContext.Provider>);
const page = (items: unknown[]) => ({ body: { items, page: 1, pageSize: 20, totalItems: items.length } });

function openAccountsTab() {
  fireEvent.mouseDown(screen.getByRole("tab", { name: /Comptes/ }), { button: 0 });
}

// ADR-0132: the administrator of an RDP account sets what its operators may choose.
describe("The screen profile of an RDP account", () => {
  const rdp = { id: "acc_r", name: "bureau", username: "ops", targetHost: "desk:3389", protocol: "rdp", rotationPolicy: "manual", createdAt: "2026-10-30T10:00:00Z" };
  const ssh = { ...rdp, id: "acc_s", name: "db", targetHost: "db:22", protocol: "ssh" };

  it("is offered on an RDP account only, and saved as the form says", async () => {
    const { api, calls } = fakeApi({ "GET /vault/accounts": page([rdp, ssh]), "PUT /vault/accounts/acc_r/screen-profile": { body: rdp } });
    signedIn(api, <Accounts />);
    openAccountsTab();
    expect(await screen.findAllByText("Profil d'écran")).toHaveLength(1);
    fireEvent.click(screen.getByText("Profil d'écran"));
    const dialog = await screen.findByRole("dialog");
    const form = within(dialog);
    // Without a profile, the form starts from everything allowed.
    expect((form.getByLabelText("Pipeline graphique") as HTMLInputElement).checked).toBe(true);
    fireEvent.click(form.getByLabelText("Pipeline graphique"));
    // The default channel is no longer allowed: said, and nothing can be sent.
    expect(form.getByText("Le canal par défaut doit être permis.")).toBeTruthy();
    expect((form.getByRole("button", { name: "Enregistrer le profil" }) as HTMLButtonElement).disabled).toBe(true);
    fireEvent.change(form.getByLabelText("Canal par défaut"), { target: { value: "bitmap" } });
    fireEvent.click(form.getByLabelText("32 bits"));
    fireEvent.change(form.getByLabelText("Profondeur par défaut"), { target: { value: "16" } });
    fireEvent.click(form.getByRole("button", { name: "Enregistrer le profil" }));
    expect((await screen.findByRole("status")).textContent).toContain("Profil d'écran de acc_r enregistré");
    expect(calls.find((c) => c.method === "PUT")).toMatchObject({
      path: "/vault/accounts/acc_r/screen-profile",
      body: { screenProfile: { channels: ["bitmap"], defaultChannel: "bitmap", colorDepths: [16], defaultColorDepth: 16 } },
    });
  });

  it("is removed back to everything allowed, and a refusal is shown in the dialog", async () => {
    const profiled = { ...rdp, screenProfile: { channels: ["bitmap"], defaultChannel: "bitmap", colorDepths: [16], defaultColorDepth: 16 } };
    const { api, calls } = fakeApi({ "GET /vault/accounts": page([profiled]), "PUT /vault/accounts/acc_r/screen-profile": { status: 403, body: { message: "forbidden" } } });
    signedIn(api, <Accounts />);
    openAccountsTab();
    fireEvent.click(await screen.findByText("Profil d'écran"));
    const form = within(await screen.findByRole("dialog"));
    expect((form.getByLabelText("Pipeline graphique") as HTMLInputElement).checked).toBe(false);
    fireEvent.click(form.getByLabelText("Mises à jour bitmap"));
    expect(form.getByText("Permettez au moins un canal.")).toBeTruthy();
    fireEvent.click(form.getByRole("button", { name: "Retirer le profil" }));
    await waitFor(() => expect(form.getByText(/403/)).toBeTruthy());
    expect(screen.getByRole("dialog")).toBeTruthy();
    expect(calls.find((c) => c.method === "PUT")).toMatchObject({ body: { screenProfile: null } });
  });
});

// ADR-0132: the operator chooses at "Open the screen"; the Broker bounds the choice.
describe("The operator's screen choice", () => {
  const session = { id: "sess_r", status: "active", protocol: "rdp", requestedBy: "alice", privilegedAccountId: "acc_r", justification: "patch", breakGlass: false, expiresAt: "2030-01-01T00:00:00Z" };
  const attach = { body: { protocol: "rdp", attach: "/sessions/sess_r/screen", expiresAt: "2030-01-01T00:00:00Z" } };

  async function find(id: string) {
    fireEvent.change(await screen.findByLabelText("Identifiant"), { target: { value: id } });
    fireEvent.submit(screen.getByRole("form", { name: "Chercher une session" }));
  }

  it("sends what was chosen, and nothing for the account's default", async () => {
    vi.stubGlobal("WebSocket", vi.fn(function () {
      return { close: vi.fn(), send: vi.fn(), readyState: 0 };
    }));
    const { api, calls } = fakeApi({ "GET /sessions": page([]), "GET /sessions/sess_r": { body: session }, "POST /sessions/sess_r/connect": attach });
    signedIn(api, <Sessions />);
    await find("sess_r");
    fireEvent.click(await screen.findByText("Ouvrir l'écran"));
    await waitFor(() => expect(calls.filter((c) => c.path === "/sessions/sess_r/connect")).toHaveLength(1));
    expect(calls.find((c) => c.path === "/sessions/sess_r/connect")?.body).toBeUndefined();

    await find("sess_r");
    fireEvent.change(await screen.findByLabelText("Canal"), { target: { value: "bitmap" } });
    fireEvent.change(screen.getByLabelText("Profondeur"), { target: { value: "16" } });
    fireEvent.click(screen.getByText("Ouvrir l'écran"));
    await waitFor(() => expect(calls.filter((c) => c.path === "/sessions/sess_r/connect")).toHaveLength(2));
    expect(calls.filter((c) => c.path === "/sessions/sess_r/connect")[1].body).toEqual({ screen: { channel: "bitmap", colorDepth: 16 } });
    vi.unstubAllGlobals();
  });

  it("says why a choice outside the account's profile opens nothing", async () => {
    const socketOpen = vi.fn();
    vi.stubGlobal("WebSocket", socketOpen);
    const { api } = fakeApi({ "GET /sessions": page([]), "GET /sessions/sess_r": { body: session }, "POST /sessions/sess_r/connect": { status: 403, body: { message: "forbidden: the account's screen profile does not allow it" } } });
    signedIn(api, <Sessions />);
    await find("sess_r");
    fireEvent.change(await screen.findByLabelText("Canal"), { target: { value: "graphics" } });
    fireEvent.click(screen.getByText("Ouvrir l'écran"));
    expect((await screen.findByRole("alert")).textContent).toContain("screen profile");
    expect(socketOpen).not.toHaveBeenCalled();
    vi.unstubAllGlobals();
  });

  it("is not offered for a VNC session", async () => {
    const { api } = fakeApi({ "GET /sessions": page([]), "GET /sessions/sess_r": { body: { ...session, protocol: "vnc" } } });
    signedIn(api, <Sessions />);
    await find("sess_r");
    expect(await screen.findByText("Ouvrir l'écran")).toBeTruthy();
    expect(screen.queryByLabelText("Canal")).toBeNull();
  });

  it("keeps only what was chosen", () => {
    expect(screenChoice("", 0)).toBeUndefined();
    expect(screenChoice("bitmap", 0)).toEqual({ channel: "bitmap" });
    expect(screenChoice("", 16)).toEqual({ colorDepth: 16 });
  });
});
