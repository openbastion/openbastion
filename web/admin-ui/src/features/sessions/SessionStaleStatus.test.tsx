import { describe, expect, it } from "vitest";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { ReactNode } from "react";
import { Api } from "../../shared/api";
import { SignedInContext } from "../../shared/session";
import { fakeApi } from "../../test-helpers";
import { Sessions } from "./Sessions";

const signedIn = (api: Api, node: ReactNode) => render(<SignedInContext.Provider value={{ api, who: null, signOut: () => {} }}>{node}</SignedInContext.Provider>);
const emptyPage = { body: { items: [], page: 1, pageSize: 50, totalItems: 0 } };

async function showSession(id: string) {
  fireEvent.change(await screen.findByLabelText("Identifiant"), { target: { value: id } });
  fireEvent.submit(screen.getByRole("form", { name: "Chercher une session" }));
}

// ADR-0134 recette: a session ended elsewhere stayed "Active" in the detail left open, while the
// Broker refused what it was asked (409). The page now reads the session again on such a refusal.
describe("A session ended elsewhere", () => {
  const session = { id: "sess_s", status: "active", protocol: "ssh", requestedBy: "alice", privilegedAccountId: "acc_s", justification: "patch", breakGlass: false, expiresAt: "2030-01-01T00:00:00Z" };

  it("is shown as it is after the secret injection is refused with 409", async () => {
    const routes: Record<string, { status?: number; body?: unknown }> = {
      "GET /sessions": emptyPage,
      "GET /sessions/sess_s": { body: session },
      "POST /sessions/sess_s/secret-injection-step-up": { status: 409, body: { message: "secret injection requires an active session" } },
    };
    const { api, calls } = fakeApi(routes);
    signedIn(api, <Sessions />);
    await showSession("sess_s");
    fireEvent.click(await screen.findByText("Saisir le secret Vault"));
    // Meanwhile, someone ended the session.
    routes["GET /sessions/sess_s"] = { body: { ...session, status: "terminated" } };
    fireEvent.click(await screen.findByText("Continuer vers la confirmation MFA"));
    await waitFor(() => expect(screen.getAllByText("Terminée").length).toBeGreaterThan(0));
    expect(screen.queryByText("Active")).toBeNull();
    expect(screen.getAllByRole("alert").some((a) => a.textContent?.includes("La session sess_s n'est plus active"))).toBe(true);
    expect(screen.queryByText("Saisir le secret Vault")).toBeNull();
    expect(calls.filter((c) => c.method === "GET" && c.path === "/sessions/sess_s")).toHaveLength(2);
  });

  it("is shown as it is after the screen is refused with 409", async () => {
    const vnc = { ...session, id: "sess_v", protocol: "vnc" };
    const routes: Record<string, { status?: number; body?: unknown }> = {
      "GET /sessions": emptyPage,
      "GET /sessions/sess_v": { body: vnc },
      "POST /sessions/sess_v/connect": { status: 409, body: { message: "session is not active" } },
    };
    const { api } = fakeApi(routes);
    signedIn(api, <Sessions />);
    await showSession("sess_v");
    const open = await screen.findByText("Ouvrir l'écran");
    routes["GET /sessions/sess_v"] = { body: { ...vnc, status: "expired" } };
    fireEvent.click(open);
    await waitFor(() => expect(screen.getAllByRole("alert").some((a) => a.textContent?.includes("La session sess_v n'est plus active"))).toBe(true));
    expect(screen.queryByText("Ouvrir l'écran")).toBeNull();
  });

  it("is left as it is when a 409 is not about its status", async () => {
    const vnc = { ...session, id: "sess_p", protocol: "vnc" };
    const { api, calls } = fakeApi({
      "GET /sessions": emptyPage,
      "GET /sessions/sess_p": { body: vnc },
      "POST /sessions/sess_p/connect": { status: 409, body: { message: "no_pinned_tls_certificate" } },
    });
    signedIn(api, <Sessions />);
    await showSession("sess_p");
    fireEvent.click(await screen.findByText("Ouvrir l'écran"));
    await waitFor(() => expect(calls.filter((c) => c.method === "GET" && c.path === "/sessions/sess_p")).toHaveLength(2));
    expect(screen.getAllByRole("alert").some((a) => a.textContent?.includes("no_pinned_tls_certificate"))).toBe(true);
    expect(screen.getAllByRole("alert").some((a) => a.textContent?.includes("n'est plus active"))).toBe(false);
    expect(screen.getByText("Ouvrir l'écran")).toBeTruthy();
  });
});
