import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { Accounts } from "./Accounts";
import { SignedInContext } from "../../shared/session";
import { CapabilitiesContext, capabilitiesFrom } from "../../shared/capabilities";
import { fakeApi } from "../../test-helpers";

const pending = {
  items: [{
    id: "session_1", status: "pending_approval", protocol: "ssh", requestedBy: "alice",
    privilegedAccountId: "account_prod", justification: "Intervention planifiée", breakGlass: false,
    ticket: "INC-2042", expiresAt: "2026-11-24T21:30:00Z", createdAt: "2026-11-24T20:30:00Z",
  }],
  page: 1, pageSize: 100, totalItems: 1,
};

function renderQueue(currentUserId = "manager") {
  const { api, calls } = fakeApi({
    "GET /sessions?status=pending_approval&page=1&pageSize=100": { body: pending },
    "POST /sessions/session_1/approve": { body: {} },
  });
  api.setToken("test-token");
  const capabilities = capabilitiesFrom("ready", { "sessions.approve": true });
  render(
    <SignedInContext.Provider value={{ api, who: { sub: currentUserId, username: currentUserId, roles: [], exp: 9999999999 }, signOut: () => api.setToken(null) }}>
      <CapabilitiesContext.Provider value={capabilities}><Accounts /></CapabilitiesContext.Provider>
    </SignedInContext.Provider>,
  );
  return { calls };
}

describe("Approval queue — ADR-0138", () => {
  it("filters the loaded queue without claiming to search beyond the returned page", async () => {
    renderQueue();
    expect(await screen.findByText("Intervention planifiée")).toBeTruthy();
    fireEvent.change(screen.getByLabelText("Rechercher dans les demandes chargées"), { target: { value: "INC-2042" } });
    expect(screen.getByText("Intervention planifiée")).toBeTruthy();
    fireEvent.change(screen.getByLabelText("Rechercher dans les demandes chargées"), { target: { value: "not-present" } });
    expect(await screen.findByText("Aucune demande chargée ne correspond à cette recherche.")).toBeTruthy();
  });

  it("does not offer self-approval even if a request is unexpectedly returned", async () => {
    renderQueue("alice");
    expect(await screen.findByText("Vous avez fait cette demande : une autre personne doit la décider.")).toBeTruthy();
    expect(screen.queryByRole("button", { name: "Approuver la session session_1" })).toBeNull();
    expect(screen.queryByRole("button", { name: "Refuser la session session_1" })).toBeNull();
  });

  it("shows the actionable request and requires confirmation before approving it", async () => {
    const { calls } = renderQueue();
    expect(await screen.findByText("Intervention planifiée")).toBeTruthy();
    expect(screen.getByText("INC-2042")).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: "Approuver la session session_1" }));
    expect(await screen.findByRole("alertdialog")).toBeTruthy();
    expect(calls.some((call) => call.method === "POST")).toBe(false);
    fireEvent.click(screen.getByRole("button", { name: "Annuler" }));
    expect(calls.some((call) => call.method === "POST")).toBe(false);

    fireEvent.click(screen.getByRole("button", { name: "Approuver la session session_1" }));
    fireEvent.click(within(screen.getByRole("alertdialog")).getByRole("button", { name: "Confirmer l'approbation" }));
    await waitFor(() => expect(calls.some((call) => call.method === "POST" && call.path === "/sessions/session_1/approve")).toBe(true));
  });
});
