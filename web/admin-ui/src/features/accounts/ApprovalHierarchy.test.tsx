import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { ApprovalHierarchy } from "./ApprovalHierarchy";
import { SignedInContext } from "../../shared/session";
import { CapabilitiesContext, capabilitiesFrom } from "../../shared/capabilities";
import { fakeApi } from "../../test-helpers";

function renderHierarchy(routes: Record<string, { status?: number; body?: unknown }>) {
  const { api, calls } = fakeApi(routes);
  api.setToken("test-token");
  const capabilities = capabilitiesFrom("ready", {
    "approvalHierarchy.read": true,
    "approvalHierarchy.manage": true,
    "approvalHierarchy.reports": true,
  });
  render(
    <SignedInContext.Provider value={{ api, who: null, signOut: () => api.setToken(null) }}>
      <CapabilitiesContext.Provider value={capabilities}><ApprovalHierarchy /></CapabilitiesContext.Provider>
    </SignedInContext.Provider>,
  );
  return { calls };
}

describe("Approval hierarchy — ADR-0138", () => {
  it("reads a direct manager and updates it with the revision ETag after explicit confirmation", async () => {
    const { calls } = renderHierarchy({
      "GET /approval-hierarchy/users/alice/manager": {
        body: { userId: "alice", manager: { userId: "bob", updatedAt: "2026-11-24T10:00:00Z" }, revision: 7 },
      },
      "PUT /approval-hierarchy/users/alice/manager": {
        body: { userId: "alice", managerUserId: "carol", revision: 8, updatedAt: "2026-11-24T11:00:00Z" },
      },
    });

    fireEvent.change(screen.getByLabelText("Identifiant du subordonné"), { target: { value: "alice" } });
    fireEvent.click(screen.getByRole("button", { name: "Consulter" }));
    expect(await screen.findByText("Supérieur direct actuel : bob")).toBeTruthy();

    fireEvent.change(screen.getByLabelText("Nouveau supérieur direct"), { target: { value: "carol" } });
    fireEvent.click(screen.getByRole("button", { name: "Enregistrer le supérieur" }));
    expect(await screen.findByRole("alertdialog")).toBeTruthy();
    expect(screen.getByText(/Les demandes déjà en attente conservent leur approbateur actuel/)).toBeTruthy();
    expect(calls.filter((call) => call.method === "PUT")).toHaveLength(0);

    fireEvent.click(within(screen.getByRole("alertdialog")).getByRole("button", { name: "Enregistrer le supérieur" }));
    await waitFor(() => expect(calls.filter((call) => call.method === "PUT")).toHaveLength(1));
    const mutation = calls.find((call) => call.method === "PUT");
    expect(mutation?.body).toEqual({ managerUserId: "carol" });
    expect(mutation?.headers?.["If-Match"]).toBe('"hierarchy-7"');
    expect(await screen.findByText("Le supérieur de alice est maintenant carol.")).toBeTruthy();
  });

  it("does not mutate when the administrator cancels the confirmation", async () => {
    const { calls } = renderHierarchy({
      "GET /approval-hierarchy/users/alice/manager": {
        body: { userId: "alice", manager: null, revision: 12 },
      },
    });
    fireEvent.change(screen.getByLabelText("Identifiant du subordonné"), { target: { value: "alice" } });
    fireEvent.click(screen.getByRole("button", { name: "Consulter" }));
    await screen.findByText("Supérieur direct actuel : Aucun supérieur défini");
    fireEvent.change(screen.getByLabelText("Nouveau supérieur direct"), { target: { value: "bob" } });
    fireEvent.click(screen.getByRole("button", { name: "Enregistrer le supérieur" }));
    fireEvent.click(screen.getByRole("button", { name: "Annuler" }));
    expect(calls.some((call) => call.method === "PUT" || call.method === "DELETE")).toBe(false);
  });

  it("lists direct reports using the manager-scoped read contract", async () => {
    const { calls } = renderHierarchy({
      "GET /approval-hierarchy/users/bob/reports?page=1&pageSize=20": {
        body: {
          items: [{ userId: "alice", updatedAt: "2026-11-24T10:00:00Z" }],
          page: 1, pageSize: 20, totalItems: 1, revision: 9,
        },
      },
    });
    fireEvent.change(screen.getByLabelText("Identifiant du supérieur"), { target: { value: "bob" } });
    fireEvent.click(screen.getByRole("button", { name: "Afficher les subordonnés" }));
    expect(await screen.findByText("alice")).toBeTruthy();
    expect(calls.some((call) => call.path === "/approval-hierarchy/users/bob/reports?page=1&pageSize=20")).toBe(true);
  });

  it("shows an API refusal with its status and reason", async () => {
    renderHierarchy({
      "GET /approval-hierarchy/users/alice/manager": { status: 403, body: { message: "hierarchy read denied" } },
    });
    fireEvent.change(screen.getByLabelText("Identifiant du subordonné"), { target: { value: "alice" } });
    fireEvent.click(screen.getByRole("button", { name: "Consulter" }));
    expect(await screen.findByRole("alert")).toHaveProperty("textContent", expect.stringContaining("403"));
    expect(screen.getByRole("alert").textContent).toContain("hierarchy read denied");
  });
});
