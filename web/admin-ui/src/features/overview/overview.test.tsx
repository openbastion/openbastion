import { describe, expect, it } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import { Overview } from "./Overview";
import { SignedInContext } from "../../shared/session";
import { fakeApi, fakeToken } from "../../test-helpers";

function renderOverview(routes: Parameters<typeof fakeApi>[0]) {
  const { api, calls } = fakeApi(routes);
  api.setToken(fakeToken("operator", ["platform-admin"]));
  const who = { sub: "user-1", username: "operator", roles: ["platform-admin"], exp: 9999999999 };
  render(<SignedInContext.Provider value={{ api, who, signOut: () => api.setToken(null) }}><Overview /></SignedInContext.Provider>);
  return calls;
}

describe("Overview — ADR-0073 UX-04", () => {
  it("shows counts returned by the public Vault and approval endpoints", async () => {
    const calls = renderOverview({
      "GET /vault/accounts": { body: { items: [{ id: "a1", rotationOwedSince: "2026-11-11T10:00:00Z" }], page: 1, pageSize: 100, totalItems: 8 } },
      "GET /sessions": { body: { items: [], page: 1, pageSize: 100, totalItems: 3 } },
    });
    expect(screen.getByRole("group", { name: "Indicateurs opérationnels" }).className).toContain("dashboard-metrics");
    expect((await screen.findAllByText("8")).length).toBeGreaterThan(0);
    expect(screen.getByText("3")).toBeTruthy();
    expect(screen.getAllByText("1").length).toBeGreaterThan(0);
    expect(screen.getByText(/L’analyse porte sur 1 comptes chargés sur 8/)).toBeTruthy();
    expect(calls.map((call) => call.path)).toEqual([
      "/vault/accounts?page=1&pageSize=100",
      "/sessions?status=pending_approval&page=1&pageSize=100",
    ]);
  });

  it("does not turn a denied source into a zero count", async () => {
    renderOverview({
      "GET /vault/accounts": { status: 403, body: "forbidden" },
      "GET /sessions": { body: { items: [], page: 1, pageSize: 100, totalItems: 0 } },
    });
    expect((await screen.findAllByText("Indisponible")).length).toBe(3);
    expect(screen.getByText("0")).toBeTruthy();
    expect(screen.getAllByText(/API n’a pas fourni/).length).toBe(3);
  });

  it("announces truncated approval results", async () => {
    renderOverview({
      "GET /vault/accounts": { body: { items: [], page: 1, pageSize: 100, totalItems: 0 } },
      "GET /sessions": { body: { items: [], page: 1, pageSize: 100, totalItems: 100, truncated: true } },
    });
    await waitFor(() => expect(screen.getByText(/liste des demandes est tronquée/)).toBeTruthy());
  });
});


describe("Overview — reference dashboard", () => {
  it("renders only real pending approval rows and clearly marks the missing activity aggregate", async () => {
    renderOverview({
      "GET /vault/accounts": { body: { items: [{ id: "acc_1", protocol: "ssh", hostKeyFingerprint: "SHA256:pinned" }], page: 1, pageSize: 100, totalItems: 1 } },
      "GET /sessions": { body: { items: [{ id: "sess_1", status: "pending_approval", protocol: "ssh", requestedBy: "alice", privilegedAccountId: "acc_1", justification: "maintenance", breakGlass: false, expiresAt: "2026-11-17T13:00:00Z", createdAt: "2026-11-17T12:00:00Z" }], page: 1, pageSize: 100, totalItems: 1 } },
    });
    expect(await screen.findByText("Historique agrégé indisponible")).toBeTruthy();
    expect(screen.getByText("alice")).toBeTruthy();
    expect(screen.getByText("acc_1")).toBeTruthy();
  });
});
