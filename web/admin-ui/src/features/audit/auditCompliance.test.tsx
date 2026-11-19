import { describe, expect, it } from "vitest";
import { render, screen } from "@testing-library/react";
import { AuditCompliance } from "./AuditCompliance";
import { SignedInContext } from "../../shared/session";
import { fakeApi, fakeToken } from "../../test-helpers";

function renderAudit(routes: Parameters<typeof fakeApi>[0]) {
  const { api, calls } = fakeApi(routes);
  api.setToken(fakeToken("operator", ["platform-admin"]));
  const who = { sub: "user-1", username: "operator", roles: ["platform-admin"], exp: 9999999999 };
  render(<SignedInContext.Provider value={{ api, who, signOut: () => api.setToken(null) }}><AuditCompliance /></SignedInContext.Provider>);
  return calls;
}

describe("Audit & conformité", () => {
  it("leaves every figure the public API cannot produce empty, and says so", async () => {
    renderAudit({ "GET /vault/accounts": { body: { page: 1, pageSize: 100, totalItems: 0, items: [] } } });
    expect((await screen.findByRole("group", { name: "Indicateurs d’audit et de conformité" })).className).toContain("reference-metrics");
    // The one figure the product guarantees: every admitted session is recorded or refused (ADR-0008).
    expect(screen.getByText("Sessions journalisées")).toBeTruthy();
    expect(await screen.findByText("100 %")).toBeTruthy();
    expect(screen.getByText("Journal d’audit non exposé par l’API")).toBeTruthy();
    expect(screen.getByText("Aucun compteur public d’accès refusés")).toBeTruthy();
    expect(screen.getByText("Aucun réglage de rétention exposé")).toBeTruthy();
    expect(screen.getAllByText("—").length).toBeGreaterThanOrEqual(3);
    expect(screen.getAllByText("Non évalué")).toHaveLength(3);
    expect(screen.getByText(/ces jauges restent vides/)).toBeTruthy();
  });

  it("recommends only what the Vault's own fields show, and never calls the audit search", async () => {
    const calls = renderAudit({
      "GET /vault/accounts": { body: { page: 1, pageSize: 100, totalItems: 2, items: [
        { id: "ssh-unpinned", name: "legacy SSH", protocol: "ssh", targetHost: "host-a:22", rotationPolicy: "manual", createdAt: "2026-11-01T00:00:00Z" },
        { id: "rdp-incomplete", name: "Windows", protocol: "rdp", targetHost: "host-b:3389", rotationPolicy: "scheduled", createdAt: "2026-11-01T00:00:00Z", tlsCertificateSha256: "", targetDomain: "", rotationFailures: 2 },
      ] } },
    });
    expect(await screen.findByText("Épingler 2 identité(s) de cible")).toBeTruthy();
    expect(screen.getByText("Revoir 1 rotation(s) en anomalie")).toBeTruthy();
    expect(screen.getByText("02")).toBeTruthy();
    // The journal tab shows the missing contract, it does not query an unrouted route.
    expect(screen.getByText("Journal d’audit indisponible")).toBeTruthy();
    expect(screen.getByText(/GET \/audit\/events/)).toBeTruthy();
    expect(calls.map((call) => call.path)).toEqual(["/vault/accounts?page=1&pageSize=100"]);
    expect(calls.some((call) => call.path.startsWith("/audit"))).toBe(false);
  });

  it("says there is nothing to recommend when every account is pinned and rotates cleanly", async () => {
    renderAudit({
      "GET /vault/accounts": { body: { page: 1, pageSize: 100, totalItems: 1, items: [
        { id: "ssh-pinned", name: "secure SSH", protocol: "ssh", targetHost: "host:22", rotationPolicy: "manual", createdAt: "2026-11-01T00:00:00Z", hostKeyFingerprint: "SHA256:known" },
      ] } },
    });
    expect(await screen.findByText("Aucun signal parmi les comptes examinés.")).toBeTruthy();
    expect(screen.getByText("00")).toBeTruthy();
  });

  it("shows an API refusal instead of an empty or healthy state", async () => {
    renderAudit({ "GET /vault/accounts": { status: 403, body: "forbidden" } });
    expect(await screen.findByRole("alert")).toHaveProperty("textContent", expect.stringContaining("403 — forbidden"));
    expect(screen.queryByText("Aucun signal parmi les comptes examinés.")).toBeNull();
  });
});
