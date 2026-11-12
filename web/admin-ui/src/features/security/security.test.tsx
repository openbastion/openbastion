import { describe, expect, it } from "vitest";
import { render, screen } from "@testing-library/react";
import { SecurityCenter } from "./SecurityCenter";
import { SignedInContext } from "../../shared/session";
import { fakeApi, fakeToken } from "../../test-helpers";

function renderSecurity(routes: Parameters<typeof fakeApi>[0]) {
  const { api, calls } = fakeApi(routes);
  api.setToken(fakeToken("operator", ["platform-admin"]));
  const who = { sub: "user-1", username: "operator", roles: ["platform-admin"], exp: 9999999999 };
  render(<SignedInContext.Provider value={{ api, who, signOut: () => api.setToken(null) }}><SecurityCenter /></SignedInContext.Provider>);
  return calls;
}

describe("Security Center — ADR-0073 UX-04", () => {
  it("flags only concrete missing pins and rotation signals from the returned page", async () => {
    const calls = renderSecurity({
      "GET /vault/accounts": { body: { page: 1, pageSize: 100, totalItems: 2, items: [
        { id: "ssh-unpinned", name: "legacy SSH", protocol: "ssh", targetHost: "host-a:22", rotationPolicy: "manual", createdAt: "2026-11-01T00:00:00Z" },
        { id: "rdp-incomplete", name: "Windows", protocol: "rdp", targetHost: "host-b:3389", rotationPolicy: "scheduled", createdAt: "2026-11-01T00:00:00Z", tlsCertificateSha256: "", targetDomain: "", rotationFailures: 2 },
      ] } },
    });
    expect(await screen.findByText("Clé d’hôte SSH non épinglée")).toBeTruthy();
    expect(screen.getByText("Identité TLS de la cible incomplète")).toBeTruthy();
    expect(screen.getByText("Échecs de rotation consécutifs : 2")).toBeTruthy();
    expect(screen.getAllByText("2").length).toBeGreaterThan(0);
    expect(screen.getByText(/journal d’audit/)).toBeTruthy();
    expect(calls).toHaveLength(1);
    expect(calls[0].path).toBe("/vault/accounts?page=1&pageSize=100");
  });

  it("marks coverage as partial when pagination hides accounts", async () => {
    renderSecurity({
      "GET /vault/accounts": { body: { page: 1, pageSize: 100, totalItems: 120, items: [{ id: "a1", name: "a1", protocol: "ssh", targetHost: "host:22", rotationPolicy: "manual", createdAt: "2026-11-01T00:00:00Z" }] } },
    });
    expect(await screen.findByText(/1 comptes examinés sur 120/)).toBeTruthy();
    expect(screen.getByText(/Échantillon partiel/)).toBeTruthy();
  });

  it("shows an API refusal instead of an empty or healthy state", async () => {
    renderSecurity({ "GET /vault/accounts": { status: 403, body: "forbidden" } });
    expect(await screen.findByRole("alert")).toHaveProperty("textContent", expect.stringContaining("403 — forbidden"));
    expect(screen.queryByText(/Aucun signal/)).toBeNull();
  });

  it("does not flag correctly pinned SSH accounts", async () => {
    renderSecurity({
      "GET /vault/accounts": { body: { page: 1, pageSize: 100, totalItems: 1, items: [
        { id: "ssh-pinned", name: "secure SSH", protocol: "ssh", targetHost: "host:22", rotationPolicy: "manual", createdAt: "2026-11-01T00:00:00Z", hostKeyFingerprint: "SHA256:known" },
      ] } },
    });
    expect(await screen.findByText("Aucun signal parmi les métadonnées des comptes examinés.")).toBeTruthy();
  });
});
