import { describe, expect, it } from "vitest";
import { render, screen } from "@testing-library/react";
import { Infrastructure } from "./Infrastructure";
import { SignedInContext } from "../../shared/session";
import { fakeApi, fakeToken } from "../../test-helpers";

function renderInfrastructure(routes: Parameters<typeof fakeApi>[0]) {
  const { api, calls } = fakeApi(routes);
  api.setToken(fakeToken("operator", ["platform-admin"]));
  const who = { sub: "user-1", username: "operator", roles: ["platform-admin"], exp: 9999999999 };
  render(<SignedInContext.Provider value={{ api, who, signOut: () => api.setToken(null) }}><Infrastructure /></SignedInContext.Provider>);
  return calls;
}

describe("Infrastructure — référence openbastion-infrastructure.svg", () => {
  it("shows the Vault's own resource count and leaves the figures no public route produces empty", async () => {
    renderInfrastructure({
      "GET /vault/accounts": { body: { page: 1, pageSize: 1, totalItems: 128, items: [] } },
    });
    expect((await screen.findByRole("group", { name: "Indicateurs d’infrastructure" })).className).toContain("reference-metrics");
    expect(await screen.findByText("128")).toBeTruthy();
    expect(screen.getByText("Comptes privilégiés du Password Vault")).toBeTruthy();
    expect(screen.getByText("Aucun contrat public de connecteurs")).toBeTruthy();
    expect(screen.getByText("Aucun contrat public de déploiement")).toBeTruthy();
    expect(screen.getByText("Aucune mesure publique sur 30 jours")).toBeTruthy();
    expect(screen.getByText("Topologie des accès")).toBeTruthy();
    expect(screen.getByText(/aucune répartition par plateforme/)).toBeTruthy();
    expect(screen.getByText("Santé du cluster")).toBeTruthy();
  });

  it("keeps the connector table's shape and says why it stays empty", async () => {
    const calls = renderInfrastructure({
      "GET /vault/accounts": { body: { page: 1, pageSize: 1, totalItems: 0, items: [] } },
    });
    expect(await screen.findByText("Aucun connecteur exposé par l’API publique")).toBeTruthy();
    for (const column of ["CONNECTEUR", "TYPE", "RESSOURCES", "DERNIÈRE SYNC.", "ÉTAT"]) {
      expect(screen.getByRole("columnheader", { name: column })).toBeTruthy();
    }
    expect(screen.queryByText("Configurer")).toBeNull();
    expect(calls.map((call) => call.path)).toEqual(["/vault/accounts?page=1&pageSize=1"]);
  });

  it("shows an API refusal instead of a confident empty state", async () => {
    renderInfrastructure({ "GET /vault/accounts": { status: 403, body: "forbidden" } });
    expect(await screen.findByRole("alert")).toHaveProperty("textContent", expect.stringContaining("403 — forbidden"));
    expect(screen.getByText("Aucun connecteur exposé par l’API publique")).toBeTruthy();
  });
});
