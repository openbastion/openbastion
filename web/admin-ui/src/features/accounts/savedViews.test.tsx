import { describe, expect, it } from "vitest";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { SignedInContext } from "../../shared/session";
import { Accounts } from "./Accounts";
import { fakeApi } from "../../test-helpers";

const rows = [
  { id: "acc_ssh", name: "SSH account", username: "svc-ssh", targetHost: "ssh.internal:22", protocol: "ssh", rotationPolicy: "manual", createdAt: "2026-11-01T00:00:00Z", hostKeyFingerprint: "SHA256:pinned", approvalRequired: true },
  { id: "acc_vnc", name: "VNC account", username: "svc-vnc", targetHost: "vnc.internal:5900", protocol: "vnc", rotationPolicy: "manual", createdAt: "2026-11-01T00:00:00Z", tlsCertificateSha256: "AA:BB", approvalRequired: false },
];

function renderAccounts(routes: Record<string, { status?: number; body?: unknown }>) {
  const { api, calls } = fakeApi(routes);
  api.setToken("test-token");
  render(<SignedInContext.Provider value={{ api, who: null, signOut: () => api.setToken(null) }}><Accounts /></SignedInContext.Provider>);
  return { api, calls };
}

describe("Accounts — ADR-0073 UX-05 saved views", () => {
  it("saves and reapplies dynamic rules without persisting search terms or resource data", async () => {
    window.localStorage.clear();
    const { calls } = renderAccounts({
      "GET /vault/accounts": { body: { items: rows, page: 1, pageSize: 20, totalItems: 2 } },
    });
    expect(await screen.findByText("SSH account")).toBeTruthy();

    fireEvent.click(screen.getByRole("button", { name: "+ Ajouter un filtre" }));
    fireEvent.click(screen.getByRole("button", { name: "+ Ajouter un filtre" }));
    fireEvent.change(screen.getByLabelText("Champ de la règle 2"), { target: { value: "approval" } });
    fireEvent.change(screen.getByLabelText("Valeur de la règle 2"), { target: { value: "required" } });
    fireEvent.change(screen.getByLabelText("Filtrer les comptes de cette page"), { target: { value: "sensitive-search-term" } });
    fireEvent.change(screen.getByLabelText("Nom de la vue"), { target: { value: "SSH avec approbation" } });
    fireEvent.click(screen.getByRole("button", { name: "Enregistrer la vue" }));

    expect(await screen.findByText("Vue enregistrée dans ce navigateur.")).toBeTruthy();
    const stored = window.localStorage.getItem("openbastion.admin-ui.account-views.v1") ?? "";
    expect(stored).toContain('"field":"protocol"');
    expect(stored).toContain('"field":"approval"');
    expect(stored).toContain('"value":"required"');
    expect(stored).toContain('"version":2');
    expect(stored).not.toContain("sensitive-search-term");
    expect(stored).not.toContain("acc_ssh");
    expect(stored).not.toContain("ssh.internal");
    expect(stored).not.toContain("svc-ssh");

    const views = screen.getByLabelText("Vues enregistrées");
    fireEvent.change(views, { target: { value: "" } });
    fireEvent.change(views, { target: { value: "SSH avec approbation" } });
    expect(screen.getByText("SSH account")).toBeTruthy();
    expect(screen.queryByText("VNC account")).toBeNull();
    expect((screen.getByLabelText("Filtrer les comptes de cette page") as HTMLInputElement).value).toBe("");
    expect(calls.filter((call) => call.method === "GET" && call.path.startsWith("/vault/accounts")).length).toBe(1);

    fireEvent.click(screen.getByRole("button", { name: "Supprimer la vue" }));
    await waitFor(() => expect(screen.queryByRole("option", { name: "SSH avec approbation" })).toBeNull());
    expect(window.localStorage.getItem("openbastion.admin-ui.account-views.v1")).toContain('"views":[]');
  });

  it("updates values from the selected field and applies AND / OR to account results", async () => {
    window.localStorage.clear();
    renderAccounts({
      "GET /vault/accounts": { body: { items: rows, page: 1, pageSize: 20, totalItems: 2 } },
    });
    expect(await screen.findByText("SSH account")).toBeTruthy();

    fireEvent.click(screen.getByRole("button", { name: "+ Ajouter un filtre" }));
    fireEvent.click(screen.getByRole("button", { name: "+ Ajouter un filtre" }));
    fireEvent.change(screen.getByLabelText("Champ de la règle 2"), { target: { value: "approval" } });
    expect(screen.getByRole("option", { name: "Requise" })).toBeTruthy();
    fireEvent.change(screen.getByLabelText("Valeur de la règle 2"), { target: { value: "not-required" } });
    expect(screen.queryByText("SSH account")).toBeNull();
    expect(screen.queryByText("VNC account")).toBeNull();

    fireEvent.change(screen.getByLabelText("Combinaison avant la règle 2"), { target: { value: "OR" } });
    expect(screen.getByText("SSH account")).toBeTruthy();
    expect(screen.getByText("VNC account")).toBeTruthy();

    fireEvent.change(screen.getByLabelText("Opérateur de la règle 2"), { target: { value: "is-not" } });
    expect(screen.getByText("SSH account")).toBeTruthy();
    expect(screen.queryByText("VNC account")).toBeNull();

    fireEvent.click(screen.getByRole("button", { name: "Supprimer la règle 2" }));
    expect(screen.getByText("SSH account")).toBeTruthy();
    expect(screen.queryByText("VNC account")).toBeNull();
  });

  it("shows a storage refusal and does not claim that the view was saved", async () => {
    window.localStorage.clear();
    renderAccounts({
      "GET /vault/accounts": { body: { items: rows, page: 1, pageSize: 20, totalItems: 2 } },
    });
    await screen.findByText("SSH account");
    fireEvent.click(screen.getByRole("button", { name: "+ Ajouter un filtre" }));
    fireEvent.change(screen.getByLabelText("Nom de la vue"), { target: { value: "Vue SSH" } });
    const original = Storage.prototype.setItem;
    Storage.prototype.setItem = function () { throw new Error("blocked"); };
    try {
      fireEvent.click(screen.getByRole("button", { name: "Enregistrer la vue" }));
      expect(await screen.findByRole("alert")).toHaveProperty("textContent", expect.stringContaining("Impossible d'enregistrer cette vue"));
      expect(screen.queryByText("Vue enregistrée dans ce navigateur.")).toBeNull();
    } finally {
      Storage.prototype.setItem = original;
    }
  });
});
