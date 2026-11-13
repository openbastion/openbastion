import { describe, expect, it } from "vitest";
import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { App } from "./App";
import { fakeApi, fakeToken } from "../test-helpers";

const emptySessions = { items: [], page: 1, pageSize: 100, totalItems: 0 };
const accounts = {
  items: [
    { id: "acc_ssh", name: "SSH account", username: "svc-ssh", targetHost: "ssh.internal:22", protocol: "ssh", rotationPolicy: "manual", createdAt: "2026-11-01T00:00:00Z", hostKeyFingerprint: "SHA256:pinned", approvalRequired: true },
    { id: "acc_vnc", name: "VNC account", username: "svc-vnc", targetHost: "vnc.internal:5900", protocol: "vnc", rotationPolicy: "manual", createdAt: "2026-11-01T00:00:00Z", tlsCertificateSha256: "AA:BB", approvalRequired: false },
  ],
  page: 1,
  pageSize: 20,
  totalItems: 2,
};

function createApi() {
  const { api } = fakeApi({
    "POST /auth/login": { body: { accessToken: fakeToken("alice", ["platform-admin"]), expiresIn: 3600 } },
    "GET /vault/accounts": { body: accounts },
    "GET /sessions": { body: emptySessions },
  });
  return api;
}

async function signIn(api = createApi()) {
  const view = render(<App api={api} location={{ pathname: "/ui/", search: "" } as Location} navigate={() => undefined} />);
  fireEvent.change(screen.getByLabelText("Utilisateur"), { target: { value: "alice" } });
  fireEvent.change(screen.getByLabelText("Mot de passe"), { target: { value: "pw" } });
  fireEvent.click(screen.getByText("Se connecter"));
  expect(await screen.findByText("alice (platform-admin)")).toBeTruthy();
  return { api, ...view };
}

describe("ADR-0073 UX-05 — préférences opérateur", () => {
  it("persists presentation preferences and favorites without storing credentials", async () => {
    window.localStorage.clear();
    window.sessionStorage.clear();
    await signIn();

    fireEvent.click(screen.getByRole("button", { name: "Ouvrir les préférences" }));
    const dialog = screen.getByRole("dialog", { name: "Préférences et raccourcis" });
    fireEvent.change(within(dialog).getByLabelText("Thème"), { target: { value: "dark" } });
    fireEvent.change(within(dialog).getByLabelText("Densité de l'interface"), { target: { value: "compact" } });
    fireEvent.change(within(dialog).getByLabelText("Vue affichée à la connexion"), { target: { value: "accounts" } });
    fireEvent.click(within(dialog).getByLabelText("Réduire la navigation latérale"));
    fireEvent.click(within(dialog).getByRole("button", { name: "Enregistrer les préférences" }));

    expect(await screen.findByRole("heading", { name: "Comptes privilégiés" })).toBeTruthy();
    expect(document.documentElement.dataset.theme).toBe("dark");
    expect(document.documentElement.dataset.density).toBe("compact");
    expect(screen.getByRole("button", { name: "Développer la navigation" })).toBeTruthy();

    fireEvent.click(screen.getByRole("button", { name: "Ajouter Comptes aux favoris" }));
    expect(screen.getByRole("heading", { name: "Favoris" })).toBeTruthy();
    expect(screen.getAllByRole("button", { name: "Retirer Comptes des favoris" })).toHaveLength(2);

    const raw = window.localStorage.getItem("openbastion.admin-ui.preferences.v1") ?? "";
    expect(raw).toContain('"theme":"dark"');
    expect(raw).toContain('"defaultTab":"accounts"');
    expect(raw).toContain('"accounts"');
    expect(raw).not.toContain("alice");
    expect(raw).not.toContain("accessToken");
    expect(raw).not.toContain("session");
    expect(window.sessionStorage.length).toBe(0);
  });

  it("does not persist a cancelled draft and restores the dialog trigger focus", async () => {
    window.localStorage.clear();
    await signIn();
    const trigger = screen.getByRole("button", { name: "Ouvrir les préférences" });
    fireEvent.click(trigger);
    const dialog = screen.getByRole("dialog", { name: "Préférences et raccourcis" });
    fireEvent.change(within(dialog).getByLabelText("Thème"), { target: { value: "dark" } });
    fireEvent.click(within(dialog).getByRole("button", { name: "Annuler" }));
    await waitFor(() => expect(document.activeElement).toBe(trigger));
    expect(document.documentElement.dataset.theme).toBe("light");
    expect(window.localStorage.getItem("openbastion.admin-ui.preferences.v1")).toBeNull();
  });

  it("uses the saved default destination on the next application load", async () => {
    window.localStorage.clear();
    const first = await signIn();
    fireEvent.click(screen.getByRole("button", { name: "Ouvrir les préférences" }));
    const dialog = screen.getByRole("dialog", { name: "Préférences et raccourcis" });
    fireEvent.change(within(dialog).getByLabelText("Vue affichée à la connexion"), { target: { value: "security" } });
    fireEvent.click(within(dialog).getByRole("button", { name: "Enregistrer les préférences" }));
    first.unmount();

    await signIn();
    expect(await screen.findByRole("heading", { name: "Centre de sécurité" })).toBeTruthy();
  });

  it("supports section shortcuts but ignores them in text fields", async () => {
    window.localStorage.clear();
    await signIn();
    fireEvent.keyDown(screen.getByRole("main"), { key: "2", altKey: true, shiftKey: true });
    expect(await screen.findByRole("heading", { name: "Comptes privilégiés" })).toBeTruthy();

    const filter = screen.getByLabelText("Filtrer les comptes de cette page");
    fireEvent.keyDown(filter, { key: "3", altKey: true, shiftKey: true });
    expect(screen.getByRole("heading", { name: "Comptes privilégiés" })).toBeTruthy();
  });

  it("does not apply a preference draft when local storage refuses the write", async () => {
    window.localStorage.clear();
    await signIn();
    const original = Storage.prototype.setItem;
    Storage.prototype.setItem = function () { throw new Error("blocked"); };
    try {
      fireEvent.click(screen.getByRole("button", { name: "Ouvrir les préférences" }));
      const dialog = screen.getByRole("dialog", { name: "Préférences et raccourcis" });
      fireEvent.change(within(dialog).getByLabelText("Thème"), { target: { value: "dark" } });
      fireEvent.click(within(dialog).getByRole("button", { name: "Enregistrer les préférences" }));
      expect(await within(dialog).findByRole("alert")).toBeTruthy();
      expect(document.documentElement.dataset.theme).toBe("light");
    } finally {
      Storage.prototype.setItem = original;
    }
  });
});
