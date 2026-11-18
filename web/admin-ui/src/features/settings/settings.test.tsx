import { describe, expect, it } from "vitest";
import { fireEvent, render, screen } from "@testing-library/react";
import { Settings } from "./Settings";

// Paramètres reproduces the five reference sections. The public API exposes no settings resource,
// so the test also holds the line the screen draws: the reference's save action is present but
// unavailable, and each section states what the deployment declares.
describe("Paramètres — référence openbastion-parametres*.svg", () => {
  it("opens on Général, fills the fields the browser really knows, and leaves the rest unexposed", () => {
    render(<Settings />);
    expect(screen.getByRole("heading", { level: 2, name: "Paramètres" })).toBeTruthy();
    expect(screen.getByText("Configurez votre espace et les règles de sécurité du bastion.")).toBeTruthy();

    expect((screen.getByLabelText("Nom de l’organisation") as HTMLInputElement).value).toBe("—");
    expect((screen.getByLabelText("Nom de l’espace") as HTMLInputElement).value).toBe("Production");
    expect((screen.getByLabelText("URL du bastion") as HTMLInputElement).value).toBe(window.location.origin);
    expect((screen.getByLabelText("Fuseau horaire") as HTMLInputElement).value).toBe(Intl.DateTimeFormat().resolvedOptions().timeZone);

    const save = screen.getByRole("button", { name: "Enregistrer les modifications" }) as HTMLButtonElement;
    expect(save.disabled).toBe(true);
    expect(save.getAttribute("title")).toContain("aucune écriture des paramètres");
  });

  it("keeps the default security rules in their reference position without pretending to toggle them", () => {
    render(<Settings />);
    expect(screen.getByText("Authentification multifacteur")).toBeTruthy();
    expect(screen.getByText("Enregistrement des sessions")).toBeTruthy();
    expect(screen.getByText("Approbation des accès sensibles")).toBeTruthy();
    expect(screen.queryByRole("switch")).toBeNull();
    expect(screen.getByText(/déclarées au déploiement et ne se modifient pas/)).toBeTruthy();
  });

  it("follows the section chosen in the tabs", () => {
    render(<Settings />);

    fireEvent.mouseDown(screen.getByRole("tab", { name: "Sécurité" }), { button: 0 });
    expect(screen.getByText("Politiques, authentification forte et intégrité des opérations.")).toBeTruthy();
    // The save action belongs to Général in the reference; no other section carries it.
    expect(screen.queryByRole("button", { name: "Enregistrer les modifications" })).toBeNull();
    expect(screen.getByText("RBAC — refus par défaut")).toBeTruthy();
    expect(screen.getByText("Politique « enregistrer ou refuser »")).toBeTruthy();
    expect(screen.getAllByText("PAR RÔLE")).toHaveLength(2);

    fireEvent.mouseDown(screen.getByRole("tab", { name: "Identités & SSO" }), { button: 0 });
    expect(screen.getByText("Configurez les sources d’identité et les règles de fédération.")).toBeTruthy();
    expect(screen.getByText("Microsoft Entra ID")).toBeTruthy();
    expect(screen.getByDisplayValue("IDENTITY_PROVIDERS_FILE")).toBeTruthy();

    fireEvent.mouseDown(screen.getByRole("tab", { name: "Intégrations" }), { button: 0 });
    expect(screen.getByText("Connecteurs et services externes utilisés par OpenBastion.")).toBeTruthy();
    expect(screen.getByText("HashiCorp Vault / OpenBao Transit")).toBeTruthy();

    fireEvent.mouseDown(screen.getByRole("tab", { name: "Notifications" }), { button: 0 });
    expect(screen.getByText("Canaux sortants, événements notifiés et garanties de livraison.")).toBeTruthy();
    expect(screen.getAllByDisplayValue("generic · slack · teams")).toHaveLength(2);
  });

  it("opens the Identities & SSO section from the identity card of Général", () => {
    render(<Settings />);
    fireEvent.click(screen.getByRole("button", { name: /Configurer le SSO/ }));
    expect(screen.getByText("Fournisseurs d’identité déclarés")).toBeTruthy();
  });
});
