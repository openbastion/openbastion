import { describe, expect, it } from "vitest";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { ReactNode } from "react";
import { Api } from "../shared/api";
import { SignedInContext } from "../shared/session";
import { Accounts } from "./accounts/Accounts";
import { Recording } from "./audit/Recording";
import { Sessions } from "./sessions/Sessions";
import { Policies } from "./policies/Policies";
import { fakeApi } from "../test-helpers";

const signedIn = (api: Api, node: ReactNode) => render(<SignedInContext.Provider value={{ api, who: null, signOut: () => {} }}>{node}</SignedInContext.Provider>);

describe("Accounts", () => {
  const account = { id: "acc_1", name: "prod db", username: "root", targetHost: "db:22", protocol: "ssh", rotationPolicy: "manual", createdAt: "2026-10-30T10:00:00Z" };

  it("lists the accounts, and rotates one", async () => {
    const { api, calls } = fakeApi({ "GET /vault/accounts": { body: { items: [account], page: 1, pageSize: 20, totalItems: 1 } }, "POST /vault/accounts/acc_1/rotate": { body: {} } });
    signedIn(api, <Accounts />);
    expect(await screen.findByText("prod db")).toBeTruthy();
    fireEvent.click(screen.getByText("Renouveler le secret"));
    expect((await screen.findByRole("status")).textContent).toContain("Secret de acc_1 renouvelé");
    expect(calls.some((c) => c.method === "POST" && c.path === "/vault/accounts/acc_1/rotate")).toBe(true);
  });

  it("onboards an account with its secret as bytes, and never shows it again", async () => {
    const { api, calls } = fakeApi({ "GET /vault/accounts": { body: { items: [], page: 1, pageSize: 20, totalItems: 0 } }, "POST /vault/accounts": { status: 201, body: {} } });
    signedIn(api, <Accounts />);
    const form = await screen.findByRole("form", { name: "Enregistrer un compte" });
    const field = (label: string, value: string) => fireEvent.change(screen.getByLabelText(label), { target: { value } });
    field("Identifiant", "acc_2");
    field("Nom", "web");
    field("Cible (hôte:port)", "web:22");
    field("Utilisateur sur la cible", "admin");
    field("Secret initial", "s3cr3t-é");
    fireEvent.submit(form);
    await waitFor(() => expect(calls.some((c) => c.method === "POST" && c.path === "/vault/accounts")).toBe(true));
    const sent = calls.find((c) => c.method === "POST" && c.path === "/vault/accounts")!.body as Record<string, string>;
    expect(sent).toMatchObject({ id: "acc_2", protocol: "ssh", targetHost: "web:22" });
    expect(new TextDecoder().decode(Uint8Array.from(atob(sent.initialSecret), (c) => c.charCodeAt(0)))).toBe("s3cr3t-é");
    expect((screen.getByLabelText("Secret initial") as HTMLInputElement).value).toBe("");
  });
});

describe("Recording", () => {
  it("shows the commands typed, as text — never as markup", async () => {
    const page = { sessionId: "s1", page: 1, pageSize: 100, totalEntries: 2, entries: [
      { timestamp: "2026-10-30T10:00:00Z", command: "whoami" },
      { timestamp: "2026-10-30T10:00:01Z", command: `<img src=x onerror="alert(1)">` },
    ] };
    const { api, calls } = fakeApi({ "GET /sessions/s1/recording": { body: page } });
    const { container } = signedIn(api, <Recording />);
    fireEvent.change(screen.getByLabelText("Session"), { target: { value: "s1" } });
    fireEvent.click(screen.getByText("Relire"));
    expect(await screen.findByText("whoami")).toBeTruthy();
    expect(screen.getByText(`<img src=x onerror="alert(1)">`)).toBeTruthy();
    expect(container.querySelector("img")).toBeNull();
    expect(calls[0].path).toBe("/sessions/s1/recording?page=1&pageSize=100");
  });

  it("says when the read is refused", async () => {
    const { api } = fakeApi({ "GET /sessions/s1/recording": { status: 403, body: "forbidden" } });
    signedIn(api, <Recording />);
    fireEvent.change(screen.getByLabelText("Session"), { target: { value: "s1" } });
    fireEvent.click(screen.getByText("Relire"));
    expect((await screen.findByRole("alert")).textContent).toContain("403 — forbidden");
  });
});

describe("Sessions", () => {
  it("lists the requests to decide, and approves one", async () => {
    const req = { id: "sess_1", status: "pending_approval", protocol: "ssh", requestedBy: "bob", privilegedAccountId: "acc_1", justification: "incident 42", breakGlass: true, expiresAt: "2026-10-30T11:00:00Z" };
    const { api, calls } = fakeApi({ "GET /sessions": { body: { items: [req], page: 1, pageSize: 50, totalItems: 1 } }, "POST /sessions/sess_1/approve": { body: req } });
    signedIn(api, <Sessions />);
    expect(await screen.findByText("incident 42")).toBeTruthy();
    fireEvent.click(screen.getByText("Approuver"));
    expect((await screen.findByRole("status")).textContent).toContain("sess_1 approuvée");
    expect(calls[0].path).toBe("/sessions?status=pending_approval");
  });
});

describe("Policies", () => {
  it("creates a policy with what the form says — the creator is the Gateway's business", async () => {
    const { api, calls } = fakeApi({ "POST /policies": { status: 201, body: {} } });
    signedIn(api, <Policies />);
    const field = (label: string, value: string) => fireEvent.change(screen.getByLabelText(label), { target: { value } });
    field("Nom", "dba-on-prod");
    field("Rôle", "dba");
    field("Motif de ressource", "vault:account:acc_1");
    fireEvent.click(screen.getByText("Créer"));
    expect((await screen.findByRole("status")).textContent).toContain("Politique dba-on-prod créée");
    expect(calls[0].body).toEqual({ name: "dba-on-prod", role: "dba", resourcePattern: "vault:account:acc_1", effect: "allow" });
  });
});
