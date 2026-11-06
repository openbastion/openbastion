import { describe, expect, it, vi } from "vitest";
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

  it("lists the accounts, and rotates one on its target", async () => {
    const { api, calls } = fakeApi({ "GET /vault/accounts": { body: { items: [account], page: 1, pageSize: 20, totalItems: 1 } }, "POST /vault/accounts/acc_1/rotate": { status: 202, body: "" } });
    signedIn(api, <Accounts />);
    expect(await screen.findByText("prod db")).toBeTruthy();
    fireEvent.click(screen.getByText("Renouveler le secret"));
    expect((await screen.findByRole("status")).textContent).toContain("Secret de acc_1 renouvelé sur la cible");
    expect(calls.some((c) => c.method === "POST" && c.path === "/vault/accounts/acc_1/rotate")).toBe(true);
  });

  it("says why a rotation is refused", async () => {
    const { api } = fakeApi({ "GET /vault/accounts": { body: { items: [account], page: 1, pageSize: 20, totalItems: 1 } }, "POST /vault/accounts/acc_1/rotate": { status: 409, body: "the account has no usable reconciliation account: it cannot be rotated" } });
    signedIn(api, <Accounts />);
    fireEvent.click(await screen.findByText("Renouveler le secret"));
    expect((await screen.findByRole("alert")).textContent).toContain("409 — the account has no usable reconciliation account");
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
    field("Compte de réconciliation (même cible ; vide : pas de rotation — obligatoire pour une rotation planifiée)", "acc_root");
    field("Clé d'hôte de la cible (relevée sur la cible : /etc/ssh/ssh_host_ed25519_key.pub), ou autorité : @cert-authority <nom> <clé de l'autorité>", "ssh-ed25519 AAAAkey");
    fireEvent.submit(form);
    await waitFor(() => expect(calls.some((c) => c.method === "POST" && c.path === "/vault/accounts")).toBe(true));
    const sent = calls.find((c) => c.method === "POST" && c.path === "/vault/accounts")!.body as Record<string, string>;
    expect(sent).toMatchObject({ id: "acc_2", protocol: "ssh", targetHost: "web:22", reconciliationAccountId: "acc_root", hostKey: "ssh-ed25519 AAAAkey" });
    expect(sent).not.toHaveProperty("rotationIntervalDays"); // not a scheduled account
    expect(new TextDecoder().decode(Uint8Array.from(atob(sent.initialSecret), (c) => c.charCodeAt(0)))).toBe("s3cr3t-é");
    expect((screen.getByLabelText("Secret initial") as HTMLInputElement).value).toBe("");
  });
});

describe("Accounts — host key (ADR-0039)", () => {
  const pinned = { id: "acc_1", name: "prod db", username: "root", targetHost: "db:22", protocol: "ssh", rotationPolicy: "manual", createdAt: "2026-10-30T10:00:00Z", hostKey: "ssh-ed25519 AAAAold", hostKeyFingerprint: "SHA256:old" };
  const unpinned = { ...pinned, id: "acc_2", hostKey: "", hostKeyFingerprint: "" };

  it("shows each account's fingerprint, and the accounts that are not pinned", async () => {
    const { api } = fakeApi({ "GET /vault/accounts": { body: { items: [pinned, unpinned], page: 1, pageSize: 20, totalItems: 2 } } });
    signedIn(api, <Accounts />);
    expect(await screen.findByText("SHA256:old")).toBeTruthy();
    expect(screen.getByText("non épinglée")).toBeTruthy();
    expect(screen.getByText("Épingler la clé d'hôte")).toBeTruthy();
    expect(screen.getByText("Changer la clé d'hôte")).toBeTruthy();
  });

  it("re-pins with the key typed, and says the new fingerprint; cancelled, it sends nothing", async () => {
    const { api, calls } = fakeApi({
      "GET /vault/accounts": { body: { items: [pinned], page: 1, pageSize: 20, totalItems: 1 } },
      "PUT /vault/accounts/acc_1/host-key": { body: { hostKeyFingerprint: "SHA256:new" } },
    });
    const prompt = window.prompt;
    try {
      window.prompt = () => null;
      signedIn(api, <Accounts />);
      fireEvent.click(await screen.findByText("Changer la clé d'hôte"));
      expect(calls.some((c) => c.method === "PUT")).toBe(false);

      let asked = "";
      window.prompt = (msg?: string) => { asked = msg ?? ""; return "ssh-ed25519 AAAAnew"; };
      fireEvent.click(screen.getByText("Changer la clé d'hôte"));
      expect((await screen.findByRole("status")).textContent).toContain("Clé d'hôte de acc_1 épinglée : SHA256:new");
      expect(asked).toContain("Elle remplace SHA256:old");
      expect(calls.find((c) => c.method === "PUT")?.body).toEqual({ hostKey: "ssh-ed25519 AAAAnew" });
    } finally {
      window.prompt = prompt;
    }
  });
});

describe("Accounts — scheduled rotation (ADR-0040)", () => {
  it("asks for an interval only for a scheduled account, and sends it as a number", async () => {
    const { api, calls } = fakeApi({ "GET /vault/accounts": { body: { items: [], page: 1, pageSize: 20, totalItems: 0 } }, "POST /vault/accounts": { status: 201, body: {} } });
    signedIn(api, <Accounts />);
    const form = await screen.findByRole("form", { name: "Enregistrer un compte" });
    const label = "Intervalle de rotation (jours, 1 à 365)";
    expect(screen.queryByLabelText(label)).toBeNull();
    const field = (l: string, value: string) => fireEvent.change(screen.getByLabelText(l), { target: { value } });
    field("Rotation", "scheduled");
    field(label, "7");
    for (const [l, v] of [["Identifiant", "acc_3"], ["Nom", "db"], ["Cible (hôte:port)", "db:22"], ["Utilisateur sur la cible", "app"], ["Secret initial", "s"],
      ["Compte de réconciliation (même cible ; vide : pas de rotation — obligatoire pour une rotation planifiée)", "acc_root"],
      ["Clé d'hôte de la cible (relevée sur la cible : /etc/ssh/ssh_host_ed25519_key.pub), ou autorité : @cert-authority <nom> <clé de l'autorité>", "ssh-ed25519 AAAAkey"]]) field(l, v);
    fireEvent.submit(form);
    await waitFor(() => expect(calls.some((c) => c.method === "POST")).toBe(true));
    expect(calls.find((c) => c.method === "POST")!.body).toMatchObject({ rotationPolicy: "scheduled", rotationIntervalDays: 7 });
  });

  it("shows a scheduled account's cadence and next rotation", async () => {
    const acc = { id: "acc_1", name: "db", username: "app", targetHost: "db:22", protocol: "ssh", rotationPolicy: "scheduled", createdAt: "2026-10-30T10:00:00Z",
      rotationIntervalDays: 30, nextRotationAt: "2026-11-29T10:00:00Z", hostKeyFingerprint: "SHA256:k" };
    const { api } = fakeApi({ "GET /vault/accounts": { body: { items: [acc], page: 1, pageSize: 20, totalItems: 1 } } });
    signedIn(api, <Accounts />);
    expect((await screen.findByText(/tous les 30 j/)).textContent).toContain("prochaine : 2026-11-29T10:00:00Z");
    expect(screen.queryByText(/en échec/)).toBeNull();
  });

  it("shows an account whose scheduled rotations keep failing (ADR-0041)", async () => {
    const acc = { id: "acc_1", name: "db", username: "app", targetHost: "db:22", protocol: "ssh", rotationPolicy: "scheduled", createdAt: "2026-10-30T10:00:00Z",
      rotationIntervalDays: 30, nextRotationAt: "2026-11-29T10:00:00Z", hostKeyFingerprint: "SHA256:k", rotationFailures: 4 };
    const { api } = fakeApi({ "GET /vault/accounts": { body: { items: [acc], page: 1, pageSize: 20, totalItems: 1 } } });
    signedIn(api, <Accounts />);
    expect((await screen.findByText("en échec (4)")).className).toContain("warn");
  });

  it("shows an account that owes a rotation after use (ADR-0044)", async () => {
    const acc = { id: "acc_1", name: "db", username: "app", targetHost: "db:22", protocol: "ssh", rotationPolicy: "post_use", createdAt: "2026-10-30T10:00:00Z",
      hostKeyFingerprint: "SHA256:k", rotationOwedSince: "2026-10-31T09:00:00Z" };
    const { api } = fakeApi({ "GET /vault/accounts": { body: { items: [acc, { ...acc, id: "acc_2", name: "web", rotationOwedSince: undefined }], page: 1, pageSize: 20, totalItems: 2 } } });
    signedIn(api, <Accounts />);
    expect((await screen.findAllByText("renouvellement dû")).length).toBe(1);
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

describe("Approval with a ticket (ADR-0067)", () => {
  const account = { id: "acc_1", name: "prod db", username: "root", targetHost: "db:22", protocol: "ssh", rotationPolicy: "manual", createdAt: "2026-10-30T10:00:00Z", hostKeyFingerprint: "SHA256:k" };

  it("makes an account require approval, and says which accounts do", async () => {
    const { api, calls } = fakeApi({
      "GET /vault/accounts": { body: { items: [account, { ...account, id: "acc_2", name: "web", approvalRequired: true }], page: 1, pageSize: 20, totalItems: 2 } },
      "PUT /vault/accounts/acc_1/approval": { body: { approvalRequired: true } },
    });
    signedIn(api, <Accounts />);
    expect(await screen.findByText("requise")).toBeTruthy();
    expect(screen.getByText("Ne plus exiger l'approbation")).toBeTruthy(); // acc_2
    fireEvent.click(screen.getByText("Exiger l'approbation")); // acc_1
    expect((await screen.findByRole("status")).textContent).toContain("acc_1 : approbation requise");
    expect(calls.find((c) => c.method === "PUT")).toMatchObject({ path: "/vault/accounts/acc_1/approval", body: { approvalRequired: true } });
  });

  it("onboards an account that requires approval", async () => {
    const { api, calls } = fakeApi({ "GET /vault/accounts": { body: { items: [], page: 1, pageSize: 20, totalItems: 0 } }, "POST /vault/accounts": { status: 201, body: {} } });
    signedIn(api, <Accounts />);
    const form = await screen.findByRole("form", { name: "Enregistrer un compte" });
    fireEvent.click(screen.getByLabelText("Approbation requise : chaque session attend l'accord d'une autre personne, avec un ticket"));
    fireEvent.submit(form);
    await waitFor(() => expect(calls.some((c) => c.method === "POST" && c.path === "/vault/accounts")).toBe(true));
    expect(calls.find((c) => c.method === "POST")!.body).toMatchObject({ approvalRequired: true });
  });

  it("asks for a session with its ticket, and says that it waits", async () => {
    const waiting = { id: "sess_9", status: "pending_approval", protocol: "ssh", requestedBy: "alice", privilegedAccountId: "acc_1", justification: "patch", breakGlass: false, approvalRequired: true, ticket: "CHG0001234", expiresAt: "2026-10-30T11:15:00Z" };
    const { api, calls } = fakeApi({ "GET /sessions": { body: { items: [], page: 1, pageSize: 20, totalItems: 0 } }, "POST /sessions": { status: 201, body: waiting } });
    signedIn(api, <Sessions />);
    const form = await screen.findByRole("form", { name: "Demander une session" });
    const field = (label: string, value: string) => fireEvent.change(screen.getByLabelText(label), { target: { value } });
    field("Compte", "acc_1");
    field("Justification", "patch");
    field("Durée (minutes)", "45");
    field("Ticket (si le compte exige une approbation)", "CHG0001234");
    fireEvent.submit(form);
    expect((await screen.findByRole("status")).textContent).toContain("sess_9 en attente de l'approbation d'une autre personne");
    expect(calls.find((c) => c.method === "POST")!.body).toEqual({ targetAccountId: "acc_1", justification: "patch", durationMinutes: 45, ticket: "CHG0001234", protocol: "ssh" });
  });

  it("shows the approver the ticket of a request, and which kind of request it is", async () => {
    const req = { id: "sess_9", status: "pending_approval", protocol: "ssh", requestedBy: "alice", privilegedAccountId: "acc_1", justification: "patch", breakGlass: false, approvalRequired: true, ticket: "CHG0001234", expiresAt: "2026-10-30T11:15:00Z" };
    const { api, calls } = fakeApi({ "GET /sessions": { body: { items: [req], page: 1, pageSize: 20, totalItems: 1 } }, "POST /sessions/sess_9/reject": { body: req } });
    signedIn(api, <Sessions />);
    expect(await screen.findByText("CHG0001234")).toBeTruthy();
    expect(screen.getByText("approbation")).toBeTruthy();
    fireEvent.click(screen.getByText("Refuser"));
    expect((await screen.findByRole("status")).textContent).toContain("sess_9 refusée");
    expect(calls.some((c) => c.method === "POST" && c.path === "/sessions/sess_9/reject")).toBe(true);
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

describe("Graphical accounts and sessions (ADR-0071)", () => {
  const vnc = { id: "acc_v", name: "bureau", username: "ops", targetHost: "desk:5900", protocol: "vnc", rotationPolicy: "manual", createdAt: "2026-10-30T10:00:00Z" };
  const page = (items: unknown[]) => ({ body: { items, page: 1, pageSize: 20, totalItems: items.length } });
  const session = { id: "sess_v", status: "active", protocol: "vnc", requestedBy: "alice", privilegedAccountId: "acc_v", justification: "patch", breakGlass: false, expiresAt: "2030-01-01T00:00:00Z" };

  it("onboards a VNC account with neither host key nor rotation, and sends its secret once", async () => {
    const { api, calls } = fakeApi({ "GET /vault/accounts": page([]), "POST /vault/accounts": { status: 201, body: {} } });
    signedIn(api, <Accounts />);
    const form = await screen.findByRole("form", { name: "Enregistrer un compte" });
    const field = (label: string, value: string) => fireEvent.change(screen.getByLabelText(label), { target: { value } });
    field("Protocole", "vnc");
    expect(screen.queryByLabelText("Rotation")).toBeNull();
    expect(screen.queryByPlaceholderText("ssh-ed25519 AAAA…")).toBeNull();
    field("Identifiant", "acc_v");
    field("Nom", "bureau");
    field("Cible (hôte:port)", "desk:5900");
    field("Utilisateur sur la cible", "ops");
    field("Secret initial", "pw");
    fireEvent.submit(form);
    await waitFor(() => expect(calls.some((c) => c.method === "POST")).toBe(true));
    expect(calls.find((c) => c.method === "POST")!.body).toMatchObject({ protocol: "vnc", rotationPolicy: "manual", hostKey: "", reconciliationAccountId: "" });
    expect((screen.getByLabelText("Secret initial") as HTMLInputElement).value).toBe("");
  });

  it("pins a VNC account's certificate, offers no rotation, and says when it is not pinned", async () => {
    const { api, calls } = fakeApi({ "GET /vault/accounts": page([vnc]), "PUT /vault/accounts/acc_v/tls-pin": { body: {} } });
    signedIn(api, <Accounts />);
    expect(await screen.findByText("non épinglée")).toBeTruthy();
    expect(screen.queryByText("Renouveler le secret")).toBeNull();
    const prompt = vi.spyOn(window, "prompt").mockReturnValueOnce(" ab12 ").mockReturnValueOnce("desk.example");
    fireEvent.click(screen.getByText("Épingler le certificat TLS"));
    expect((await screen.findByRole("status")).textContent).toContain("Certificat TLS de acc_v épinglé");
    expect(calls.find((c) => c.method === "PUT")).toMatchObject({ path: "/vault/accounts/acc_v/tls-pin", body: { tlsCertificateSha256: "ab12", targetDomain: "desk.example" } });
    prompt.mockRestore();
  });

  it("changes nothing when the pin is cancelled at either question", async () => {
    const { api, calls } = fakeApi({ "GET /vault/accounts": page([vnc]) });
    signedIn(api, <Accounts />);
    await screen.findByText("non épinglée");
    const prompt = vi.spyOn(window, "prompt").mockReturnValueOnce(null).mockReturnValueOnce("ab12").mockReturnValueOnce(null);
    fireEvent.click(screen.getByText("Épingler le certificat TLS"));
    fireEvent.click(screen.getByText("Épingler le certificat TLS"));
    expect(calls.some((c) => c.method === "PUT")).toBe(false);
    prompt.mockRestore();
  });

  it("shows a pinned certificate where an SSH account shows its host key", async () => {
    const { api } = fakeApi({ "GET /vault/accounts": page([{ ...vnc, tlsCertificateSha256: "ab".repeat(32), targetDomain: "desk.example" }]) });
    signedIn(api, <Accounts />);
    expect(await screen.findByText("ab".repeat(32))).toBeTruthy();
    expect(screen.getByText("Changer le certificat TLS")).toBeTruthy();
  });

  it("asks for a session in the protocol chosen, and offers the screen once it is active", async () => {
    const socketOpen = vi.fn(function () {
      return { close: vi.fn(), send: vi.fn(), readyState: 0 };
    });
    vi.stubGlobal("WebSocket", socketOpen);
    const { api, calls } = fakeApi({ "GET /sessions": page([]), "POST /sessions": { status: 201, body: session }, "POST /sessions/sess_v/connect": { body: { protocol: "vnc", attach: "/sessions/sess_v/screen", expiresAt: "2030-01-01T00:00:00Z" } } });
    signedIn(api, <Sessions />);
    const form = await screen.findByRole("form", { name: "Demander une session" });
    const field = (label: string, value: string) => fireEvent.change(screen.getByLabelText(label), { target: { value } });
    field("Compte", "acc_v");
    field("Protocole du compte", "vnc");
    field("Justification", "patch");
    fireEvent.submit(form);
    fireEvent.click(await screen.findByText("Ouvrir l'écran"));
    await waitFor(() => expect(socketOpen).toHaveBeenCalledOnce());
    expect(calls.find((c) => c.path === "/sessions")?.body).toMatchObject({ protocol: "vnc" });
    expect(socketOpen).toHaveBeenCalledWith(expect.stringMatching(/\/sessions\/sess_v\/screen$/), "openbastion.screen.v1");
    vi.unstubAllGlobals();
  });

  // A browser ignores Set-Cookie on a call made with credentials "omit": without this, no screen
  // ever attaches, and no test with a fake API would ever say so.
  it("lets the attach cookie land on connect, and on nothing else", async () => {
    vi.stubGlobal("WebSocket", vi.fn(function () {
      return { close: vi.fn(), send: vi.fn(), readyState: 0 };
    }));
    const { api, calls } = fakeApi({ "GET /sessions": page([]), "GET /sessions/sess_v": { body: session }, "POST /sessions/sess_v/connect": { body: { protocol: "vnc", attach: "/sessions/sess_v/screen", expiresAt: "2030-01-01T00:00:00Z" } } });
    signedIn(api, <Sessions />);
    fireEvent.change(await screen.findByLabelText("Identifiant"), { target: { value: "sess_v" } });
    fireEvent.submit(screen.getByRole("form", { name: "Chercher une session" }));
    fireEvent.click(await screen.findByText("Ouvrir l'écran"));
    await waitFor(() => expect(calls.some((c) => c.path === "/sessions/sess_v/connect")).toBe(true));
    for (const call of calls) expect(call.credentials, call.path).toBe(call.path === "/sessions/sess_v/connect" ? "same-origin" : "omit");
    vi.unstubAllGlobals();
  });

  it("says why a screen cannot be attached, and opens nothing", async () => {
    const socketOpen = vi.fn();
    vi.stubGlobal("WebSocket", socketOpen);
    const { api } = fakeApi({ "GET /sessions": page([]), "GET /sessions/sess_v": { body: session }, "POST /sessions/sess_v/connect": { status: 409, body: { message: "no_pinned_tls_certificate" } } });
    signedIn(api, <Sessions />);
    fireEvent.change(await screen.findByLabelText("Identifiant"), { target: { value: "sess_v" } });
    fireEvent.submit(screen.getByRole("form", { name: "Chercher une session" }));
    fireEvent.click(await screen.findByText("Ouvrir l'écran"));
    expect((await screen.findByRole("alert")).textContent).toContain("no_pinned_tls_certificate");
    expect(socketOpen).not.toHaveBeenCalled();
    vi.unstubAllGlobals();
  });

  it("offers no screen for an SSH session, nor one that is not active", async () => {
    const { api } = fakeApi({ "GET /sessions": page([]), "GET /sessions/sess_v": { body: { ...session, protocol: "ssh" } }, "GET /sessions/sess_w": { body: { ...session, status: "pending_approval" } } });
    signedIn(api, <Sessions />);
    const find = async (id: string) => {
      fireEvent.change(screen.getByLabelText("Identifiant"), { target: { value: id } });
      fireEvent.submit(screen.getByRole("form", { name: "Chercher une session" }));
      await screen.findByText(id === "sess_v" ? "ssh" : "pending_approval");
    };
    await screen.findByLabelText("Identifiant");
    await find("sess_v");
    expect(screen.queryByText("Ouvrir l'écran")).toBeNull();
    await find("sess_w");
    expect(screen.queryByText("Ouvrir l'écran")).toBeNull();
  });
});
