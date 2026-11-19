import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import { Session } from "../../shared/api";
import { SignedInContext } from "../../shared/session";
import { fakeApi } from "../../test-helpers";
import { SecretInjection } from "./SecretInjection";

const session: Session = {
  id: "session-1",
  status: "active",
  protocol: "rdp",
  requestedBy: "alice",
  privilegedAccountId: "account-1",
  justification: "maintenance",
  breakGlass: false,
  expiresAt: "2026-11-15T09:00:00Z",
};

function renderInjection(
  routes: Record<string, { status?: number; body?: unknown }>,
  credentials?: CredentialsContainer,
  currentSession: Session = session,
) {
  const { api, calls } = fakeApi(routes);
  const view = render(
    <SignedInContext.Provider value={{ api, who: null, signOut: vi.fn() }}>
      <SecretInjection session={currentSession} credentials={credentials as unknown as import("../../shared/webauthn").Credentials | undefined} />
    </SignedInContext.Provider>,
  );
  return { calls, ...view };
}

function fakeWebAuthnCredentials(): CredentialsContainer {
  const bytes = (...values: number[]) => new Uint8Array(values).buffer;
  return {
    get: vi.fn(async () => ({
      id: "credential-id",
      rawId: bytes(1, 2, 3),
      type: "public-key",
      response: {
        clientDataJSON: bytes(4),
        authenticatorData: bytes(5),
        signature: bytes(6),
        userHandle: null,
      },
      getClientExtensionResults: () => ({}),
    }) as unknown as PublicKeyCredential),
    create: vi.fn(async () => null),
  } as unknown as CredentialsContainer;
}

describe("Vault secret injection in a session (ADR-0097)", () => {
  it("hides the action for inactive sessions and protocols without a typer", () => {
    const inactive = { ...session, status: "terminated" } as Session;
    const { unmount } = renderInjection({}, undefined, inactive);
    expect(screen.queryByRole("button", { name: "Saisir le secret Vault" })).toBeNull();
    unmount();
    const unsupported = { ...session, protocol: "telnet" } as Session;
    renderInjection({}, undefined, unsupported);
    expect(screen.queryByRole("button", { name: "Saisir le secret Vault" })).toBeNull();
  });

  it("does not request a challenge when the operator cancels the warning", () => {
    const { calls } = renderInjection({});
    fireEvent.click(screen.getByRole("button", { name: "Saisir le secret Vault" }));
    expect(screen.getByRole("alertdialog")).toBeTruthy();
    expect(screen.getByText(/mot de passe masqué/i)).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: "Annuler" }));
    expect(calls).toHaveLength(0);
  });

  it("starts action-bound MFA and submits only a TOTP proof, never a target secret", async () => {
    const { calls } = renderInjection({
      "POST /sessions/session-1/secret-injection-step-up": {
        body: { challenge: "opaque-challenge", expires_in: 120, factors: ["totp"] },
      },
      "POST /sessions/session-1/secret-injection": { status: 204 },
    });

    fireEvent.click(screen.getByRole("button", { name: "Saisir le secret Vault" }));
    fireEvent.click(screen.getByRole("button", { name: "Continuer vers la confirmation MFA" }));
    await waitFor(() => expect(calls).toHaveLength(1));
    expect(calls[0]).toMatchObject({ method: "POST", path: "/sessions/session-1/secret-injection-step-up" });
    expect(calls[0].body).toBeUndefined();
    expect(await screen.findByLabelText("Code de vérification")).toBeTruthy();

    fireEvent.change(screen.getByLabelText("Code de vérification"), { target: { value: "123456" } });
    fireEvent.click(screen.getByRole("button", { name: "Confirmer et saisir" }));
    await waitFor(() => expect(calls).toHaveLength(2));
    expect(calls[1].body).toEqual({ challenge: "opaque-challenge", factor: "totp", totp_code: "123456" });
    expect(JSON.stringify(calls[1].body)).not.toMatch(/secret|password|credential/i);
    expect(await screen.findByRole("status")).toBeTruthy();
    expect(screen.queryByDisplayValue("123456")).toBeNull();
  });

  it("refuses a challenge with no WebAuthn options instead of downgrading the factor", async () => {
    const { calls } = renderInjection({
      "POST /sessions/session-1/secret-injection-step-up": {
        body: { challenge: "opaque-key-challenge", expires_in: 120, factors: ["webauthn"] },
      },
    });
    fireEvent.click(screen.getByRole("button", { name: "Saisir le secret Vault" }));
    fireEvent.click(screen.getByRole("button", { name: "Continuer vers la confirmation MFA" }));
    expect(await screen.findByText("Aucun facteur MFA utilisable n'a été fourni. La saisie est refusée.")).toBeTruthy();
    expect(calls).toHaveLength(1);
    expect(screen.queryByLabelText("Code de vérification")).toBeNull();
  });

  it("uses the browser WebAuthn assertion when only the security key is allowed", async () => {
    const credentials = fakeWebAuthnCredentials();
    const { calls } = renderInjection({
      "POST /sessions/session-1/secret-injection-step-up": {
        body: {
          challenge: "opaque-key-challenge",
          expires_in: 120,
          factors: ["webauthn"],
          webauthn: { publicKey: { challenge: "AQID", rpId: "localhost", allowCredentials: [] } },
        },
      },
      "POST /sessions/session-1/secret-injection": { status: 204 },
    }, credentials);

    fireEvent.click(screen.getByRole("button", { name: "Saisir le secret Vault" }));
    fireEvent.click(screen.getByRole("button", { name: "Continuer vers la confirmation MFA" }));
    await screen.findByRole("button", { name: "Utiliser ma clé de sécurité" });
    expect(screen.queryByLabelText("Code de vérification")).toBeNull();
    fireEvent.click(screen.getByRole("button", { name: "Utiliser ma clé de sécurité" }));
    await waitFor(() => expect(calls).toHaveLength(2));
    expect(credentials.get).toHaveBeenCalledTimes(1);
    expect(calls[1].body).toMatchObject({ challenge: "opaque-key-challenge", factor: "webauthn", webauthn_response: { id: "credential-id" } });
    expect(calls[1].body).not.toHaveProperty("totp_code");
  });

  it("shows a refusal and keeps the challenge flow fail-closed", async () => {
    const { calls } = renderInjection({
      "POST /sessions/session-1/secret-injection-step-up": {
        body: { challenge: "opaque-challenge", expires_in: 120, factors: ["totp"] },
      },
      "POST /sessions/session-1/secret-injection": { status: 403, body: { message: "secret injection is not authorized or MFA verification failed" } },
    });

    fireEvent.click(screen.getByRole("button", { name: "Saisir le secret Vault" }));
    fireEvent.click(screen.getByRole("button", { name: "Continuer vers la confirmation MFA" }));
    fireEvent.change(await screen.findByLabelText("Code de vérification"), { target: { value: "123456" } });
    fireEvent.click(screen.getByRole("button", { name: "Confirmer et saisir" }));
    expect(await screen.findByRole("alert")).toBeTruthy();
    expect(screen.queryByDisplayValue("123456")).toBeNull();
    expect(calls).toHaveLength(2);
  });

  it("does not submit a proof after the local challenge expiry", async () => {
    const now = vi.spyOn(Date, "now").mockReturnValue(1_000);
    try {
      const { calls } = renderInjection({
        "POST /sessions/session-1/secret-injection-step-up": {
          body: { challenge: "opaque-challenge", expires_in: 120, factors: ["totp"] },
        },
      });
      fireEvent.click(screen.getByRole("button", { name: "Saisir le secret Vault" }));
      fireEvent.click(screen.getByRole("button", { name: "Continuer vers la confirmation MFA" }));
      fireEvent.change(await screen.findByLabelText("Code de vérification"), { target: { value: "123456" } });
      now.mockReturnValue(121_000);
      fireEvent.click(screen.getByRole("button", { name: "Confirmer et saisir" }));
      expect(await screen.findByRole("alert")).toBeTruthy();
      expect(calls).toHaveLength(1); // challenge only; no proof reached the Gateway
      expect(screen.queryByLabelText("Code de vérification")).toBeNull();
    } finally {
      now.mockRestore();
    }
  });
});
