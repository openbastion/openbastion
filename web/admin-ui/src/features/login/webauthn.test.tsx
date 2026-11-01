import { describe, expect, it, vi } from "vitest";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { SecondFactor } from "./SecondFactor";
import { fakeApi } from "../../test-helpers";
import { _test } from "../../shared/webauthn";

const buf = (...b: number[]) => new Uint8Array(b).buffer;

// A browser's security key: it records what it was asked, and answers with fixed bytes.
function fakeCredentials() {
  const asked: { get?: CredentialRequestOptions; create?: CredentialCreationOptions } = {};
  const answer = (response: Record<string, unknown>) =>
    ({ id: "Cgs", rawId: buf(10, 11), type: "public-key", response, getClientExtensionResults: () => ({}) }) as unknown as Credential;
  return {
    asked,
    credentials: {
      get: vi.fn(async (o?: CredentialRequestOptions) => {
        asked.get = o;
        return answer({ clientDataJSON: buf(1), authenticatorData: buf(2), signature: buf(3), userHandle: buf(4) });
      }),
      create: vi.fn(async (o?: CredentialCreationOptions) => {
        asked.create = o;
        return answer({ clientDataJSON: buf(5), attestationObject: buf(6) });
      }),
    },
  };
}

describe("WebAuthn in the login (ADR-0065)", () => {
  it("base64url goes both ways, without padding", () => {
    for (const s of ["", "AQ", "AQID", "_-8", "AQIDBA"]) expect(_test.toB64(_test.fromB64(s))).toBe(s);
  });

  it("a strict role is offered its key only, and the browser's signature is what is sent", async () => {
    const { api, calls } = fakeApi({ "POST /auth/mfa/webauthn/verify": { body: { accessToken: "key-tok", expiresIn: 3600 } } });
    const { credentials, asked } = fakeCredentials();
    const onToken = vi.fn();
    const options = { publicKey: { challenge: "AQID", rpId: "localhost", allowCredentials: [{ id: "CQk", type: "public-key" }] } };
    render(<SecondFactor api={api} challenge={{ kind: "required", challenge: "ch-k", factors: ["webauthn"], webauthn: options }} onToken={onToken} onCancel={vi.fn()} credentials={credentials} />);
    expect(screen.queryByLabelText("Code de l'application d'authentification")).toBeNull(); // no TOTP for a strict role
    fireEvent.click(screen.getByText("Utiliser ma clé de sécurité"));
    await waitFor(() => expect(onToken).toHaveBeenCalledWith("key-tok"));
    expect(new Uint8Array(asked.get!.publicKey!.challenge as ArrayBuffer)).toEqual(new Uint8Array([1, 2, 3]));
    expect(new Uint8Array(asked.get!.publicKey!.allowCredentials![0].id as ArrayBuffer)).toEqual(new Uint8Array([9, 9]));
    expect(calls[0].path).toBe("/auth/mfa/webauthn/verify");
    expect(calls[0].body).toEqual({
      challenge: "ch-k",
      credential: { id: "Cgs", rawId: "Cgs", type: "public-key", clientExtensionResults: {}, response: { clientDataJSON: "AQ", authenticatorData: "Ag", signature: "Aw", userHandle: "BA" } },
    });
  });

  it("a key is enrolled with the administrator's code, the browser's new key sent to confirm", async () => {
    const { api, calls } = fakeApi({
      "POST /auth/mfa/enroll": { body: { webauthn: { publicKey: { challenge: "BwgJ", rp: { id: "localhost", name: "OpenBastion" }, user: { id: "dXNlcl8x", name: "root", displayName: "Root" } } } } },
      "POST /auth/mfa/webauthn/enroll/confirm": { body: { accessToken: "enrolled-key", expiresIn: 3600 } },
    });
    const { credentials, asked } = fakeCredentials();
    const onToken = vi.fn();
    render(<SecondFactor api={api} challenge={{ kind: "enrollment_required", challenge: "ch-e", factors: ["webauthn"] }} onToken={onToken} onCancel={vi.fn()} credentials={credentials} />);
    expect(screen.queryByText("Recevoir le secret")).toBeNull();
    fireEvent.change(screen.getByLabelText("Code d'enrôlement"), { target: { value: "abcd" } });
    fireEvent.click(screen.getByText("Enrôler une clé de sécurité"));
    await waitFor(() => expect(onToken).toHaveBeenCalledWith("enrolled-key"));
    expect(calls[0].body).toEqual({ challenge: "ch-e", enrollmentCode: "abcd", factor: "webauthn" });
    expect(new TextDecoder().decode(asked.create!.publicKey!.user.id as ArrayBuffer)).toBe("user_1");
    expect(calls[1].body).toMatchObject({ challenge: "ch-e", credential: { response: { clientDataJSON: "BQ", attestationObject: "Bg" } } });
  });

  it("a key the browser does not give is an error, and nothing is sent", async () => {
    const { api, calls } = fakeApi({});
    const credentials = { get: vi.fn(async () => null), create: vi.fn(async () => null) };
    render(<SecondFactor api={api} challenge={{ kind: "required", challenge: "c", factors: ["webauthn"], webauthn: { publicKey: { challenge: "AQ" } } }} onToken={vi.fn()} onCancel={vi.fn()} credentials={credentials} />);
    fireEvent.click(screen.getByText("Utiliser ma clé de sécurité"));
    expect(await screen.findByRole("alert")).toBeTruthy();
    expect(calls).toHaveLength(0);
  });

  it("a backup key: the current key signs, with the administrator's code, then the new key is sent", async () => {
    const { api, calls } = fakeApi({
      "POST /auth/mfa/webauthn/keys/add": { body: { webauthn: { publicKey: { challenge: "Dw", rp: { id: "localhost" }, user: { id: "dXNlcl8x", name: "root", displayName: "Root" } } } } },
      "POST /auth/mfa/webauthn/enroll/confirm": { body: { accessToken: "two-keys", expiresIn: 3600 } },
    });
    const { credentials } = fakeCredentials();
    const onToken = vi.fn();
    render(<SecondFactor api={api} challenge={{ kind: "required", challenge: "ch-b", factors: ["webauthn"], webauthn: { publicKey: { challenge: "AQ" } } }} onToken={onToken} onCancel={vi.fn()} credentials={credentials} />);
    fireEvent.click(screen.getByText("Ajouter une clé de secours"));
    fireEvent.change(screen.getByLabelText("Code d'enrôlement"), { target: { value: "admin-code" } });
    fireEvent.click(screen.getByText("Signer avec ma clé, puis ajouter la nouvelle"));
    await waitFor(() => expect(onToken).toHaveBeenCalledWith("two-keys"));
    expect(credentials.get).toHaveBeenCalledTimes(1);
    expect(credentials.create).toHaveBeenCalledTimes(1);
    expect(calls[0].path).toBe("/auth/mfa/webauthn/keys/add");
    expect(calls[0].body).toMatchObject({ challenge: "ch-b", enrollmentCode: "admin-code", credential: { response: { signature: "Aw" } } });
    expect(calls[1].body).toMatchObject({ challenge: "ch-b", credential: { response: { attestationObject: "Bg" } } });
  });
});
