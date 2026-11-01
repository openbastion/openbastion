// WebAuthn in the browser (ADR-0065): the server's options, base64url as JSON carries them, become
// the buffers navigator.credentials wants; its answer becomes JSON again, as the server reads it.
// No dependency: the browser does the ceremony, the server verifies it.

export type Credentials = Pick<CredentialsContainer, "create" | "get">;

const fromB64 = (s: string): ArrayBuffer => {
  const b = atob(s.replace(/-/g, "+").replace(/_/g, "/").padEnd(Math.ceil(s.length / 4) * 4, "="));
  const out = new Uint8Array(b.length);
  for (let i = 0; i < b.length; i++) out[i] = b.charCodeAt(i);
  return out.buffer;
};

const toB64 = (buf: ArrayBuffer | null | undefined): string | undefined => {
  if (!buf) return undefined;
  const bytes = new Uint8Array(buf);
  let s = "";
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
};

type Descriptor = { id: string; type: string; transports?: string[] };
type Options = { publicKey: Record<string, unknown> };

function descriptors(list: unknown): PublicKeyCredentialDescriptor[] | undefined {
  if (!Array.isArray(list)) return undefined;
  return (list as Descriptor[]).map((d) => ({ ...d, id: fromB64(d.id) }) as PublicKeyCredentialDescriptor);
}

function credentialJSON(c: PublicKeyCredential): Record<string, unknown> {
  const r = c.response as AuthenticatorAttestationResponse & AuthenticatorAssertionResponse;
  const response: Record<string, unknown> = { clientDataJSON: toB64(r.clientDataJSON) };
  if ("attestationObject" in r && r.attestationObject) response.attestationObject = toB64(r.attestationObject);
  if ("authenticatorData" in r && r.authenticatorData) {
    response.authenticatorData = toB64(r.authenticatorData);
    response.signature = toB64(r.signature);
    response.userHandle = toB64(r.userHandle) ?? "";
  }
  return { id: c.id, rawId: toB64(c.rawId), type: c.type, response, clientExtensionResults: c.getClientExtensionResults?.() ?? {} };
}

// register asks the browser for a new security key, for the creation options of the server.
export async function register(options: unknown, credentials: Credentials = navigator.credentials): Promise<Record<string, unknown>> {
  const pk = (options as Options).publicKey;
  const user = pk.user as { id: string; name: string; displayName: string };
  const c = await credentials.create({
    publicKey: {
      ...(pk as unknown as PublicKeyCredentialCreationOptions),
      challenge: fromB64(pk.challenge as string),
      user: { ...user, id: fromB64(user.id) },
      excludeCredentials: descriptors(pk.excludeCredentials),
    },
  });
  if (!c) throw new Error("la clé de sécurité n'a rien répondu");
  return credentialJSON(c as PublicKeyCredential);
}

// sign asks the browser for a signature by one of the account's keys, for the request options.
export async function sign(options: unknown, credentials: Credentials = navigator.credentials): Promise<Record<string, unknown>> {
  const pk = (options as Options).publicKey;
  const c = await credentials.get({
    publicKey: {
      ...(pk as unknown as PublicKeyCredentialRequestOptions),
      challenge: fromB64(pk.challenge as string),
      allowCredentials: descriptors(pk.allowCredentials),
    },
  });
  if (!c) throw new Error("la clé de sécurité n'a rien répondu");
  return credentialJSON(c as PublicKeyCredential);
}

export const _test = { fromB64, toB64 };
