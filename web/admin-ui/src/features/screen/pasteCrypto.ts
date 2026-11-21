// An operator's password, encrypted in the browser for the screen proxy (ADR-0133). The Gateway relays
// the screen stream by decoding its frames: it must only ever hold the ciphertext. The proxy published
// its ephemeral P-256 key in the HELLO; this draws an ephemeral key of its own per password, derives an
// AES-256-GCM key by HKDF-SHA-256 from the ECDH secret — salted by the one-use paste token, bound to
// both public keys — and encrypts with the session, the token and the protocol as associated data.
// pkg/proxycore/paste.go is the other side; paste_vector_test.go and pasteCrypto.test.ts check both
// against the same known-answer vector.
//
// What this does not protect from, said in ADR-0133: a compromised Gateway serves this very code.

const HKDF_INFO = "openbastion paste v1";
const AAD_LABEL = "openbastion-paste-v1";
export const PASTE_TOKEN_SIZE = 32;
export const PASTE_NONCE_SIZE = 12;
export const MAX_PASTE_CHARACTERS = 128;

export interface SealedPaste {
  token: Uint8Array;
  clientKey: Uint8Array; // 65 bytes, uncompressed
  nonce: Uint8Array;
  ciphertext: Uint8Array;
}

function concat(...parts: Uint8Array[]): Uint8Array<ArrayBuffer> {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let at = 0;
  for (const p of parts) {
    out.set(p, at);
    at += p.length;
  }
  return out;
}

export function hexToBytes(hex: string): Uint8Array<ArrayBuffer> {
  if (!/^(?:[0-9a-f]{2})*$/.test(hex)) throw new Error("not hexadecimal");
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return out;
}

// What a password may be (ADR-0097 §6): 1 to 128 characters, one line, no tab nor control character.
// The proxy checks again; this only spares the operator a second factor for a text it would refuse.
export function validPassword(text: string): boolean {
  const characters = [...text];
  return characters.length >= 1 && characters.length <= MAX_PASTE_CHARACTERS &&
    characters.every((c) => { const code = c.codePointAt(0) ?? 0; return code >= 0x20 && code !== 0x7f; });
}

// The associated data, byte for byte as the proxy builds it: label, 0, session, 0, token, protocol.
function associatedData(sessionId: string, token: Uint8Array, protocol: "rdp" | "vnc"): Uint8Array<ArrayBuffer> {
  const encode = (s: string) => new TextEncoder().encode(s);
  return concat(encode(AAD_LABEL), new Uint8Array([0]), encode(sessionId), new Uint8Array([0]), token, encode(protocol));
}

// sealPaste encrypts text for the proxy key of this screen session. The ephemeral key and the nonce
// are drawn here; a test may give its own to reproduce the known-answer vector.
export async function sealPaste(
  proxyKey: Uint8Array, sessionId: string, protocol: "rdp" | "vnc", token: Uint8Array, text: string,
  fixed?: { clientKeys: CryptoKeyPair; nonce: Uint8Array },
): Promise<SealedPaste> {
  const subtle = globalThis.crypto.subtle;
  if (proxyKey.length !== 65 || proxyKey[0] !== 0x04 || token.length !== PASTE_TOKEN_SIZE) throw new Error("invalid paste key or token");
  const proxy = await subtle.importKey("raw", concat(proxyKey), { name: "ECDH", namedCurve: "P-256" }, false, []);
  const clientKeys = fixed?.clientKeys ?? await subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, false, ["deriveBits"]) as CryptoKeyPair;
  const clientKey = new Uint8Array(await subtle.exportKey("raw", clientKeys.publicKey));
  const shared = await subtle.deriveBits({ name: "ECDH", public: proxy }, clientKeys.privateKey, 256);
  const hkdfKey = await subtle.importKey("raw", shared, "HKDF", false, ["deriveKey"]);
  const aesKey = await subtle.deriveKey(
    { name: "HKDF", hash: "SHA-256", salt: concat(token), info: concat(new TextEncoder().encode(HKDF_INFO), clientKey, proxyKey) },
    hkdfKey, { name: "AES-GCM", length: 256 }, false, ["encrypt"],
  );
  const nonce = fixed?.nonce ?? globalThis.crypto.getRandomValues(new Uint8Array(PASTE_NONCE_SIZE));
  const ciphertext = new Uint8Array(await subtle.encrypt(
    { name: "AES-GCM", iv: concat(nonce), additionalData: associatedData(sessionId, token, protocol) },
    aesKey, new TextEncoder().encode(text),
  ));
  return { token, clientKey, nonce, ciphertext };
}
