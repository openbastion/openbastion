import { describe, expect, it } from "vitest";
import { hexToBytes, sealPaste, validPassword } from "./pasteCrypto";
import { encodePasteInput } from "./protocol";

// The known-answer vector of pkg/proxycore/paste_vector_test.go: the same keys, token, nonce, session,
// protocol and text must give the same ciphertext, byte for byte. If this test and the Go one both
// pass, the browser and the proxy agree on the whole of ADR-0133's encryption.
const PROXY_KEY = "046ff03b949241ce1dadd43519e6960e0a85b41a69a05c328103aa2bce1594ca163c4f753a55bf01dc53f6c0b0c7eee78b40c6ff7d25a96e2282b989cef71c144a";
const CLIENT_KEY = "04550f471003f3df97c3df506ac797f6721fb1a1fb7b8f6f83d224498a65c88e24136093d7012e509a73715cbd0b00a3cc0ff4b5c01b3ffa196ab1fb327036b8e6";
const CLIENT_SCALAR = "02".repeat(32);
const CIPHERTEXT = "305c0501b12f9e69ccd392935fc1633995666b67d4c4a0050baaf697e8732b";

function base64url(bytes: Uint8Array): string {
  return btoa(String.fromCharCode(...bytes)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

async function fixedClientKeys(): Promise<CryptoKeyPair> {
  const pub = hexToBytes(CLIENT_KEY);
  const jwk = { kty: "EC", crv: "P-256", x: base64url(pub.slice(1, 33)), y: base64url(pub.slice(33)), d: base64url(hexToBytes(CLIENT_SCALAR)), ext: true };
  const privateKey = await crypto.subtle.importKey("jwk", jwk, { name: "ECDH", namedCurve: "P-256" }, true, ["deriveBits"]);
  const publicKey = await crypto.subtle.importKey("raw", pub, { name: "ECDH", namedCurve: "P-256" }, true, []);
  return { privateKey, publicKey };
}

describe("an operator's password, encrypted for the proxy (ADR-0133)", () => {
  it("gives the Go side's ciphertext for the known-answer vector", async () => {
    const sealed = await sealPaste(hexToBytes(PROXY_KEY), "session-vector", "rdp", hexToBytes("03".repeat(32)), "Correct-Horse-1",
      { clientKeys: await fixedClientKeys(), nonce: hexToBytes("04".repeat(12)) });
    expect([...sealed.clientKey].map((b) => b.toString(16).padStart(2, "0")).join("")).toBe(CLIENT_KEY);
    expect([...sealed.ciphertext].map((b) => b.toString(16).padStart(2, "0")).join("")).toBe(CIPHERTEXT);
  });

  it("does not give it for another session, protocol or text", async () => {
    const keys = await fixedClientKeys();
    const hex = async (session: string, protocol: "rdp" | "vnc", text: string) => {
      const s = await sealPaste(hexToBytes(PROXY_KEY), session, protocol, hexToBytes("03".repeat(32)), text, { clientKeys: keys, nonce: hexToBytes("04".repeat(12)) });
      return [...s.ciphertext].map((b) => b.toString(16).padStart(2, "0")).join("");
    };
    expect(await hex("session-other", "rdp", "Correct-Horse-1")).not.toBe(CIPHERTEXT);
    expect(await hex("session-vector", "vnc", "Correct-Horse-1")).not.toBe(CIPHERTEXT);
    expect(await hex("session-vector", "rdp", "Correct-Horse-2")).not.toBe(CIPHERTEXT);
  });

  it("draws a fresh key and nonce each time, and never carries the text in clear", async () => {
    const a = await sealPaste(hexToBytes(PROXY_KEY), "s", "vnc", hexToBytes("03".repeat(32)), "Correct-Horse-1");
    const b = await sealPaste(hexToBytes(PROXY_KEY), "s", "vnc", hexToBytes("03".repeat(32)), "Correct-Horse-1");
    expect(a.clientKey).not.toEqual(b.clientKey);
    expect(a.nonce).not.toEqual(b.nonce);
    expect(new TextDecoder().decode(a.ciphertext)).not.toContain("Correct-Horse");
  });

  it("encodes the InputPaste message as pkg/screenstream reads it", async () => {
    const s = await sealPaste(hexToBytes(PROXY_KEY), "s", "vnc", hexToBytes("03".repeat(32)), "x");
    const message = encodePasteInput(s.token, s.clientKey, s.nonce, s.ciphertext)!;
    expect([...message.slice(0, 4)]).toEqual([1, 6, 0, 0]);
    expect(message.length).toBe(4 + 32 + 65 + 12 + 2 + s.ciphertext.length);
    expect(new DataView(message.buffer).getUint16(4 + 32 + 65 + 12)).toBe(s.ciphertext.length);
    expect(encodePasteInput(s.token, s.clientKey, s.nonce, new Uint8Array(529))).toBeNull();
    expect(encodePasteInput(s.token.slice(1), s.clientKey, s.nonce, s.ciphertext)).toBeNull();
  });

  it("takes a password, not a script", () => {
    expect(validPassword("Correct-Horse-1")).toBe(true);
    expect(validPassword("é".repeat(128))).toBe(true);
    for (const bad of ["", "a".repeat(129), "line\nbreak", "tab\there", "nul\u0000", "del\u007f"]) expect(validPassword(bad)).toBe(false);
  });
});
