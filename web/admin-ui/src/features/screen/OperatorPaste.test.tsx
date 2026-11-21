import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import { SignedInContext } from "../../shared/session";
import { fakeApi } from "../../test-helpers";
import { OperatorPaste } from "./OperatorPaste";
import { hexToBytes } from "./pasteCrypto";

const PROXY_KEY = hexToBytes("046ff03b949241ce1dadd43519e6960e0a85b41a69a05c328103aa2bce1594ca163c4f753a55bf01dc53f6c0b0c7eee78b40c6ff7d25a96e2282b989cef71c144a");
const TOKEN = "ab".repeat(32);
const PASSWORD = "Correct-Horse-1";

function renderPaste(routes: Record<string, { status?: number; body?: unknown }>) {
  const { api, calls } = fakeApi(routes);
  const send = vi.fn();
  render(
    <SignedInContext.Provider value={{ api, who: null, signOut: vi.fn() }}>
      <OperatorPaste sessionId="session-1" protocol="rdp" pasteKey={PROXY_KEY} send={send} />
    </SignedInContext.Provider>,
  );
  return { calls, send };
}

function typePassword(text: string) {
  fireEvent.click(screen.getByRole("button", { name: "Saisir un mot de passe…" }));
  fireEvent.change(screen.getByLabelText(/Mot de passe/), { target: { value: text } });
  fireEvent.click(screen.getByRole("button", { name: "Continuer" }));
}

const flow = {
  "POST /sessions/session-1/secret-paste-step-up": { body: { challenge: "opaque", expires_in: 120, factors: ["totp"] } },
  "POST /sessions/session-1/secret-paste": { body: { pasteToken: TOKEN, expiresInSeconds: 60 } },
};

describe("an operator's password typed into a screen session (ADR-0133)", () => {
  it("asks the factor, then sends the password encrypted, never to the API", async () => {
    const { calls, send } = renderPaste(flow);
    typePassword(PASSWORD);
    fireEvent.change(await screen.findByLabelText(/Code/), { target: { value: "123456" } });
    fireEvent.click(screen.getByRole("button", { name: "Confirmer et saisir" }));
    await waitFor(() => expect(send).toHaveBeenCalledTimes(1));
    expect(calls.map((c) => c.path)).toEqual(["/sessions/session-1/secret-paste-step-up", "/sessions/session-1/secret-paste"]);
    expect(calls[0].body).toBeUndefined();
    expect(calls[1].body).toEqual({ challenge: "opaque", factor: "totp", totp_code: "123456" });
    expect(JSON.stringify(calls)).not.toContain(PASSWORD);
    const message: Uint8Array = send.mock.calls[0][0];
    expect([...message.slice(0, 2)]).toEqual([1, 6]);
    expect([...message.slice(4, 36)]).toEqual([...hexToBytes(TOKEN)]);
    expect(new TextDecoder("latin1").decode(message)).not.toContain(PASSWORD);
    expect(screen.queryByRole("dialog")).toBeNull();
    expect(screen.getByText(/envoyé chiffré au proxy/)).toBeTruthy();
  });

  it("refuses a text the proxy would refuse before asking for a factor", () => {
    const { calls, send } = renderPaste(flow);
    typePassword("tab\there");
    expect(screen.getByText(/sur une seule ligne/)).toBeTruthy();
    expect(calls).toHaveLength(0);
    expect(send).not.toHaveBeenCalled();
  });

  it("sends nothing when the Broker gives no token", async () => {
    const { send } = renderPaste({ ...flow, "POST /sessions/session-1/secret-paste": { status: 503, body: { error: "proxy unavailable" } } });
    typePassword(PASSWORD);
    fireEvent.change(await screen.findByLabelText(/Code/), { target: { value: "123456" } });
    fireEvent.click(screen.getByRole("button", { name: "Confirmer et saisir" }));
    expect(await screen.findByText(/n'a pas pu être autorisée/)).toBeTruthy();
    expect(send).not.toHaveBeenCalled();
  });

  it("sends nothing for a malformed token", async () => {
    const { send } = renderPaste({ ...flow, "POST /sessions/session-1/secret-paste": { body: { pasteToken: "short" } } });
    typePassword(PASSWORD);
    fireEvent.change(await screen.findByLabelText(/Code/), { target: { value: "123456" } });
    fireEvent.click(screen.getByRole("button", { name: "Confirmer et saisir" }));
    expect(await screen.findByText(/invalid paste token/)).toBeTruthy();
    expect(send).not.toHaveBeenCalled();
  });
});
