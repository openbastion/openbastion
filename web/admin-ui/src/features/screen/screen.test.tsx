import { describe, expect, it, vi } from "vitest";
import { act, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { ScreenDeps, ScreenSocket, ScreenViewer, attachUrl } from "./ScreenViewer";
import { SUBPROTOCOL, decodeScreenMessage, encodeKey, encodePointer, encodeReleaseAll, encodeScancode, endMessage } from "./protocol";
import { keysymOf, rfbButtons, scancodeOf } from "./keys";

const PNG = [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 1, 2, 3];

function header(type: number, sequence: bigint, width: number, height: number, payload: ArrayLike<number>): ArrayBuffer {
  const out = new Uint8Array(32 + payload.length);
  const view = new DataView(out.buffer);
  out[0] = 1;
  out[1] = type;
  view.setBigUint64(4, sequence);
  view.setBigInt64(12, 1_000_000_000n);
  view.setUint32(20, width);
  view.setUint32(24, height);
  view.setUint32(28, payload.length);
  out.set(payload, 32);
  return out.buffer;
}
function oversizedFrame(): ArrayBuffer {
  const payload = new Uint8Array((4 << 20) + 1);
  payload.set(PNG);
  return header(1, 1n, 1, 1, payload);
}
const frame = (sequence: bigint, width = 100, height = 50) => header(1, sequence, width, height, PNG);
function hello(id = "s1", protocol: "rdp" | "vnc" = "vnc"): ArrayBuffer {
  const bytes = [...new TextEncoder().encode(id)];
  const p = new Uint8Array(14 + bytes.length);
  const v = new DataView(p.buffer);
  p[0] = protocol === "rdp" ? 1 : 2;
  v.setBigUint64(2, 1893456000n);
  v.setUint32(10, bytes.length);
  p.set(bytes, 14);
  return header(2, 0n, 0, 0, [...p]);
}
function end(text: string, sequence = 2n): ArrayBuffer {
  const bytes = [...new TextEncoder().encode(text)];
  const p = new Uint8Array(4 + bytes.length);
  new DataView(p.buffer).setUint16(2, bytes.length);
  p.set(bytes, 4);
  return header(3, sequence, 0, 0, [...p]);
}

class FakeSocket implements ScreenSocket {
  sent: Uint8Array<ArrayBuffer>[] = [];
  readyState: WebSocket["readyState"] = 1;
  closed = false;
  binaryType: BinaryType = "blob";
  onopen: ScreenSocket["onopen"] = null;
  onmessage: ScreenSocket["onmessage"] = null;
  onclose: ScreenSocket["onclose"] = null;
  onerror: ScreenSocket["onerror"] = null;
  send(data: string | ArrayBufferLike | Blob | ArrayBufferView) {
    this.sent.push(data as Uint8Array<ArrayBuffer>);
  }
  close() {
    this.closed = true;
    this.readyState = 3;
  }
  receive(data: ArrayBuffer) {
    act(() => this.onmessage?.call(this as unknown as WebSocket, { data } as MessageEvent));
  }
}

function setup(attach = "/sessions/s1/screen", decodeResult?: () => Promise<ImageBitmap>) {
  const socket = new FakeSocket();
  const urls: [string, string][] = [];
  const shown: { width: number; height: number }[] = [];
  const closeImage = vi.fn();
  const deps: ScreenDeps = {
    open: (url, protocol) => {
      urls.push([url, protocol]);
      return socket;
    },
    decode: decodeResult ?? (async () => ({ close: closeImage }) as unknown as ImageBitmap),
    draw: (_canvas, _image, width, height) => shown.push({ width, height }),
  };
  const onReconnect = vi.fn();
  const onClose = vi.fn();
  const view = render(<ScreenViewer attach={attach} deps={deps} onReconnect={onReconnect} onClose={onClose} />);
  const canvas = view.container.querySelector("canvas") as HTMLCanvasElement;
  vi.spyOn(canvas, "getBoundingClientRect").mockReturnValue({ left: 10, top: 20, width: 200, height: 100, right: 210, bottom: 120, x: 10, y: 20, toJSON: () => ({}) });
  return { socket, urls, shown, canvas, onReconnect, onClose, view };
}

async function live(s: ReturnType<typeof setup>, protocol: "rdp" | "vnc" = "vnc") {
  s.socket.receive(hello("s1", protocol));
  s.socket.receive(frame(1n));
  await waitFor(() => expect(s.shown.length).toBe(1));
}

describe("the screen contract (ADR-0071 §6)", () => {
  it("reads the three messages the proxy sends", () => {
    expect(decodeScreenMessage(hello("sess-1"))).toMatchObject({ type: "hello", protocol: "vnc", sessionId: "sess-1", expiresAt: new Date(1893456000000) });
    expect(decodeScreenMessage(frame(7n))).toMatchObject({ type: "frame", sequence: 7n, width: 100, height: 50 });
    expect(decodeScreenMessage(end("session_revoked", 9n))).toMatchObject({ type: "end", sequence: 9n, text: "session_revoked" });
  });

  it("refuses what is not exactly that", () => {
    const tampered = (edit: (b: Uint8Array) => void, source = frame(1n)) => {
      const copy = new Uint8Array(source.slice(0));
      edit(copy);
      return copy.buffer;
    };
    const cases: Record<string, ArrayBuffer> = {
      "too short": new ArrayBuffer(31),
      "unknown version": tampered((b) => (b[0] = 2)),
      flags: tampered((b) => (b[3] = 1)),
      "unknown type": tampered((b) => (b[1] = 9)),
      "length too large": tampered((b) => (b[31] = 200)),
      "not a PNG": header(1, 1n, 1, 1, [1, 2, 3, 4, 5, 6, 7, 8]),
      "no pixels": frame(1n, 0, 0),
      "too many pixels": frame(1n, 16_777_217, 1),
      "frame sequence zero": frame(0n),
      "PNG over 4 MiB": oversizedFrame(),
      "hello with a frame size": tampered((b) => (b[23] = 1), hello()),
      "hello unknown protocol": tampered((b) => (b[32] = 3), hello()),
      "end sequence zero": end("x", 0n),
      "end text not UTF-8": header(3, 1n, 0, 0, [0, 0, 0, 2, 0xc3, 0x28]),
    };
    for (const [what, data] of Object.entries(cases)) {
      expect(() => decodeScreenMessage(data), what).toThrow();
    }
  });

  it("writes the 16 bytes pkg/screenstream decodes", () => {
    expect([...encodeKey(0x61, true)]).toEqual([1, 1, 1, 0, 0, 0, 0, 0x61, 0, 0, 0, 0, 0, 0, 0, 0]);
    expect([...encodeKey(0x61, false)]).toEqual([1, 1, 0, 0, 0, 0, 0, 0x61, 0, 0, 0, 0, 0, 0, 0, 0]);
    expect([...encodePointer(258, 3, 5, -1)]).toEqual([1, 2, 0, 0, 0, 0, 0, 0, 0, 0, 1, 2, 0, 3, 5, 255]);
    expect([...encodeReleaseAll()]).toEqual([1, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
  });

  it("says every code of ADR-0071 §12 in words, and nothing it does not know", () => {
    for (const code of ["session_ended", "pin_missing", "pin_mismatch", "tls_required", "nla_required", "protocol_version_unsupported", "codec_unsupported", "recording_unavailable", "recording_lost", "ticket_invalid", "input_invalid", "session_expired", "session_revoked", "target_unreachable"]) {
      expect(endMessage(code), code).not.toContain(code);
      expect(endMessage(code), code).not.toBe(endMessage("<script>"));
    }
    expect(endMessage("<script>")).toBe("La session s'est arrêtée.");
  });

  it("maps keys and buttons", () => {
    expect(keysymOf("a")).toBe(0x61);
    expect(keysymOf("é")).toBe(0xe9);
    expect(keysymOf("€")).toBe(0x010020ac);
    expect(keysymOf("Enter")).toBe(0xff0d);
    expect(keysymOf("F12")).toBe(0xffc9);
    expect(keysymOf("Shift")).toBe(0xffe1);
    for (const notAKey of ["Dead", "Unidentified", "Process", "\u0007", "\u007f", "\u0085"]) expect(keysymOf(notAKey), notAKey).toBeNull();
    expect(rfbButtons(1)).toBe(1); // left
    expect(rfbButtons(2)).toBe(4); // right
    expect(rfbButtons(4)).toBe(2); // middle
  });
});

describe("where the socket goes (ADR-0071 §7)", () => {
  const here = { protocol: "https:", host: "bastion.test", origin: "https://bastion.test" };
  it("is this origin, and the attach path, with nothing in the URL", () => {
    expect(attachUrl("/sessions/s1/screen", here)).toBe("wss://bastion.test/sessions/s1/screen");
    expect(attachUrl("/sessions/s1/screen", { ...here, protocol: "http:", origin: "http://bastion.test" })).toBe("ws://bastion.test/sessions/s1/screen");
  });
  it("is never anywhere else, whatever the answer says", () => {
    for (const bad of ["https://evil.test/sessions/s1/screen", "//evil.test/sessions/s1/screen", "/auth/login", "/sessions/s1/screen?ticket=x", "http://[bad"]) {
      expect(attachUrl(bad, here), bad).toBeNull();
    }
  });
  it("opens nothing for a path of another origin", () => {
    const s = setup("https://evil.test/sessions/s1/screen");
    expect(s.urls).toEqual([]);
    expect(screen.getByRole("alert").textContent).toContain("n'est pas valide");
    s.view.unmount();
  });
  it("asks for the versioned subprotocol, in binary", () => {
    const s = setup();
    expect(s.urls[0][0].endsWith("/sessions/s1/screen")).toBe(true);
    expect(s.urls[0][1]).toBe(SUBPROTOCOL);
    expect(s.socket.binaryType).toBe("arraybuffer");
    s.view.unmount();
  });
});

describe("the screen", () => {
  it("waits, then shows the frame, sized as the proxy says", async () => {
    const s = setup();
    expect(screen.getByRole("status").textContent).toContain("Connexion à la cible");
    s.socket.receive(hello());
    expect(screen.getByRole("status").textContent).toContain("première image");
    expect(s.canvas.hidden).toBe(true);
    s.socket.receive(frame(1n, 640, 480));
    await waitFor(() => expect(s.shown).toEqual([{ width: 640, height: 480 }]));
    await waitFor(() => expect(s.canvas.hidden).toBe(false));
    expect(screen.getByRole("status").textContent).toContain("Session enregistrée");
    s.view.unmount();
  });

  it("accepts gaps in the sequence, which is what a slow page gets", async () => {
    const s = setup();
    await live(s);
    s.socket.receive(frame(5n));
    await waitFor(() => expect(s.shown.length).toBe(2));
    expect(s.socket.closed).toBe(false);
    s.view.unmount();
  });

  it("never paints an older frame over a newer one that decoded first", async () => {
    const resolvers: ((b: ImageBitmap) => void)[] = [];
    const s = setup("/sessions/s1/screen", () => new Promise((resolve) => resolvers.push(resolve)));
    s.socket.receive(hello());
    s.socket.receive(frame(1n, 11, 11));
    s.socket.receive(frame(2n, 22, 22));
    const close = vi.fn();
    await act(async () => resolvers[1]({ close } as unknown as ImageBitmap));
    await act(async () => resolvers[0]({ close } as unknown as ImageBitmap));
    expect(s.shown).toEqual([{ width: 22, height: 22 }]);
    expect(close).toHaveBeenCalledTimes(2);
    s.view.unmount();
  });

  it.each([
    ["a frame that repeats a sequence", () => frame(1n)],
    ["a frame that goes back", () => frame(0n)],
    ["garbage", () => new ArrayBuffer(8)],
  ])("closes on %s, and shows no more", async (_what, bad) => {
    const s = setup();
    await live(s);
    s.socket.receive(bad());
    expect(s.socket.closed).toBe(true);
    expect(screen.getByRole("alert").textContent).toContain("n'est pas valide");
    s.socket.receive(frame(9n));
    await act(async () => undefined);
    expect(s.shown.length).toBe(1);
    s.view.unmount();
  });

  it("closes when the browser cannot decode a frame", async () => {
    const s = setup("/sessions/s1/screen", () => Promise.reject(new Error("bad image")));
    s.socket.receive(frame(1n));
    expect((await screen.findByRole("alert")).textContent).toContain("n'est pas valide");
    expect(s.socket.closed).toBe(true);
    s.view.unmount();
  });

  it("says why it ended in words, as text, and offers a new connection", async () => {
    const s = setup();
    await live(s);
    s.socket.receive(end("session_revoked"));
    expect(screen.getByRole("alert").textContent).toBe("La session a été révoquée.");
    expect(s.socket.closed).toBe(true);
    fireEvent.click(screen.getByText("Se reconnecter"));
    expect(s.onReconnect).toHaveBeenCalledOnce();
    s.view.unmount();
  });

  it("says when the connection goes away without an END, and does not reconnect by itself", async () => {
    const s = setup();
    await live(s);
    act(() => s.socket.onclose?.call(s.socket as unknown as WebSocket, {} as CloseEvent));
    expect(screen.getByRole("alert").textContent).toContain("perdue");
    expect(s.onReconnect).not.toHaveBeenCalled();
    expect(s.urls.length).toBe(1);
    s.view.unmount();
  });

  it("lets go of everything on the way out", async () => {
    const s = setup();
    await live(s);
    s.view.unmount();
    expect(s.socket.closed).toBe(true);
    expect([...s.socket.sent.at(-1)!]).toEqual([...encodeReleaseAll()]);
  });
});

describe("what the operator sends to an RDP session (ADR-0088)", () => {
  it("writes the scancode where pkg/screenstream reads it, and no keysym", () => {
    expect([...encodeScancode(0xe048, true)]).toEqual([1, 1, 1, 0, 0, 0, 0, 0, 0xe0, 0x48, 0, 0, 0, 0, 0, 0]);
    expect([...encodeScancode(0x1e, false)]).toEqual([1, 1, 0, 0, 0, 0, 0, 0, 0, 0x1e, 0, 0, 0, 0, 0, 0]);
  });

  it("maps the physical key, whatever character the browser's layout gives", () => {
    expect(scancodeOf("KeyA")).toBe(0x1e);
    expect(scancodeOf("KeyQ")).toBe(0x10);
    expect(scancodeOf("ArrowUp")).toBe(0xe048);
    expect(scancodeOf("AltRight")).toBe(0xe038);
    expect(scancodeOf("Pause")).toBeNull();
    expect(scancodeOf("toString")).toBeNull();
  });

  it("sends the scancode of the key pressed, and releases what it pressed", async () => {
    const s = setup();
    await live(s, "rdp");
    // An AZERTY browser: the key that gives "a" is KeyQ, and RDP is sent KeyQ.
    fireEvent.keyDown(s.canvas, { key: "a", code: "KeyQ" });
    fireEvent.keyUp(s.canvas, { key: "a", code: "KeyQ" });
    fireEvent.keyDown(s.canvas, { key: "Pause", code: "Pause" });
    expect(s.socket.sent.map((m) => [...m])).toEqual([[...encodeScancode(0x10, true)], [...encodeScancode(0x10, false)]]);
    s.view.unmount();
  });

  // The browser keeps Ctrl+Alt+Del for itself: a button sends it, to an RDP session only.
  it("sends Ctrl+Alt+Del from its button, pressed then released in order", async () => {
    const s = setup();
    await live(s, "rdp");
    fireEvent.click(screen.getByText("Ctrl+Alt+Suppr"));
    expect(s.socket.sent.map((m) => [...m])).toEqual([
      [...encodeScancode(0x1d, true)], [...encodeScancode(0x38, true)], [...encodeScancode(0xe053, true)],
      [...encodeScancode(0xe053, false)], [...encodeScancode(0x38, false)], [...encodeScancode(0x1d, false)],
    ]);
    s.view.unmount();
  });

  it("offers no Ctrl+Alt+Del to a VNC session, nor before the session is live", async () => {
    const s = setup();
    expect(screen.queryByText("Ctrl+Alt+Suppr")).toBeNull();
    await live(s, "vnc");
    expect(screen.queryByText("Ctrl+Alt+Suppr")).toBeNull();
    s.view.unmount();
  });

  it("sends no key before the proxy has said which protocol it is", () => {
    const s = setup();
    fireEvent.keyDown(s.canvas, { key: "a", code: "KeyA" });
    expect(s.socket.sent.length).toBe(0);
    s.view.unmount();
  });
});

describe("what the operator sends", () => {
  it("sends a key down and up, and its release names what its press named", async () => {
    const s = setup();
    await live(s);
    fireEvent.keyDown(s.canvas, { key: "A", code: "KeyA" });
    fireEvent.keyUp(s.canvas, { key: "a", code: "KeyA" }); // Shift went up first
    expect(s.socket.sent.map((m) => [...m])).toEqual([[...encodeKey(0x41, true)], [...encodeKey(0x41, false)]]);
    s.view.unmount();
  });

  it("repeats a held key as the keysym it was pressed as, even if Shift has changed meanwhile", async () => {
    const s = setup();
    await live(s);
    fireEvent.keyDown(s.canvas, { key: "A", code: "KeyA" });
    fireEvent.keyDown(s.canvas, { key: "a", code: "KeyA", repeat: true });
    fireEvent.keyUp(s.canvas, { key: "a", code: "KeyA" });
    expect(s.socket.sent.map((m) => [...m])).toEqual([[...encodeKey(0x41, true)], [...encodeKey(0x41, true)], [...encodeKey(0x41, false)]]);
    s.view.unmount();
  });

  it("keeps a key the browser would act on, and does not send what is not a key", async () => {
    const s = setup();
    await live(s);
    expect(fireEvent.keyDown(s.canvas, { key: "Tab", code: "Tab" })).toBe(false); // default prevented
    expect(s.socket.sent.length).toBe(1);
    fireEvent.keyDown(s.canvas, { key: "Dead", code: "BracketLeft" });
    fireEvent.keyUp(s.canvas, { key: "Dead", code: "BracketLeft" });
    expect(s.socket.sent.length).toBe(1);
    s.view.unmount();
  });

  it("releases everything when the screen loses the focus (ADR-0071 §6)", async () => {
    const s = setup();
    await live(s);
    fireEvent.keyDown(s.canvas, { key: "Control", code: "ControlLeft" });
    fireEvent.blur(s.canvas);
    expect([...s.socket.sent.at(-1)!]).toEqual([...encodeReleaseAll()]);
    // The key is forgotten: the release that may follow says nothing to the target.
    const count = s.socket.sent.length;
    fireEvent.keyUp(s.canvas, { key: "Control", code: "ControlLeft" });
    expect(s.socket.sent.length).toBe(count);
    s.view.unmount();
  });

  it("sends the click at frame coordinates, whatever the scale of the page", async () => {
    const s = setup();
    await live(s);
    // The 100x50 frame shows at 200x100, from (10,20): page (110,70) is its middle.
    fireEvent.pointerDown(s.canvas, { clientX: 110, clientY: 70, buttons: 1 });
    fireEvent.pointerUp(s.canvas, { clientX: 110, clientY: 70, buttons: 0 });
    expect(s.socket.sent.map((m) => [...m])).toEqual([[...encodePointer(50, 25, 1)], [...encodePointer(50, 25, 0)]]);
    s.view.unmount();
  });

  it("never sends a coordinate outside the frame, which would close the session", async () => {
    const s = setup();
    await live(s);
    fireEvent.pointerDown(s.canvas, { clientX: 210, clientY: 120, buttons: 1 }); // the far corner
    fireEvent.pointerUp(s.canvas, { clientX: 9999, clientY: -9999, buttons: 0 });
    expect(s.socket.sent.map((m) => [...m])).toEqual([[...encodePointer(99, 49, 1)], [...encodePointer(99, 0, 0)]]);
    s.view.unmount();
  });

  it("sends no pointer before the first frame: there are no coordinates yet", () => {
    const s = setup();
    s.socket.receive(hello());
    fireEvent.pointerDown(s.canvas, { clientX: 10, clientY: 10, buttons: 1 });
    fireEvent.pointerMove(s.canvas, { clientX: 10, clientY: 10 });
    fireEvent.wheel(s.canvas, { clientX: 10, clientY: 10, deltaY: 1 });
    expect(s.socket.sent).toEqual([]);
    s.view.unmount();
  });

  it("coalesces moves to the latest, once per animation frame", async () => {
    const frames: FrameRequestCallback[] = [];
    vi.stubGlobal("requestAnimationFrame", (cb: FrameRequestCallback) => frames.push(cb));
    const s = setup();
    await live(s);
    fireEvent.pointerMove(s.canvas, { clientX: 20, clientY: 30 });
    fireEvent.pointerMove(s.canvas, { clientX: 30, clientY: 40 });
    expect(s.socket.sent).toEqual([]);
    expect(frames.length).toBe(1);
    frames[0](0);
    expect(s.socket.sent.map((m) => [...m])).toEqual([[...encodePointer(10, 10, 0)]]);
    s.view.unmount();
    vi.unstubAllGlobals();
  });

  it("sends one wheel notch at a time", async () => {
    const s = setup();
    await live(s);
    fireEvent.wheel(s.canvas, { clientX: 110, clientY: 70, deltaY: -240 });
    fireEvent.wheel(s.canvas, { clientX: 110, clientY: 70, deltaY: 240 });
    expect(s.socket.sent.map((m) => [...m])).toEqual([[...encodePointer(50, 25, 0, 1)], [...encodePointer(50, 25, 0, -1)]]);
    s.view.unmount();
  });

  it("sends nothing once the session has ended", async () => {
    const s = setup();
    await live(s);
    s.socket.receive(end("session_ended"));
    fireEvent.keyDown(s.canvas, { key: "a", code: "KeyA" });
    expect(s.socket.sent).toEqual([]);
    s.view.unmount();
  });
});
