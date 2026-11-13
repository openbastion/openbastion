import { describe, expect, it, vi } from "vitest";
import { act, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { RESIZE_DEBOUNCE_MS, ScreenDeps, ScreenSocket, ScreenViewer, attachUrl } from "./ScreenViewer";
import { SUBPROTOCOL, clampResize, decodeScreenMessage, encodeClipboard, encodeKey, encodePointer, encodeReleaseAll, encodeResize, encodeScancode, endMessage } from "./protocol";
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
function hello(id = "s1", protocol: "rdp" | "vnc" = "vnc", pointerDrawn = false, resizable = false, clipTo = false, clipFrom = false): ArrayBuffer {
  const bytes = [...new TextEncoder().encode(id)];
  const p = new Uint8Array(14 + bytes.length);
  const v = new DataView(p.buffer);
  p[0] = protocol === "rdp" ? 1 : 2;
  p[1] = (pointerDrawn ? 1 : 0) | (resizable ? 2 : 0) | (clipTo ? 4 : 0) | (clipFrom ? 8 : 0);
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

function setup(attach = "/sessions/s1/screen", decodeResult?: () => Promise<ImageBitmap>, measure?: ScreenDeps["measure"], clipboard?: Pick<ScreenDeps, "readClipboard" | "writeClipboard">) {
  const socket = new FakeSocket();
  const urls: [string, string][] = [];
  const shown: { width: number; height: number }[] = [];
  // What reached the canvas, in order: whole frames and rectangles put in place.
  const painted: string[] = [];
  const closeImage = vi.fn();
  const deps: ScreenDeps = {
    open: (url, protocol) => {
      urls.push([url, protocol]);
      return socket;
    },
    // A fake PNG says its own size in its two bytes after the signature (rectPNG below).
    decode: decodeResult ?? (async (png) => ({ close: closeImage, width: png[8], height: png[9] }) as unknown as ImageBitmap),
    draw: (_canvas, _image, width, height) => {
      shown.push({ width, height });
      painted.push(`frame ${width}x${height}`);
    },
    patch: (_canvas, image, x, y) => painted.push(`rect ${x},${y} ${image.width}x${image.height}`),
    measure,
    ...clipboard,
  };
  const onReconnect = vi.fn();
  const onClose = vi.fn();
  const view = render(<ScreenViewer attach={attach} deps={deps} onReconnect={onReconnect} onClose={onClose} />);
  const canvas = view.container.querySelector("canvas") as HTMLCanvasElement;
  vi.spyOn(canvas, "getBoundingClientRect").mockReturnValue({ left: 10, top: 20, width: 200, height: 100, right: 210, bottom: 120, x: 10, y: 20, toJSON: () => ({}) });
  return { socket, urls, shown, painted, canvas, onReconnect, onClose, view };
}

// A partial frame (ADR-0092): its rectangles, each a fake PNG saying its size.
function rectPNG(width: number, height: number): number[] {
  return [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, width, height];
}
function delta(sequence: bigint, width: number, height: number, rects: { x: number; y: number; w: number; h: number; png?: number[] }[]): ArrayBuffer {
  const parts: number[] = [0, rects.length];
  for (const r of rects) {
    const png = r.png ?? rectPNG(r.w, r.h);
    const head = new Uint8Array(20);
    const v = new DataView(head.buffer);
    v.setUint32(0, r.x);
    v.setUint32(4, r.y);
    v.setUint32(8, r.w);
    v.setUint32(12, r.h);
    v.setUint32(16, png.length);
    parts.push(...head, ...png);
  }
  return header(4, sequence, width, height, parts);
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
      "hello reserved flag": tampered((b) => (b[33] = 0x10), hello()),
      "hello reserved flag beside the pointer": tampered((b) => (b[33] = 0x81), hello()),
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

describe("the pointer drawn into the frames (ADR-0091)", () => {
  it("reads the HELLO's flag", () => {
    expect(decodeScreenMessage(hello("s1", "rdp", true))).toMatchObject({ type: "hello", pointerDrawn: true });
    expect(decodeScreenMessage(hello("s1", "rdp", false))).toMatchObject({ type: "hello", pointerDrawn: false });
  });

  it("hides the browser's arrow only when the frames carry the pointer", async () => {
    for (const drawn of [true, false]) {
      const s = setup();
      s.socket.receive(hello("s1", "rdp", drawn));
      s.socket.receive(frame(1n));
      await waitFor(() => expect(s.shown.length).toBe(1));
      expect(s.canvas.classList.contains("pointer-drawn")).toBe(drawn);
      s.view.unmount();
    }
  });
});

describe("partial frames, live (ADR-0092)", () => {
  it("decodes them as strictly as the proxy encodes them", () => {
    expect(decodeScreenMessage(delta(2n, 8, 4, [{ x: 1, y: 2, w: 3, h: 2 }]))).toMatchObject({
      type: "delta", sequence: 2n, width: 8, height: 4, rects: [{ x: 1, y: 2, width: 3, height: 2 }],
    });
    const cases: Record<string, ArrayBuffer> = {
      "no rectangle": delta(2n, 8, 4, []),
      "past the right edge": delta(2n, 8, 4, [{ x: 7, y: 0, w: 2, h: 1 }]),
      "past the bottom edge": delta(2n, 8, 4, [{ x: 0, y: 3, w: 1, h: 2 }]),
      "an empty rectangle": delta(2n, 8, 4, [{ x: 0, y: 0, w: 0, h: 1 }]),
      "not a PNG": delta(2n, 8, 4, [{ x: 0, y: 0, w: 1, h: 1, png: [1, 2, 3, 4, 5, 6, 7, 8, 9] }]),
      "sequence zero": delta(0n, 8, 4, [{ x: 0, y: 0, w: 1, h: 1 }]),
      "a byte left over": (() => {
        const good = new Uint8Array(delta(2n, 8, 4, [{ x: 0, y: 0, w: 1, h: 1 }]));
        const out = new Uint8Array(good.length + 1);
        out.set(good);
        new DataView(out.buffer).setUint32(28, out.length - 32);
        return out.buffer;
      })(),
      "a count past the rectangles": (() => {
        const b = new Uint8Array(delta(2n, 8, 4, [{ x: 0, y: 0, w: 1, h: 1 }]).slice(0));
        b[33] = 2;
        return b.buffer;
      })(),
    };
    for (const [what, data] of Object.entries(cases)) {
      expect(() => decodeScreenMessage(data), what).toThrow();
    }
  });

  it("puts each rectangle in place, after the frame before it", async () => {
    const s = setup();
    s.socket.receive(hello("s1", "rdp", true));
    s.socket.receive(frame(1n, 8, 4));
    s.socket.receive(delta(2n, 8, 4, [{ x: 1, y: 2, w: 3, h: 2 }, { x: 7, y: 3, w: 1, h: 1 }]));
    s.socket.receive(delta(3n, 8, 4, [{ x: 0, y: 0, w: 2, h: 2 }]));
    await waitFor(() => expect(s.painted).toEqual(["frame 8x4", "rect 1,2 3x2", "rect 7,3 1x1", "rect 0,0 2x2"]));
    expect(s.socket.closed).toBe(false);
    s.view.unmount();
  });

  it("waits for the frame before it to be painted, however long it decodes", async () => {
    const resolvers: (() => void)[] = [];
    const s = setup("/sessions/s1/screen", async () => {
      await new Promise<void>((resolve) => resolvers.push(resolve));
      return { close: vi.fn(), width: 1, height: 1 } as unknown as ImageBitmap;
    });
    s.socket.receive(hello());
    s.socket.receive(frame(1n, 8, 4));
    s.socket.receive(delta(2n, 8, 4, [{ x: 0, y: 0, w: 1, h: 1 }]));
    await waitFor(() => expect(resolvers.length).toBe(1)); // the rectangle waits for the key frame
    await act(async () => resolvers[0]());
    await waitFor(() => expect(resolvers.length).toBe(2));
    await act(async () => resolvers[1]());
    await waitFor(() => expect(s.painted).toEqual(["frame 8x4", "rect 0,0 1x1"]));
    s.view.unmount();
  });

  it.each([
    ["a partial frame before any key frame", [delta(1n, 8, 4, [{ x: 0, y: 0, w: 1, h: 1 }])]],
    ["a partial frame after a gap", [frame(1n, 8, 4), delta(3n, 8, 4, [{ x: 0, y: 0, w: 1, h: 1 }])]],
    ["a partial frame of another size", [frame(1n, 8, 4), delta(2n, 16, 4, [{ x: 0, y: 0, w: 1, h: 1 }])]],
    ["a rectangle whose PNG is not of its size", [frame(1n, 8, 4), delta(2n, 8, 4, [{ x: 0, y: 0, w: 2, h: 2, png: rectPNG(1, 1) }])]],
  ])("closes on %s", async (_what, messages) => {
    const s = setup();
    s.socket.receive(hello());
    for (const m of messages) s.socket.receive(m);
    await waitFor(() => expect(s.socket.closed).toBe(true));
    expect(s.painted.filter((p) => p.startsWith("rect"))).toEqual([]);
    s.view.unmount();
  });

  it("goes on at a key frame that comes after a gap", async () => {
    const s = setup();
    s.socket.receive(hello());
    s.socket.receive(frame(1n, 8, 4));
    s.socket.receive(frame(9n, 8, 4)); // the proxy dropped what a slow page could not take
    s.socket.receive(delta(10n, 8, 4, [{ x: 0, y: 0, w: 1, h: 1 }]));
    await waitFor(() => expect(s.painted).toEqual(["frame 8x4", "rect 0,0 1x1"]));
    expect(s.socket.closed).toBe(false);
    s.view.unmount();
  });
});

// A clipboard text (ADR-0096): a direction, three reserved bytes, then UTF-8.
function clipboard(sequence: bigint, direction: number, text: string, reserved = 0): ArrayBuffer {
  return header(5, sequence, 0, 0, [direction, reserved, 0, 0, ...new TextEncoder().encode(text)]);
}

describe("clipboard texts, live (ADR-0096)", () => {
  it("decodes them as strictly as the proxy encodes them", () => {
    expect(decodeScreenMessage(clipboard(3n, 2, "copied é €"))).toEqual({ type: "clipboard", sequence: 3n, direction: "from-target", text: "copied é €" });
    expect(decodeScreenMessage(clipboard(3n, 1, ""))).toEqual({ type: "clipboard", sequence: 3n, direction: "to-target", text: "" });
    expect(decodeScreenMessage(clipboard(1n, 1, "x".repeat(32763)))).toMatchObject({ type: "clipboard" });
    for (const bad of [
      clipboard(0n, 1, "no sequence"),
      clipboard(1n, 0, "no direction"),
      clipboard(1n, 3, "an unknown direction"),
      clipboard(1n, 1, "a reserved byte", 1),
      clipboard(1n, 1, "a\u0000NUL"),
      clipboard(1n, 1, "x".repeat(32764)),
      header(5, 1n, 1, 1, [1, 0, 0, 0]),
      header(5, 1n, 0, 0, [1, 0, 0]),
      header(5, 1n, 0, 0, [1, 0, 0, 0, 0xff]),
    ]) {
      expect(() => decodeScreenMessage(bad)).toThrow();
    }
  });

  it("takes its place in the sequence, and a partial frame after it applies to the screen before it", async () => {
    const s = setup();
    s.socket.receive(hello("s1", "rdp"));
    s.socket.receive(frame(1n, 8, 4));
    s.socket.receive(clipboard(2n, 2, "copied"));
    s.socket.receive(delta(3n, 8, 4, [{ x: 0, y: 0, w: 1, h: 1 }]));
    await waitFor(() => expect(s.painted).toEqual(["frame 8x4", "rect 0,0 1x1"]));
    expect(s.socket.closed).toBe(false);
    s.view.unmount();
  });

  it("closes on a clipboard text out of the sequence", async () => {
    const s = setup();
    s.socket.receive(hello("s1", "rdp"));
    s.socket.receive(frame(2n, 8, 4));
    s.socket.receive(clipboard(2n, 2, "replayed"));
    await waitFor(() => expect(s.socket.closed).toBe(true));
    s.view.unmount();
  });
});

describe("the clipboard panel (ADR-0096 §6)", () => {
  it("writes the message pkg/screenstream decodes, and nothing the contract does not carry", () => {
    const bytes = encodeClipboard("pasted é €") as Uint8Array;
    const utf8 = new TextEncoder().encode("pasted é €");
    expect([...bytes.subarray(0, 8)]).toEqual([1, 5, 0, 0, 0, 0, 0, utf8.length]);
    expect([...bytes.subarray(8)]).toEqual([...utf8]);
    expect(encodeClipboard("a\u0000b")).toBeNull();
    expect(encodeClipboard("x".repeat(32764))).toBeNull();
    expect(encodeClipboard("\uD800 alone")).toBeNull();
    expect(encodeClipboard("\u{1F600}")).not.toBeNull();
  });

  it("offers nothing the HELLO does not allow", async () => {
    const s = setup();
    s.socket.receive(hello("s1", "rdp"));
    s.socket.receive(frame(1n));
    await waitFor(() => expect(s.shown.length).toBe(1));
    expect(screen.queryByRole("region", { name: "Presse-papiers" })).toBeNull();
    s.view.unmount();
  });

  it("reads the operator's clipboard only on their click, shows it, and sends it only when they confirm", async () => {
    const read = vi.fn(async () => "pasted é");
    const s = setup("/sessions/s1/screen", undefined, undefined, { readClipboard: read });
    s.socket.receive(hello("s1", "rdp", false, false, true, false));
    s.socket.receive(frame(1n));
    await waitFor(() => expect(s.shown.length).toBe(1));
    expect(read).not.toHaveBeenCalled();
    expect(screen.queryByText("Copier le texte de la cible")).toBeNull();
    const before = s.socket.sent.length;
    fireEvent.click(screen.getByText("Coller vers la cible…"));
    const field = (await screen.findByLabelText("Texte à coller dans la cible")) as HTMLTextAreaElement;
    expect(field.value).toBe("pasted é");
    expect(s.socket.sent.length).toBe(before); // shown, not sent
    fireEvent.change(field, { target: { value: "pasted, edited" } });
    fireEvent.click(screen.getByText("Envoyer"));
    const sent = s.socket.sent[s.socket.sent.length - 1];
    expect([...sent]).toEqual([...(encodeClipboard("pasted, edited") as Uint8Array)]);
    // The proxy shows it back once recorded: it takes its place in the sequence.
    s.socket.receive(clipboard(2n, 1, "pasted, edited"));
    expect(await screen.findByText("Collé dans la cible")).toBeTruthy();
    s.view.unmount();
  });

  it("leaves a field to paste into when the browser will not give its clipboard, and sends nothing on cancel", async () => {
    const s = setup("/sessions/s1/screen", undefined, undefined, { readClipboard: async () => { throw new Error("denied"); } });
    s.socket.receive(hello("s1", "rdp", false, false, true, false));
    s.socket.receive(frame(1n));
    await waitFor(() => expect(s.shown.length).toBe(1));
    const before = s.socket.sent.length;
    fireEvent.click(screen.getByText("Coller vers la cible…"));
    expect(((await screen.findByLabelText("Texte à coller dans la cible")) as HTMLTextAreaElement).value).toBe("");
    expect(screen.getByText(/n'a pas donné le presse-papiers/)).toBeTruthy();
    fireEvent.click(screen.getByText("Annuler"));
    expect(screen.queryByLabelText("Texte à coller dans la cible")).toBeNull();
    expect(s.socket.sent.length).toBe(before);
    s.view.unmount();
  });

  it("refuses to send a text past the bound, and says why", async () => {
    const s = setup("/sessions/s1/screen", undefined, undefined, { readClipboard: async () => "x".repeat(32764) });
    s.socket.receive(hello("s1", "rdp", false, false, true, false));
    s.socket.receive(frame(1n));
    await waitFor(() => expect(s.shown.length).toBe(1));
    const before = s.socket.sent.length;
    fireEvent.click(screen.getByText("Coller vers la cible…"));
    await screen.findByLabelText("Texte à coller dans la cible");
    fireEvent.click(screen.getByText("Envoyer"));
    expect(await screen.findByText(/ne peut pas être envoyé/)).toBeTruthy();
    expect(s.socket.sent.length).toBe(before);
    s.view.unmount();
  });

  it("writes what the target copied to the operator's clipboard on their click, and only then", async () => {
    const write = vi.fn(async () => {});
    const s = setup("/sessions/s1/screen", undefined, undefined, { writeClipboard: write });
    s.socket.receive(hello("s1", "rdp", false, false, false, true));
    s.socket.receive(frame(1n));
    await waitFor(() => expect(s.shown.length).toBe(1));
    expect(screen.queryByText("Coller vers la cible…")).toBeNull();
    s.socket.receive(clipboard(2n, 2, "copied <b>on</b> the target"));
    expect(await screen.findByText("copied <b>on</b> the target")).toBeTruthy(); // as text, never markup
    expect(write).not.toHaveBeenCalled();
    fireEvent.click(screen.getByText("Copier le texte de la cible"));
    await waitFor(() => expect(write).toHaveBeenCalledWith("copied <b>on</b> the target"));
    expect(await screen.findByText("Texte copié dans votre presse-papiers.")).toBeTruthy();
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

  it("never paints an older frame once a newer key frame has come", async () => {
    const resolvers: ((b: ImageBitmap) => void)[] = [];
    const s = setup("/sessions/s1/screen", () => new Promise((resolve) => resolvers.push(resolve)));
    s.socket.receive(hello());
    s.socket.receive(frame(1n, 11, 11));
    s.socket.receive(frame(2n, 22, 22));
    const close = vi.fn();
    await waitFor(() => expect(resolvers.length).toBe(1)); // frame 1 is not even decoded
    await act(async () => resolvers[0]({ close } as unknown as ImageBitmap));
    expect(s.shown).toEqual([{ width: 22, height: 22 }]);
    expect(close).toHaveBeenCalledTimes(1);
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

// The resize of ADR-0095: the HELLO's bit 1, the input of type 4, and the page asking a resizable
// session for the size of its screen area.
describe("the resize", () => {
  it("reads the HELLO's resize flag, beside the pointer's", () => {
    expect(decodeScreenMessage(hello("s1", "rdp", false, true))).toMatchObject({ type: "hello", resizable: true, pointerDrawn: false });
    expect(decodeScreenMessage(hello("s1", "rdp", true, true))).toMatchObject({ type: "hello", resizable: true, pointerDrawn: true });
    expect(decodeScreenMessage(hello("s1", "rdp", true, false))).toMatchObject({ type: "hello", resizable: false });
  });

  it("encodes a size as an input of type 4, within the bounds and even", () => {
    const sent = encodeResize(1921, 1081);
    const view = new DataView(sent.buffer);
    expect([sent[0], sent[1], view.getUint16(10), view.getUint16(12)]).toEqual([1, 4, 1920, 1081]);
    expect([...sent.slice(2, 10), ...sent.slice(14)]).toEqual(new Array(10).fill(0));
    expect(clampResize(100, 100)).toEqual({ width: 640, height: 480 });
    expect(clampResize(9000, 9000)).toEqual({ width: 2560, height: 1600 });
    expect(clampResize(1023.7, 768.9)).toEqual({ width: 1022, height: 768 });
  });

  function resizes(sent: Uint8Array<ArrayBuffer>[]): string[] {
    return sent.filter((m) => m[1] === 4).map((m) => {
      const v = new DataView(m.buffer);
      return `${v.getUint16(10)}x${v.getUint16(12)}`;
    });
  }

  it("asks a resizable session for the room the page has, and again when it changes", async () => {
    let room = { width: 1200, height: 700 };
    const s = setup("/sessions/s1/screen", undefined, () => room);
    s.socket.receive(hello("s1", "rdp", false, true));
    // Waits with room: real timers, which a loaded machine stretches (one unexplained failure, 13 Nov.).
    await waitFor(() => expect(resizes(s.socket.sent)).toEqual(["1200x700"]), { timeout: 5000 });
    // A window that stops changing: one more resize, after the pause; the same size again, none.
    room = { width: 1001, height: 650 };
    act(() => {
      window.dispatchEvent(new Event("resize"));
      window.dispatchEvent(new Event("resize"));
    });
    expect(resizes(s.socket.sent)).toEqual(["1200x700"]);
    await waitFor(() => expect(resizes(s.socket.sent)).toEqual(["1200x700", "1000x650"]), { timeout: 5000 });
    room = { width: 1000, height: 650 };
    act(() => {
      window.dispatchEvent(new Event("resize"));
    });
    await new Promise((resolve) => setTimeout(resolve, RESIZE_DEBOUNCE_MS * 2));
    expect(resizes(s.socket.sent)).toEqual(["1200x700", "1000x650"]);
  });

  it("asks a session that does not resize for nothing", async () => {
    const s = setup("/sessions/s1/screen", undefined, () => ({ width: 1200, height: 700 }));
    s.socket.receive(hello("s1", "rdp", false, false));
    act(() => {
      window.dispatchEvent(new Event("resize"));
    });
    await new Promise((resolve) => setTimeout(resolve, RESIZE_DEBOUNCE_MS * 2));
    expect(resizes(s.socket.sent)).toEqual([]);
  });
});
