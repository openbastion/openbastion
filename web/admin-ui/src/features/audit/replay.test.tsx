import { describe, expect, it, vi } from "vitest";
import { act, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { ReactNode } from "react";
import { Api } from "../../shared/api";
import { SignedInContext } from "../../shared/session";
import { fakeApi } from "../../test-helpers";
import { ReplayDeps, VideoReplay } from "./VideoReplay";
import { Recording } from "./Recording";

const signedIn = (api: Api, node: ReactNode) => render(<SignedInContext.Provider value={{ api, who: null, signOut: () => {} }}>{node}</SignedInContext.Provider>);

// A PNG as the recorder stores it: the signature, then a byte saying which frame it is.
const png = (n: number) => btoa(String.fromCharCode(0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, n));
const at = (seconds: number) => new Date(Date.UTC(2026, 10, 9, 10, 0, seconds)).toISOString();
const segment = (first: number, ids: number[], complete: boolean, times = ids.map((_, i) => first + i)) => ({
  sessionId: "sess_r", firstSequence: first, lastSequence: first + ids.length - 1, complete,
  frames: ids.map((id, i) => ({ timestamp: at(times[i]), frameData: png(id), codec: "png" })),
});
const path = (first: number) => `GET /sessions/sess_r/recording/video/segments/${first}`;

function deps() {
  const drawn: number[] = [];
  const patched: string[] = [];
  const pending: (() => void)[] = [];
  const delays: number[] = [];
  const replay: ReplayDeps = {
    decode: async (bytes) => ({ id: bytes[8], close: vi.fn() }) as unknown as ImageBitmap,
    draw: (_canvas, image) => drawn.push((image as unknown as { id: number }).id),
    patch: (_canvas, image, x, y) => patched.push(`${x},${y} ${image.width}x${image.height}`),
    schedule: (run, delayMs) => {
      pending.push(run);
      delays.push(delayMs);
      return () => {};
    },
  };
  return { replay, drawn, patched, pending, delays };
}

async function open(api: Api, d: ReturnType<typeof deps>) {
  signedIn(api, <VideoReplay deps={d.replay} />);
  fireEvent.change(screen.getByLabelText("Session de l'écran"), { target: { value: "sess_r" } });
  fireEvent.submit(screen.getByRole("form", { name: "Relire l'écran d'une session" }));
}

describe("recorded terminal commands", () => {
  it("renders the command stream in the shared surface without interpreting it", async () => {
    const { api } = fakeApi({
      "GET /sessions/sess_r/recording?page=1&pageSize=100": {
        body: {
          sessionId: "sess_r",
          page: 1,
          pageSize: 100,
          totalEntries: 1,
          entries: [{ timestamp: at(0), command: "whoami" }],
        },
      },
    });
    signedIn(api, <Recording />);
    fireEvent.change(screen.getByLabelText("Session"), { target: { value: "sess_r" } });
    fireEvent.submit(screen.getByRole("form", { name: "Relire un enregistrement" }));
    expect(await screen.findByText("whoami")).toBeTruthy();
    expect((await screen.findByRole("region", { name: /Commandes de la session/ })).className).toContain("ob-surface");
  });
});

describe("the replay of a screen recording", () => {
  it("shows the recorded frames in order, reads ahead, and says the recording was sealed", async () => {
    const { api, calls } = fakeApi({ [path(1)]: { body: segment(1, [11, 12], false) }, [path(3)]: { body: segment(3, [13], true) } });
    const d = deps();
    await open(api, d);
    await waitFor(() => expect(d.drawn).toEqual([11]));
    // Two frames loaded is within the read-ahead: the next segment comes, then the 404 that ends it.
    expect((await screen.findByRole("region", { name: "Relecture vidéo de la session" })).className).toContain("ob-surface");
    expect(await screen.findByText(/Fin de l'enregistrement, scellé/)).toBeTruthy();
    expect(screen.getByRole("status").textContent).toContain("1 sur 3 chargées");
    fireEvent.click(screen.getByText("Image suivante"));
    await waitFor(() => expect(d.drawn).toEqual([11, 12]));
    fireEvent.click(screen.getByText("Image suivante"));
    await waitFor(() => expect(d.drawn).toEqual([11, 12, 13]));
    expect(calls.map((c) => c.path)).toEqual(["/sessions/sess_r/recording/video/segments/1", "/sessions/sess_r/recording/video/segments/3", "/sessions/sess_r/recording/video/segments/4"]);
  });

  it("plays at the recorded pace, bounded, and faster when asked", async () => {
    const { api } = fakeApi({ [path(1)]: { body: segment(1, [1, 2, 3], true, [0, 1, 600]) } });
    const d = deps();
    await open(api, d);
    await screen.findByText(/scellé/);
    fireEvent.change(screen.getByLabelText("Vitesse"), { target: { value: "2" } });
    fireEvent.click(screen.getByText("Lire"));
    await waitFor(() => expect(d.pending.length).toBe(1));
    act(() => d.pending[0]());
    await waitFor(() => expect(d.pending.length).toBe(2));
    act(() => d.pending[1]());
    await waitFor(() => expect(d.drawn).toEqual([1, 2, 3]));
    // One second at ×2 is half a second; ten minutes of a still screen are two seconds at most.
    expect(d.delays).toEqual([500, 2000]);
    expect(await screen.findByText("Lire")).toBeTruthy(); // stopped at the end
  });

  it("never paints an older frame over a newer one that decoded first", async () => {
    const { api } = fakeApi({ [path(1)]: { body: segment(1, [1, 2], true) } });
    const d = deps();
    const slow: ((image: ImageBitmap) => void)[] = [];
    d.replay.decode = (bytes) => {
      const image = { id: bytes[8], close: vi.fn() } as unknown as ImageBitmap;
      return bytes[8] === 1 ? new Promise((resolve) => slow.push(resolve)) : Promise.resolve(image);
    };
    await open(api, d);
    await screen.findByText(/scellé/);
    fireEvent.click(screen.getByText("Image suivante"));
    await waitFor(() => expect(d.drawn).toEqual([2]));
    await act(async () => slow[0]({ id: 1, close: vi.fn() } as unknown as ImageBitmap));
    expect(d.drawn).toEqual([2]);
  });

  it("says an interrupted recording is interrupted", async () => {
    const { api } = fakeApi({ [path(1)]: { body: segment(1, [1], false) } });
    await open(api, deps());
    expect(await screen.findByText(/Enregistrement interrompu/)).toBeTruthy();
  });

  it("shows the refusal of the API, and no frame", async () => {
    const { api } = fakeApi({ [path(1)]: { status: 403, body: { message: "forbidden: recording:session:read" } } });
    const d = deps();
    await open(api, d);
    expect((await screen.findByRole("alert")).textContent).toContain("forbidden");
    expect(d.drawn).toEqual([]);
    expect(screen.queryByText("Lire")).toBeNull();
  });

  it("shows nothing of a segment that is not what it says", async () => {
    const notPNG = { ...segment(1, [1], true), frames: [{ timestamp: at(0), frameData: btoa("GIF89a"), codec: "png" }] };
    const short = { ...segment(1, [1, 2], true), lastSequence: 5 };
    for (const body of [notPNG, short]) {
      const { api } = fakeApi({ [path(1)]: { body } });
      const d = deps();
      const view = signedIn(api, <VideoReplay deps={d.replay} />);
      fireEvent.change(view.getByLabelText("Session de l'écran"), { target: { value: "sess_r" } });
      fireEvent.submit(view.getByRole("form", { name: "Relire l'écran d'une session" }));
      expect((await view.findByRole("alert")).textContent).toContain("n'est pas valide");
      expect(d.drawn).toEqual([]);
      view.unmount();
    }
  });
});

// A key frame whose PNG says its size (IHDR) and, at byte 24, which frame it is.
function keyPNG(id: number, width: number, height: number): number[] {
  const out = new Uint8Array(25);
  out.set([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0, 0, 0, 13, 0x49, 0x48, 0x44, 0x52]);
  const view = new DataView(out.buffer);
  view.setUint32(16, width);
  view.setUint32(20, height);
  out[24] = id;
  return [...out];
}
// A rectangle's fake PNG: the signature, then its width and height.
const rectPNG = (w: number, h: number) => [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, w, h];
// A partial frame as the recorder stores it: the screen-stream FRAME_DELTA message.
function deltaMessage(sequence: number, width: number, height: number, rects: { x: number; y: number; w: number; h: number; png?: number[] }[]): number[] {
  const payload: number[] = [0, rects.length];
  for (const r of rects) {
    const png = r.png ?? rectPNG(r.w, r.h);
    const head = new DataView(new ArrayBuffer(20));
    head.setUint32(0, r.x);
    head.setUint32(4, r.y);
    head.setUint32(8, r.w);
    head.setUint32(12, r.h);
    head.setUint32(16, png.length);
    payload.push(...new Uint8Array(head.buffer), ...png);
  }
  const out = new Uint8Array(32 + payload.length);
  const view = new DataView(out.buffer);
  out[0] = 1;
  out[1] = 4;
  view.setBigUint64(4, BigInt(sequence));
  view.setBigInt64(12, 1_000_000_000n);
  view.setUint32(20, width);
  view.setUint32(24, height);
  view.setUint32(28, payload.length);
  out.set(payload, 32);
  return [...out];
}
const b64 = (bytes: number[]) => btoa(String.fromCharCode(...bytes));
type Recorded = { codec: "png"; bytes: number[] } | { codec: "png-delta-v1"; bytes: number[] } | { codec: "clipboard-text-v1"; bytes: number[] };
// A clipboard text as the recorder stores it (ADR-0096): the screen-stream CLIPBOARD message.
function clipboardMessage(sequence: number, direction: number, text: string): number[] {
  const payload = [direction, 0, 0, 0, ...new TextEncoder().encode(text)];
  const out = new Uint8Array(32 + payload.length);
  const view = new DataView(out.buffer);
  out[0] = 1;
  out[1] = 5;
  view.setBigUint64(4, BigInt(sequence));
  view.setBigInt64(12, 1_000_000_000n);
  view.setUint32(28, payload.length);
  out.set(payload, 32);
  return [...out];
}
const mixed = (first: number, frames: Recorded[], complete = true) => ({
  sessionId: "sess_r", firstSequence: first, lastSequence: first + frames.length - 1, complete,
  frames: frames.map((f, i) => ({ timestamp: at(first + i), frameData: b64(f.bytes), codec: f.codec })),
});

function partialDeps() {
  const d = deps();
  d.replay.decode = async (bytes) =>
    (bytes.length >= 25 ? { id: bytes[24], close: vi.fn() } : { width: bytes[8], height: bytes[9], close: vi.fn() }) as unknown as ImageBitmap;
  return d;
}

describe("the replay of clipboard texts (ADR-0096)", () => {
  const recording = mixed(1, [
    { codec: "png", bytes: keyPNG(1, 8, 4) },
    { codec: "clipboard-text-v1", bytes: clipboardMessage(2, 2, "copied é") },
    { codec: "png-delta-v1", bytes: deltaMessage(3, 8, 4, [{ x: 1, y: 2, w: 3, h: 2 }]) },
  ]);

  it("steps over a text, the screen as it was, and the partial frame after it on that screen", async () => {
    const { api } = fakeApi({ [path(1)]: { body: recording } });
    const d = partialDeps();
    await open(api, d);
    await screen.findByText(/scellé/);
    await waitFor(() => expect(d.drawn).toEqual([1]));
    fireEvent.click(screen.getByText("Image suivante"));
    fireEvent.click(screen.getByText("Image suivante"));
    await waitFor(() => expect(d.patched).toEqual(["1,2 3x2"]));
    expect(d.drawn).toEqual([1]);
    expect(screen.queryByRole("alert")).toBeNull();
  });

  it("shows the auditor what crossed, from its position on, as text", async () => {
    const { api } = fakeApi({ [path(1)]: { body: recording } });
    const d = partialDeps();
    await open(api, d);
    await screen.findByText(/scellé/);
    expect(screen.queryByRole("region", { name: "Presse-papiers enregistré" })).toBeNull(); // not yet at its time
    fireEvent.click(screen.getByText("Image suivante"));
    const region = await screen.findByRole("region", { name: "Presse-papiers enregistré" });
    expect(region.textContent).toContain("Copié depuis la cible");
    expect(region.textContent).toContain("copied é");
  });

  it.each([
    ["a clipboard text of another sequence", mixed(1, [{ codec: "png", bytes: keyPNG(1, 8, 4) }, { codec: "clipboard-text-v1", bytes: clipboardMessage(3, 2, "x") }])],
    ["a key frame under the clipboard codec", mixed(1, [{ codec: "png", bytes: keyPNG(1, 8, 4) }, { codec: "clipboard-text-v1", bytes: keyPNG(2, 8, 4) }])],
    ["a clipboard text under the partial codec", mixed(1, [{ codec: "png", bytes: keyPNG(1, 8, 4) }, { codec: "png-delta-v1", bytes: clipboardMessage(2, 2, "x") }])],
  ])("shows nothing of a segment with %s", async (_what, body) => {
    const { api } = fakeApi({ [path(1)]: { body } });
    const d = partialDeps();
    await open(api, d);
    expect((await screen.findByRole("alert")).textContent).toContain("n'est pas valide");
    expect(d.drawn).toEqual([]);
  });
});

describe("the replay of partial frames (ADR-0092)", () => {
  const recording = mixed(1, [
    { codec: "png", bytes: keyPNG(1, 8, 4) },
    { codec: "png-delta-v1", bytes: deltaMessage(2, 8, 4, [{ x: 1, y: 2, w: 3, h: 2 }]) },
    { codec: "png-delta-v1", bytes: deltaMessage(3, 8, 4, [{ x: 0, y: 0, w: 2, h: 2 }, { x: 7, y: 3, w: 1, h: 1 }]) },
    { codec: "png", bytes: keyPNG(4, 8, 4) },
    { codec: "png-delta-v1", bytes: deltaMessage(5, 8, 4, [{ x: 5, y: 1, w: 1, h: 1 }]) },
  ]);

  it("steps from frame to frame, putting only the next rectangles in place", async () => {
    const { api } = fakeApi({ [path(1)]: { body: recording } });
    const d = partialDeps();
    await open(api, d);
    await screen.findByText(/scellé/);
    await waitFor(() => expect(d.drawn).toEqual([1]));
    fireEvent.click(screen.getByText("Image suivante"));
    await waitFor(() => expect(d.patched).toEqual(["1,2 3x2"]));
    fireEvent.click(screen.getByText("Image suivante"));
    await waitFor(() => expect(d.patched).toEqual(["1,2 3x2", "0,0 2x2", "7,3 1x1"]));
    expect(d.drawn).toEqual([1]); // never composed again from the key frame
  });

  it("composes a frame reached out of order from its key frame", async () => {
    const { api } = fakeApi({ [path(1)]: { body: recording } });
    const d = partialDeps();
    await open(api, d);
    await screen.findByText(/scellé/);
    await waitFor(() => expect(d.drawn).toEqual([1]));
    // Straight to frame 3: frames 2 and 3 on the key frame on the canvas.
    fireEvent.change(screen.getByLabelText("Position"), { target: { value: "2" } });
    await waitFor(() => expect(d.patched).toEqual(["1,2 3x2", "0,0 2x2", "7,3 1x1"]));
    // Back to frame 2: from its key frame again, then its own rectangle.
    fireEvent.change(screen.getByLabelText("Position"), { target: { value: "1" } });
    await waitFor(() => expect(d.drawn).toEqual([1, 1]));
    await waitFor(() => expect(d.patched.slice(3)).toEqual(["1,2 3x2"]));
    // To frame 5: its own key frame, 4, then its rectangle.
    fireEvent.change(screen.getByLabelText("Position"), { target: { value: "4" } });
    await waitFor(() => expect(d.drawn).toEqual([1, 1, 4]));
    await waitFor(() => expect(d.patched.slice(4)).toEqual(["5,1 1x1"]));
  });

  it.each([
    ["a partial frame of another sequence", mixed(1, [{ codec: "png", bytes: keyPNG(1, 8, 4) }, { codec: "png-delta-v1", bytes: deltaMessage(3, 8, 4, [{ x: 0, y: 0, w: 1, h: 1 }]) }])],
    ["a key frame under the partial codec", mixed(1, [{ codec: "png", bytes: keyPNG(1, 8, 4) }, { codec: "png-delta-v1", bytes: keyPNG(2, 8, 4) }])],
    ["an unknown codec", mixed(1, [{ codec: "png", bytes: keyPNG(1, 8, 4) }, { codec: "png-delta-v9" as "png-delta-v1", bytes: deltaMessage(2, 8, 4, [{ x: 0, y: 0, w: 1, h: 1 }]) }])],
    ["an unknown codec around a PNG", mixed(1, [{ codec: "png", bytes: keyPNG(1, 8, 4) }, { codec: "jpeg" as "png", bytes: keyPNG(2, 8, 4) }])],
  ])("shows nothing of a segment with %s", async (_what, body) => {
    const { api } = fakeApi({ [path(1)]: { body } });
    const d = partialDeps();
    await open(api, d);
    expect((await screen.findByRole("alert")).textContent).toContain("n'est pas valide");
    expect(d.drawn).toEqual([]);
  });

  it.each([
    ["a partial frame of another size than its screen", mixed(1, [{ codec: "png", bytes: keyPNG(1, 8, 4) }, { codec: "png-delta-v1", bytes: deltaMessage(2, 16, 4, [{ x: 0, y: 0, w: 1, h: 1 }]) }])],
    ["a rectangle whose PNG is not of its size", mixed(1, [{ codec: "png", bytes: keyPNG(1, 8, 4) }, { codec: "png-delta-v1", bytes: deltaMessage(2, 8, 4, [{ x: 0, y: 0, w: 2, h: 2, png: rectPNG(1, 1) }]) }])],
  ])("stops at %s", async (_what, body) => {
    const { api } = fakeApi({ [path(1)]: { body } });
    const d = partialDeps();
    await open(api, d);
    await screen.findByText(/scellé/);
    fireEvent.click(screen.getByText("Image suivante"));
    expect((await screen.findByRole("alert")).textContent).toContain("ne se décode pas");
    expect(d.patched).toEqual([]);
  });

  it("refuses a recording that starts with a partial frame", async () => {
    const { api } = fakeApi({ [path(1)]: { body: mixed(1, [{ codec: "png-delta-v1", bytes: deltaMessage(1, 8, 4, [{ x: 0, y: 0, w: 1, h: 1 }]) }]) } });
    const d = partialDeps();
    await open(api, d);
    expect((await screen.findByRole("alert")).textContent).toContain("ne se décode pas");
    expect(d.patched).toEqual([]);
  });
});
