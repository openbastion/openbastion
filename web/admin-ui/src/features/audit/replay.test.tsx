import { describe, expect, it, vi } from "vitest";
import { act, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { ReactNode } from "react";
import { Api } from "../../shared/api";
import { SignedInContext } from "../../shared/session";
import { fakeApi } from "../../test-helpers";
import { ReplayDeps, VideoReplay } from "./VideoReplay";

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
  const pending: (() => void)[] = [];
  const delays: number[] = [];
  const replay: ReplayDeps = {
    decode: async (bytes) => ({ id: bytes[8], close: vi.fn() }) as unknown as ImageBitmap,
    draw: (_canvas, image) => drawn.push((image as unknown as { id: number }).id),
    schedule: (run, delayMs) => {
      pending.push(run);
      delays.push(delayMs);
      return () => {};
    },
  };
  return { replay, drawn, pending, delays };
}

async function open(api: Api, d: ReturnType<typeof deps>) {
  signedIn(api, <VideoReplay deps={d.replay} />);
  fireEvent.change(screen.getByLabelText("Session de l'écran"), { target: { value: "sess_r" } });
  fireEvent.submit(screen.getByRole("form", { name: "Relire l'écran d'une session" }));
}

describe("the replay of a screen recording", () => {
  it("shows the recorded frames in order, reads ahead, and says the recording was sealed", async () => {
    const { api, calls } = fakeApi({ [path(1)]: { body: segment(1, [11, 12], false) }, [path(3)]: { body: segment(3, [13], true) } });
    const d = deps();
    await open(api, d);
    await waitFor(() => expect(d.drawn).toEqual([11]));
    // Two frames loaded is within the read-ahead: the next segment comes, then the 404 that ends it.
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
