import { FormEvent, useCallback, useEffect, useRef, useState } from "react";
import { ApiError, VideoRecordingSegment } from "../../shared/api";
import { Notice } from "../../shared/Notice";
import { useSignedIn } from "../../shared/session";
import { DeltaRect, decodeScreenMessage } from "../screen/protocol";

// The replay of a graphical session (ADR-0071, ADR-0088): the very frames the Video Recorder
// acknowledged, in order, at the pace they were recorded. A key frame is a whole PNG; a partial frame
// (ADR-0092) changes rectangles of the frame before it, so a frame is shown by composing from the
// key frame at or before it. Segments are read as the replay goes,
// never all at once: each read is an audit event in the auditor's name, and a long session would
// not fit in a page. What does not parse is not shown: the replay stops and says so.

const PNG_SIGNATURE = [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a];
const MAX_FRAME_BYTES = 4 << 20;
// What a replay keeps in memory: past it, it reads no further, and says so.
const MAX_LOADED_BYTES = 256 << 20;
// The gap between two frames is the recording's, within these bounds: a quiet minute on the
// target is not a minute of a black screen to watch.
const MIN_DELAY_MS = 40;
const MAX_DELAY_MS = 2000;
const PREFETCH = 5;

export interface ReplayDeps {
  // Decodes without an <img>, as the live screen does: the page's policy allows no blob: image.
  decode: (png: Uint8Array<ArrayBuffer>) => Promise<ImageBitmap>;
  draw: (canvas: HTMLCanvasElement, image: ImageBitmap) => void;
  // Puts a rectangle of a partial frame in place, replacing the pixels under it (ADR-0092 §6).
  patch: (canvas: HTMLCanvasElement, image: ImageBitmap, x: number, y: number) => void;
  schedule: (run: () => void, delayMs: number) => () => void;
}

const browserDeps: ReplayDeps = {
  decode: (png) => createImageBitmap(new Blob([png], { type: "image/png" })),
  draw: (canvas, image) => {
    if (canvas.width !== image.width) canvas.width = image.width;
    if (canvas.height !== image.height) canvas.height = image.height;
    canvas.getContext("2d")?.drawImage(image, 0, 0);
  },
  patch: (canvas, image, x, y) => {
    const context = canvas.getContext("2d");
    context?.clearRect(x, y, image.width, image.height);
    context?.drawImage(image, x, y);
  },
  schedule: (run, delayMs) => {
    const id = window.setTimeout(run, delayMs);
    return () => window.clearTimeout(id);
  },
};

type Frame =
  | { kind: "key"; sequence: number; at: Date; bytes: number; png: Uint8Array<ArrayBuffer> }
  | { kind: "delta"; sequence: number; at: Date; bytes: number; width: number; height: number; rects: DeltaRect[] };

// The size a key frame's PNG says (IHDR), or null: a partial frame is checked against it.
function pngSize(png: Uint8Array): { width: number; height: number } | null {
  if (png.length < 24 || String.fromCharCode(...png.subarray(12, 16)) !== "IHDR") return null;
  const view = new DataView(png.buffer, png.byteOffset, png.byteLength);
  return { width: view.getUint32(16), height: view.getUint32(20) };
}

class UnreadableSegment extends Error {}

// A segment's frames, checked: base64, at most 4 MiB, a date, as many as it says, and each a PNG
// (codec png) or the partial frame of its own sequence (codec png-delta-v1).
function framesOf(segment: VideoRecordingSegment): Frame[] {
  if (!Number.isSafeInteger(segment.firstSequence) || !Number.isSafeInteger(segment.lastSequence) ||
      segment.firstSequence < 1 || segment.lastSequence - segment.firstSequence + 1 !== segment.frames.length) {
    throw new UnreadableSegment();
  }
  return segment.frames.map((frame, i) => {
    let binary: string;
    try {
      binary = atob(frame.frameData);
    } catch {
      throw new UnreadableSegment();
    }
    if (binary.length === 0 || binary.length > MAX_FRAME_BYTES) throw new UnreadableSegment();
    const data = new Uint8Array(binary.length);
    for (let j = 0; j < binary.length; j++) data[j] = binary.charCodeAt(j);
    const at = new Date(frame.timestamp);
    if (Number.isNaN(at.getTime())) throw new UnreadableSegment();
    const sequence = segment.firstSequence + i;
    if (frame.codec === "png-delta-v1") {
      let message;
      try {
        message = decodeScreenMessage(data.buffer);
      } catch {
        throw new UnreadableSegment();
      }
      if (message.type !== "delta" || message.sequence !== BigInt(sequence)) throw new UnreadableSegment();
      return { kind: "delta", sequence, at, bytes: data.length, width: message.width, height: message.height, rects: message.rects };
    }
    if (frame.codec !== "png" || PNG_SIGNATURE.some((b, j) => data[j] !== b)) throw new UnreadableSegment();
    return { kind: "key", sequence, at, bytes: data.length, png: data };
  });
}

// A key frame's size, from its PNG; what a partial frame after it must match.
function pngSizeOf(frame: Frame): { width: number; height: number } | null {
  return frame.kind === "key" ? pngSize(frame.png) : null;
}

type End = "more" | "sealed" | "interrupted" | "memory";

export function VideoReplay({ deps = browserDeps }: { deps?: ReplayDeps }) {
  const { api } = useSignedIn();
  const [sessionId, setSessionId] = useState("");
  const [opened, setOpened] = useState<string>();
  const [frames, setFrames] = useState<Frame[]>([]);
  const [index, setIndex] = useState(0);
  const [playing, setPlaying] = useState(false);
  const [speed, setSpeed] = useState(1);
  const [end, setEnd] = useState<End>("more");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<unknown>();
  const canvas = useRef<HTMLCanvasElement>(null);
  const next = useRef(1);
  const loadedBytes = useRef(0);
  const generation = useRef(0);
  // The index of the frame on the canvas, null for none: the next frame, a partial one, is put on
  // it directly; any other is composed again from its key frame.
  const painted = useRef<number | null>(null);
  const framesNow = useRef<Frame[]>([]);
  framesNow.current = frames;
  // Whether the last segment read says the recording was sealed (its terminal marker came).
  const lastComplete = useRef(false);

  // The next segment of the opened session; a 404 after the first means there is no more, and the
  // last segment read says whether the recording was sealed.
  const loadMore = useCallback(async (id: string, gen: number) => {
    setLoading(true);
    try {
      const segment = await api.request<VideoRecordingSegment>("GET", `/sessions/${encodeURIComponent(id)}/recording/video/segments/${next.current}`);
      if (gen !== generation.current) return;
      const got = framesOf(segment);
      if (got.length === 0 || segment.firstSequence !== next.current) throw new UnreadableSegment();
      next.current = segment.lastSequence + 1;
      loadedBytes.current += got.reduce((n, f) => n + f.bytes, 0);
      lastComplete.current = segment.complete;
      setFrames((had) => had.concat(got));
      if (loadedBytes.current > MAX_LOADED_BYTES) setEnd("memory");
    } catch (err) {
      if (gen !== generation.current) return;
      if (err instanceof ApiError && err.status === 404 && next.current > 1) {
        setEnd(lastComplete.current ? "sealed" : "interrupted");
      } else {
        setPlaying(false);
        setEnd("interrupted");
        setError(err instanceof UnreadableSegment ? new Error("Le segment reçu n'est pas valide : la relecture s'arrête là.") : err);
      }
    } finally {
      if (gen === generation.current) setLoading(false);
    }
  }, [api]);

  async function open(e: FormEvent) {
    e.preventDefault();
    generation.current += 1;
    next.current = 1;
    loadedBytes.current = 0;
    lastComplete.current = false;
    setFrames([]);
    painted.current = null;
    setIndex(0);
    setPlaying(false);
    setEnd("more");
    setError(undefined);
    setOpened(sessionId);
    await loadMore(sessionId, generation.current);
  }

  // The frame under the cursor, drawn once (a segment read ahead does not redraw it): from the
  // frame on the canvas when it is just before, otherwise from the key frame at or before it. A
  // newer position stops an older one between two frames: an older frame never paints over it.
  const shown = frames[index];
  useEffect(() => {
    if (!shown) return;
    let current = true;
    const target = framesNow.current.indexOf(shown);
    const paint = async () => {
      const all = framesNow.current;
      let key = target;
      while (key >= 0 && all[key].kind !== "key") key--;
      if (key < 0) throw new Error("a partial frame without a key frame before it");
      const from = painted.current;
      let start = key;
      if (from !== null && from >= key && from < target) start = from + 1;
      else if (from === target) return;
      let screenSize = pngSizeOf(all[key]);
      for (let i = start; i <= target; i++) {
        const frame = all[i];
        if (frame.kind === "key") {
          const image = await deps.decode(frame.png);
          if (!current || !canvas.current) {
            image.close();
            return;
          }
          deps.draw(canvas.current, image);
          image.close();
          screenSize = pngSizeOf(frame);
        } else {
          if (!screenSize || frame.width !== screenSize.width || frame.height !== screenSize.height) {
            throw new Error("a partial frame of another size than its screen");
          }
          const images = await Promise.all(frame.rects.map((rect) => deps.decode(rect.png)));
          try {
            if (images.some((image, j) => image.width !== frame.rects[j].width || image.height !== frame.rects[j].height)) {
              throw new Error("a rectangle of another size than announced");
            }
            if (!current || !canvas.current) return;
            frame.rects.forEach((rect, j) => deps.patch(canvas.current as HTMLCanvasElement, images[j], rect.x, rect.y));
          } finally {
            images.forEach((image) => image.close());
          }
        }
        painted.current = i;
      }
    };
    paint().catch(() => {
      if (!current) return;
      setPlaying(false);
      setError(new Error("Une image enregistrée ne se décode pas : la relecture s'arrête là."));
    });
    return () => {
      current = false;
    };
  }, [shown, deps]);

  // Reading ahead, a few frames before the end of what is loaded.
  useEffect(() => {
    if (opened && end === "more" && !loading && frames.length > 0 && index >= frames.length - PREFETCH) {
      void loadMore(opened, generation.current);
    }
  }, [opened, end, loading, frames.length, index, loadMore]);

  // Playing: the next frame after the recorded gap, scaled by the speed.
  useEffect(() => {
    if (!playing) return;
    if (index >= frames.length - 1) {
      if (end !== "more") setPlaying(false);
      return; // the next segment is on its way, or there is none
    }
    const gap = frames[index + 1].at.getTime() - frames[index].at.getTime();
    const delay = Math.min(MAX_DELAY_MS, Math.max(MIN_DELAY_MS, gap / speed));
    return deps.schedule(() => setIndex((i) => i + 1), delay);
  }, [playing, index, frames, speed, end, deps]);

  const frame = frames[index];
  const endText: Record<End, string> = {
    more: loading ? "Lecture du segment suivant…" : "",
    sealed: "Fin de l'enregistrement, scellé à la fin de la session.",
    interrupted: "Enregistrement interrompu : la session s'est arrêtée sans marqueur de fin.",
    memory: "Limite de mémoire de la relecture atteinte : la suite n'est pas chargée.",
  };

  return (
    <div className="card form-card">
      <form onSubmit={open} aria-label="Relire l'écran d'une session">
        <h3>Écran d'une session RDP ou VNC</h3>
        <p className="hint">Chaque segment relu est un événement d'audit à votre nom ; la suite n'est lue qu'au fil de la relecture.</p>
        <div className="fields">
          <label>Session de l'écran<input value={sessionId} onChange={(e) => setSessionId(e.target.value)} required /></label>
        </div>
        <div className="form-actions">
          <button type="submit" className="primary">Relire l'écran</button>
        </div>
      </form>
      <Notice error={error} />
      {frame ? (
        <div className="replay">
          <canvas ref={canvas} className="screen-canvas" role="img" aria-label="Image enregistrée de l'écran de la session, non lisible par un lecteur d'écran" />
          <div className="form-actions replay-controls">
            <button type="button" className="primary" onClick={() => setPlaying((p) => !p)}>{playing ? "Pause" : "Lire"}</button>
            <button type="button" disabled={index === 0} onClick={() => { setPlaying(false); setIndex((i) => i - 1); }}>Image précédente</button>
            <button type="button" disabled={index >= frames.length - 1} onClick={() => { setPlaying(false); setIndex((i) => i + 1); }}>Image suivante</button>
            <label>
              Position
              <input type="range" min={0} max={frames.length - 1} value={index} onChange={(e) => { setPlaying(false); setIndex(Number(e.target.value)); }} />
            </label>
            <label>
              Vitesse
              <select value={speed} onChange={(e) => setSpeed(Number(e.target.value))}>
                <option value={1}>×1</option>
                <option value={2}>×2</option>
                <option value={4}>×4</option>
              </select>
            </label>
          </div>
          <p className="hint" role="status">
            Image {frame.sequence} ({index + 1} sur {frames.length} chargées), enregistrée le <time dateTime={frame.at.toISOString()}>{frame.at.toLocaleString("fr-FR")}</time>. {endText[end]}
          </p>
        </div>
      ) : null}
    </div>
  );
}
