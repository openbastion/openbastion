import { FormEvent, useCallback, useEffect, useRef, useState } from "react";
import { ApiError, VideoRecordingSegment } from "../../shared/api";
import { Notice } from "../../shared/Notice";
import { useSignedIn } from "../../shared/session";

// The replay of a graphical session (ADR-0071, ADR-0088): the very PNG frames the Video Recorder
// acknowledged, in order, at the pace they were recorded. Segments are read as the replay goes,
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
  schedule: (run: () => void, delayMs: number) => () => void;
}

const browserDeps: ReplayDeps = {
  decode: (png) => createImageBitmap(new Blob([png], { type: "image/png" })),
  draw: (canvas, image) => {
    if (canvas.width !== image.width) canvas.width = image.width;
    if (canvas.height !== image.height) canvas.height = image.height;
    canvas.getContext("2d")?.drawImage(image, 0, 0);
  },
  schedule: (run, delayMs) => {
    const id = window.setTimeout(run, delayMs);
    return () => window.clearTimeout(id);
  },
};

interface Frame {
  sequence: number;
  at: Date;
  png: Uint8Array<ArrayBuffer>;
}

class UnreadableSegment extends Error {}

// A segment's frames, checked: base64, a PNG of at most 4 MiB, a date, and as many as it says.
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
    const png = new Uint8Array(binary.length);
    for (let j = 0; j < binary.length; j++) png[j] = binary.charCodeAt(j);
    const at = new Date(frame.timestamp);
    if (PNG_SIGNATURE.some((b, j) => png[j] !== b) || Number.isNaN(at.getTime())) throw new UnreadableSegment();
    return { sequence: segment.firstSequence + i, at, png };
  });
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
      loadedBytes.current += got.reduce((n, f) => n + f.png.length, 0);
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
    setIndex(0);
    setPlaying(false);
    setEnd("more");
    setError(undefined);
    setOpened(sessionId);
    await loadMore(sessionId, generation.current);
  }

  // The frame under the cursor, drawn once (a segment read ahead does not redraw it); an older
  // decode never paints over a newer one.
  const shown = frames[index];
  useEffect(() => {
    const frame = shown;
    if (!frame) return;
    let current = true;
    deps.decode(frame.png).then(
      (image) => {
        if (current && canvas.current) deps.draw(canvas.current, image);
        image.close();
      },
      () => {
        if (!current) return;
        setPlaying(false);
        setError(new Error("Une image enregistrée ne se décode pas : la relecture s'arrête là."));
      },
    );
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
