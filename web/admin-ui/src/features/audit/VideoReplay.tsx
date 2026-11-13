import { FormEvent, useCallback, useEffect, useRef, useState } from "react";
import { ApiError, VideoRecordingSegment } from "../../shared/api";
import { useSignedIn } from "../../shared/session";
import { FormCard } from "../../shared/ui/FormCard";
import { Frame, framesOf, paintFrame, ReplayPainter, UnreadableSegment } from "./replayFrames";
import { ReplayControls } from "./ReplayControls";

// The replay of a graphical session (ADR-0071, ADR-0088, ADR-0092): the very frames the Video
// Recorder acknowledged, in order, at the pace they were recorded. Segments are read as the replay
// goes, never all at once: each read is an audit event in the auditor's name, and a long session
// would not fit in a page. What does not parse is not shown: the replay stops and says so.

// What a replay keeps in memory: past it, it reads no further, and says so.
const MAX_LOADED_BYTES = 256 << 20;
// The gap between two frames is the recording's, within these bounds: a quiet minute on the
// target is not a minute of a black screen to watch.
const MIN_DELAY_MS = 40;
const MAX_DELAY_MS = 2000;
const PREFETCH = 5;

export type ReplayDeps = ReplayPainter & {
  schedule: (run: () => void, delayMs: number) => () => void;
};

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

type End = "more" | "sealed" | "interrupted" | "memory";

const endText: Record<End, string> = {
  more: "",
  sealed: "Fin de l'enregistrement, scellé à la fin de la session.",
  interrupted: "Enregistrement interrompu : la session s'est arrêtée sans marqueur de fin.",
  memory: "Limite de mémoire de la relecture atteinte : la suite n'est pas chargée.",
};

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

  // The frame under the cursor, drawn once (a segment read ahead does not redraw it).
  const shown = frames[index];
  useEffect(() => {
    const target = shown ? framesNow.current.indexOf(shown) : -1;
    const surface = canvas.current;
    if (target < 0 || !surface) return;
    let current = true;
    paintFrame({
      frames: framesNow.current,
      target,
      from: painted.current,
      canvas: surface,
      painter: deps,
      stopped: () => !current,
    }).then(
      (last) => {
        if (last !== null && canvas.current === surface) painted.current = last;
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
  // The clipboard texts up to the position (ADR-0096): the auditor reads what crossed, at its time,
  // beside the screen as it was.
  const transfers = frames.slice(0, index + 1).filter((f) => f.kind === "clipboard").slice(-3).reverse();

  return (
    <>
      <FormCard
        label="Relire l'écran d'une session"
        title="Écran d'une session RDP ou VNC"
        hint="Chaque segment relu est un événement d'audit à votre nom ; la suite n'est lue qu'au fil de la relecture."
        submitLabel="Relire l'écran"
        onSubmit={open}
        error={error}
      >
        <label>
          Session de l'écran
          <input value={sessionId} onChange={(e) => setSessionId(e.target.value)} required />
        </label>
      </FormCard>
      {loading && !frame ? <p className="ob-empty-state" role="status">Chargement des images enregistrées…</p> : null}
      {frame ? (
        <section className="ob-surface ob-panel video-replay-card" aria-label="Relecture vidéo de la session">
          <canvas ref={canvas} className="screen-canvas" role="img" aria-label="Image enregistrée de l'écran de la session, non lisible par un lecteur d'écran" />
          {transfers.length > 0 ? (
            <section className="screen-clipboard" aria-label="Presse-papiers enregistré">
              <ul className="screen-clipboard-history">
                {transfers.map((t) => t.kind === "clipboard" ? (
                  <li key={t.sequence} aria-current={t === frame ? "true" : undefined}>
                    <span>{t.direction === "to-target" ? "Collé dans la cible" : "Copié depuis la cible"}, à {t.at.toLocaleTimeString("fr-FR")}</span>
                    <pre>{t.text}</pre>
                  </li>
                ) : null)}
              </ul>
            </section>
          ) : null}
          <ReplayControls
            playing={playing}
            position={index}
            speed={speed}
            loaded={frames.length}
            sequence={frame.sequence}
            at={frame.at}
            endText={end === "more" && loading ? "Lecture du segment suivant…" : endText[end]}
            onPlay={() => setPlaying((p) => !p)}
            onStep={(delta) => {
              setPlaying(false);
              setIndex((i) => i + delta);
            }}
            onSeek={(position) => {
              setPlaying(false);
              setIndex(position);
            }}
            onSpeed={setSpeed}
          />
        </section>
      ) : null}
    </>
  );
}
