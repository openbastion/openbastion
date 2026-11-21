import { FormEvent, useCallback, useEffect, useRef, useState } from "react";
import { ApiError, VideoRecordingEvent, VideoRecordingEventPage, VideoRecordingSegment } from "../../shared/api";
import { useSignedIn } from "../../shared/session";
import { FormField, Input } from "@openbastion/ui";
import { FormCard } from "../../shared/ui/FormCard";
import { Frame, framesOf, paintFrame, ReplayPainter, UnreadableSegment } from "./replayFrames";
import { ReplayControls } from "./ReplayControls";
import { useAppTranslation } from "../../shared/i18n";

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
const EVENT_PAGE_SIZE = 100;
const MAX_EVENT_PAGES = 10;

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

function endTextFor(end: End, translate: (key: string) => string): string {
  return end === "more" ? "" : translate(`replay.end.${end}`);
}

export function VideoReplay({ deps = browserDeps }: { deps?: ReplayDeps }) {
  const { t, i18n } = useAppTranslation();
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
  const [events, setEvents] = useState<VideoRecordingEvent[]>([]);
  const [eventsState, setEventsState] = useState<"idle" | "loading" | "ready" | "unavailable" | "truncated">("idle");
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
        setError(err instanceof UnreadableSegment ? new Error(t("replay.errors.segment")) : err);
      }
    } finally {
      if (gen === generation.current) setLoading(false);
    }
  }, [api, t]);

  // Events are a separate, metadata-only timeline (ADR-0111), not frame sequence
  // entries. Read bounded pages and stop after a fixed ceiling for very long sessions.
  const loadEvents = useCallback(async (id: string, gen: number) => {
    setEventsState("loading");
    const collected: VideoRecordingEvent[] = [];
    const seenCursors = new Set<string>();
    let cursor = "";
    try {
      for (let page = 0; page < MAX_EVENT_PAGES; page++) {
        const query = new URLSearchParams({ limit: String(EVENT_PAGE_SIZE) });
        if (cursor) query.set("cursor", cursor);
        const result = await api.request<VideoRecordingEventPage>("GET", `/sessions/${encodeURIComponent(id)}/recording/video/events?${query.toString()}`);
        if (gen !== generation.current) return;
        if (!result || !Array.isArray(result.events) || result.events.length > EVENT_PAGE_SIZE ||
            (result.nextCursor !== undefined && (typeof result.nextCursor !== "string" || result.nextCursor.length > 1024 || !/^[A-Za-z0-9_-]+$/.test(result.nextCursor)))) {
          throw new Error("invalid video event page");
        }
        for (const event of result.events) {
          const at = typeof event?.occurredAt === "string" ? Date.parse(event.occurredAt) : NaN;
          if (!event || event.sessionId !== id || typeof event.eventId !== "string" || !event.eventId ||
              !validMarkerKind(event) || (event.protocol !== "vnc" && event.protocol !== "rdp") ||
              typeof event.accountId !== "string" || !event.accountId || !Number.isFinite(at)) {
            throw new Error("invalid video event");
          }
          collected.push(event);
        }
        if (!result.nextCursor) {
          setEvents(collected);
          setEventsState("ready");
          return;
        }
        if (seenCursors.has(result.nextCursor)) throw new Error("repeated video event cursor");
        seenCursors.add(result.nextCursor);
        cursor = result.nextCursor;
      }
      setEvents(collected);
      setEventsState("truncated");
    } catch {
      if (gen !== generation.current) return;
      setEvents([]);
      setEventsState("unavailable");
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
    setEvents([]);
    setEventsState("idle");
    setOpened(sessionId);
    const gen = generation.current;
    void loadEvents(sessionId, gen);
    await loadMore(sessionId, gen);
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
        setError(new Error(t("replay.errors.frame")));
      },
    );
    return () => {
      current = false;
    };
  }, [shown, deps, t]);

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
  let currentEventId: string | undefined;
  if (frame) {
    for (const event of events) {
      if (Date.parse(event.occurredAt) <= frame.at.getTime()) currentEventId = event.eventId;
      else break;
    }
  }
  // The clipboard texts up to the position (ADR-0096): the auditor reads what crossed, at its time,
  // beside the screen as it was.
  const transfers = frames.slice(0, index + 1).filter((f) => f.kind === "clipboard").slice(-3).reverse();

  return (
    <>
      <FormCard
        label={t("replay.form.label")}
        title={t("replay.form.title")}
        hint={t("replay.form.hint")}
        submitLabel={t("replay.form.submit")}
        onSubmit={open}
        error={error}
      >
        <FormField id="replay-session" label={t("replay.form.session")} required>
          <Input value={sessionId} onChange={(e) => setSessionId(e.target.value)} />
        </FormField>
      </FormCard>
      {loading && !frame ? <p className="ob-empty-state" role="status">{t("replay.loading")}</p> : null}
      {frame ? (
        <section className="ob-surface ob-panel video-replay-card" aria-label={t("replay.cardAria")}>
          <canvas ref={canvas} className="screen-canvas" role="img" aria-label={t("replay.canvasAria")} />
          {transfers.length > 0 ? (
            <section className="screen-clipboard" aria-label={t("replay.clipboardAria")}>
              <ul className="screen-clipboard-history">
                {transfers.map((transfer) => transfer.kind === "clipboard" ? (
                  <li key={transfer.sequence} aria-current={transfer === frame ? "true" : undefined}>
                    <span>
                      {transfer.direction === "to-target" ? t("screen.pastedToTarget") : t("screen.copiedFromTarget")}
                      {", "}
                      {t("replay.at", { time: transfer.at.toLocaleTimeString(i18n.language) })}
                    </span>
                    <pre>{transfer.text}</pre>
                  </li>
                ) : null)}
              </ul>
            </section>
          ) : null}
          {opened ? (
            <section className="screen-events" aria-label={t("replay.events.aria")}>
              <h3>{t("replay.events.title")}</h3>
              {eventsState === "loading" ? <p>{t("replay.events.loading")}</p> : null}
              {eventsState === "unavailable" ? <p role="note">{t("replay.events.unavailable")}</p> : null}
              {eventsState === "ready" && events.length === 0 ? <p>{t("replay.events.empty")}</p> : null}
              {eventsState === "truncated" ? <p role="note">{t("replay.events.truncated")}</p> : null}
              {events.length > 0 ? (
                <ol className="screen-events-list">
                  {events.map((event) => (
                    <li key={event.eventId} aria-current={event.eventId === currentEventId ? "time" : undefined}>
                      <span>{event.source === "operator"
                        ? t("replay.events.secretPasteRequested", { bytes: event.pasteBytes, sha256: event.pasteSha256, salt: event.pasteSalt })
                        : t("replay.events.secretInjectionRequested")}</span>
                      <span>{event.accountId} · {event.protocol.toUpperCase()} · {t("replay.at", { time: new Date(event.occurredAt).toLocaleTimeString(i18n.language) })}</span>
                    </li>
                  ))}
                </ol>
              ) : null}
              {events.length > 0 ? <p className="screen-events-note">{t("replay.events.note")}</p> : null}
            </section>
          ) : null}
          <ReplayControls
            playing={playing}
            position={index}
            speed={speed}
            loaded={frames.length}
            sequence={frame.sequence}
            at={frame.at}
            endText={end === "more" && loading ? t("replay.readingNext") : endTextFor(end, t)}
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

// A Vault secret's marker carries no fingerprint; an operator's password's carries its size, salt and
// salted fingerprint (ADR-0133), as the Video Recorder writes them.
export function validMarkerKind(event: VideoRecordingEvent): boolean {
  const hex = (value: unknown, length: number) => typeof value === "string" && value.length === length && /^[0-9a-f]+$/.test(value);
  if (event.eventType === "secret_injection_started" && event.source === "vault") {
    return event.pasteBytes === undefined && event.pasteSalt === undefined && event.pasteSha256 === undefined;
  }
  if (event.eventType === "secret_paste_started" && event.source === "operator") {
    return Number.isInteger(event.pasteBytes) && (event.pasteBytes as number) >= 1 && (event.pasteBytes as number) <= 512 &&
      hex(event.pasteSalt, 32) && hex(event.pasteSha256, 64);
  }
  return false;
}
