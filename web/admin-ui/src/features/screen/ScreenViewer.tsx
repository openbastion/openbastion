import { KeyboardEvent, MouseEvent, PointerEvent, WheelEvent, useCallback, useEffect, useRef, useState } from "react";
import { SUBPROTOCOL, clampResize, decodeScreenMessage, encodeKey, encodePointer, encodeReleaseAll, encodeResize, encodeScancode, endMessage } from "./protocol";
import { keysymOf, rfbButtons, scancodeOf } from "./keys";

export type ScreenSocket = Pick<WebSocket, "send" | "close" | "readyState" | "binaryType" | "onopen" | "onmessage" | "onclose" | "onerror">;

export interface ScreenDeps {
  // new WebSocket: the Gateway authenticates this upgrade by the one-use HttpOnly cookie that
  // POST /connect has just set, never by anything this page holds or a URL carries (ADR-0071 §7).
  open: (url: string, protocol: string) => ScreenSocket;
  // Decodes without an <img>: the page's policy allows no blob: image, and needs none.
  decode: (png: Uint8Array<ArrayBuffer>) => Promise<ImageBitmap>;
  draw: (canvas: HTMLCanvasElement, image: ImageBitmap, width: number, height: number) => void;
  // Puts a rectangle of a partial frame in place: its pixels replace those under it, without
  // blending (ADR-0092 §6).
  patch: (canvas: HTMLCanvasElement, image: ImageBitmap, x: number, y: number) => void;
  // The room the page has for the screen, in CSS pixels (ADR-0095): what a resizable session is
  // asked to be. Without it, the browser's own measure.
  measure?: (area: HTMLElement) => { width: number; height: number };
}

// What is above the canvas in its area (the buttons and a line of status): left out of the height.
const SCREEN_CHROME = 112;
// A resize is sent once the window has stopped moving for this long; the proxy paces them too.
export const RESIZE_DEBOUNCE_MS = 500;

function measureArea(area: HTMLElement): { width: number; height: number } {
  return { width: area.clientWidth, height: window.innerHeight - area.getBoundingClientRect().top - SCREEN_CHROME };
}

const browserDeps: ScreenDeps = {
  open: (url, protocol) => new WebSocket(url, protocol),
  decode: (png) => createImageBitmap(new Blob([png], { type: "image/png" })),
  draw: (canvas, image, width, height) => {
    if (canvas.width !== width) canvas.width = width;
    if (canvas.height !== height) canvas.height = height;
    canvas.getContext("2d")?.drawImage(image, 0, 0);
  },
  patch: (canvas, image, x, y) => {
    const context = canvas.getContext("2d");
    context?.clearRect(x, y, image.width, image.height);
    context?.drawImage(image, x, y);
  },
};

// A path on this very origin, or nothing: the page opens no socket anywhere else.
export function attachUrl(attach: string, location: { protocol: string; host: string; origin: string }): string | null {
  let url: URL;
  try {
    url = new URL(attach, location.origin);
  } catch {
    return null;
  }
  if (url.origin !== location.origin || !url.pathname.startsWith("/sessions/") || url.search !== "") return null;
  return `${location.protocol === "https:" ? "wss:" : "ws:"}//${location.host}${url.pathname}`;
}

type Phase = { name: "connecting" } | { name: "live"; expiresAt?: Date } | { name: "ended"; message: string };

const CLOSED_WITHOUT_END = "La connexion à l'écran a été perdue. Reconnectez-vous si la session est encore active.";
const UNREADABLE = "Le flux reçu n'est pas valide : la connexion a été fermée.";

// The screen of a graphical session: a canvas that shows exactly the PNG frames the Video Recorder
// has acknowledged, and the keyboard and the pointer sent back as bounded events (ADR-0071 §4, §6).
// Nothing typed is kept, logged or shown. The attach is single use: a lost connection does not come
// back on its own, the operator asks for a new one (onReconnect, another POST /connect).
export function ScreenViewer({ attach, onReconnect, onClose, deps = browserDeps }: { attach: string; onReconnect: () => void; onClose: () => void; deps?: ScreenDeps }) {
  const canvas = useRef<HTMLCanvasElement>(null);
  const area = useRef<HTMLDivElement>(null);
  const socket = useRef<ScreenSocket | null>(null);
  const frame = useRef<{ width: number; height: number } | null>(null);
  const pressed = useRef(new Map<string, number>());
  // The session's protocol, as the proxy's HELLO says: RDP takes scancodes, VNC keysyms (ADR-0088).
  const protocol = useRef<"rdp" | "vnc" | null>(null);
  const moveFrame = useRef<number | null>(null);
  const pendingMove = useRef<Uint8Array<ArrayBuffer> | null>(null);
  const buttons = useRef(0);
  const [phase, setPhase] = useState<Phase>({ name: "connecting" });
  const [isRDP, setIsRDP] = useState(false);
  // The pointer is in the frames (HELLO, ADR-0091): the browser's own arrow would be a second one.
  const [pointerDrawn, setPointerDrawn] = useState(false);
  const [resizable, setResizable] = useState(false);
  const [hasFrame, setHasFrame] = useState(false);

  const send = useCallback((message: Uint8Array<ArrayBuffer>) => {
    const ws = socket.current;
    if (ws && ws.readyState === 1) ws.send(message);
  }, []);

  useEffect(() => {
    const url = attachUrl(attach, window.location);
    if (!url) {
      setPhase({ name: "ended", message: UNREADABLE });
      return;
    }
    const ws = deps.open(url, SUBPROTOCOL);
    ws.binaryType = "arraybuffer";
    socket.current = ws;
    let ended = false;
    let lastReceived = 0n;
    // The size of the screen the last key frame set, and that key frame's sequence: a partial frame
    // applies to the frame just before it, on that screen, and to nothing else (ADR-0092 §1).
    let screen: { width: number; height: number } | null = null;
    let latestKey = 0n;
    // Frames are painted one after the other, in order: a partial frame changes the screen the
    // frames before it made. What came before the latest key frame is not painted: that key frame
    // replaces it whole.
    let painting: Promise<void> = Promise.resolve();
    const finish = (message: string) => {
      if (ended) return;
      ended = true;
      socket.current = null;
      setPhase({ name: "ended", message });
      ws.close();
    };
    ws.onmessage = (event) => {
      if (ended) return;
      let message;
      try {
        message = decodeScreenMessage(event.data as ArrayBuffer);
      } catch {
        finish(UNREADABLE);
        return;
      }
      if (message.type === "hello") {
        protocol.current = message.protocol;
        setIsRDP(message.protocol === "rdp");
        setPointerDrawn(message.pointerDrawn);
        setResizable(message.resizable);
        setPhase({ name: "live", expiresAt: message.expiresAt });
      } else if (message.type === "end") {
        finish(endMessage(message.text));
      } else {
        // Strictly increasing. Key frames may come with gaps (the proxy replaces what a slow page
        // has not taken yet); a partial frame never: it follows the frame before it, on its screen.
        if (message.sequence <= lastReceived) {
          finish(UNREADABLE);
          return;
        }
        if (message.type === "delta") {
          if (!screen || message.sequence !== lastReceived + 1n || message.width !== screen.width || message.height !== screen.height) {
            finish(UNREADABLE);
            return;
          }
        } else {
          screen = { width: message.width, height: message.height };
          latestKey = message.sequence;
        }
        lastReceived = message.sequence;
        const received = message;
        painting = painting.then(async () => {
          if (ended || received.sequence < latestKey) return;
          if (received.type === "frame") {
            const image = await deps.decode(received.png);
            if (ended || received.sequence < latestKey || !canvas.current) {
              image.close();
              return;
            }
            deps.draw(canvas.current, image, received.width, received.height);
            image.close();
          } else {
            const images = await Promise.all(received.rects.map((rect) => deps.decode(rect.png)));
            try {
              if (images.some((image, i) => image.width !== received.rects[i].width || image.height !== received.rects[i].height)) {
                throw new Error("a rectangle of another size than announced");
              }
              if (ended || received.sequence < latestKey || !canvas.current) return;
              received.rects.forEach((rect, i) => deps.patch(canvas.current as HTMLCanvasElement, images[i], rect.x, rect.y));
            } finally {
              images.forEach((image) => image.close());
            }
          }
          frame.current = { width: received.width, height: received.height };
          setHasFrame(true);
        }).catch(() => finish(UNREADABLE));
      }
    };
    ws.onclose = () => finish(CLOSED_WITHOUT_END);
    ws.onerror = () => finish(CLOSED_WITHOUT_END);
    return () => {
      ended = true;
      if (ws.readyState === 1) ws.send(encodeReleaseAll());
      ws.close();
      socket.current = null;
      if (moveFrame.current !== null) cancelAnimationFrame(moveFrame.current);
      moveFrame.current = null;
      pendingMove.current = null;
    };
  }, [attach, deps]);

  // A resizable session (ADR-0095) is asked for the size of the room the page has: once it says it
  // resizes, then each time the window has stopped changing size, and only when that size changes.
  useEffect(() => {
    if (!resizable) return;
    let last = "";
    let timer: ReturnType<typeof setTimeout> | null = null;
    const ask = () => {
      timer = null;
      if (!area.current) return;
      const measured = (deps.measure ?? measureArea)(area.current);
      const size = clampResize(measured.width, measured.height);
      const key = `${size.width}x${size.height}`;
      if (key === last) return;
      last = key;
      send(encodeResize(size.width, size.height));
    };
    const later = () => {
      if (timer !== null) clearTimeout(timer);
      timer = setTimeout(ask, RESIZE_DEBOUNCE_MS);
    };
    ask();
    window.addEventListener("resize", later);
    return () => {
      window.removeEventListener("resize", later);
      if (timer !== null) clearTimeout(timer);
    };
  }, [resizable, deps, send]);

  // Keyed by physical key: the release must name what the press named, even if Shift went up first.
  // RDP takes the physical key itself, VNC the character it gives here; before the HELLO, nothing.
  function onKeyDown(e: KeyboardEvent) {
    e.preventDefault();
    const rdp = protocol.current === "rdp";
    if (protocol.current === null) return;
    const key = pressed.current.get(e.code) ?? (rdp ? scancodeOf(e.code) : keysymOf(e.key));
    if (key === null) return;
    pressed.current.set(e.code, key);
    send(rdp ? encodeScancode(key, true) : encodeKey(key, true));
  }

  function onKeyUp(e: KeyboardEvent) {
    e.preventDefault();
    const key = pressed.current.get(e.code);
    if (key === undefined) return;
    pressed.current.delete(e.code);
    send(protocol.current === "rdp" ? encodeScancode(key, false) : encodeKey(key, false));
  }

  // Ctrl+Alt+Del, which the browser keeps for itself (ADR-0071, consequences): pressed and released
  // in order, as scancodes, for an RDP session only.
  function ctrlAltDel() {
    if (protocol.current !== "rdp") return;
    for (const code of [0x1d, 0x38, 0xe053]) send(encodeScancode(code, true));
    for (const code of [0xe053, 0x38, 0x1d]) send(encodeScancode(code, false));
    canvas.current?.focus();
  }

  // No key stays down on the target because the operator looked elsewhere (ADR-0071 §6).
  function onBlur() {
    pressed.current.clear();
    buttons.current = 0;
    pendingMove.current = null;
    send(encodeReleaseAll());
  }

  // Frame coordinates, inside the frame: the proxy closes the session on anything outside.
  function position(e: { clientX: number; clientY: number }): { x: number; y: number } | null {
    const f = frame.current;
    const c = canvas.current;
    if (!f || !c) return null;
    const box = c.getBoundingClientRect();
    if (box.width === 0 || box.height === 0) return null;
    const clamp = (v: number, size: number) => Math.min(size - 1, Math.max(0, Math.floor(v)));
    return { x: clamp(((e.clientX - box.left) * f.width) / box.width, f.width), y: clamp(((e.clientY - box.top) * f.height) / box.height, f.height) };
  }

  // Moves wait for the next animation frame, and only the latest leaves.
  function flushMove() {
    moveFrame.current = null;
    if (pendingMove.current) send(pendingMove.current);
    pendingMove.current = null;
  }

  function onPointerMove(e: PointerEvent) {
    const at = position(e);
    if (!at) return;
    pendingMove.current = encodePointer(at.x, at.y, buttons.current);
    if (moveFrame.current === null) moveFrame.current = requestAnimationFrame(flushMove);
  }

  function onPointerButtons(e: PointerEvent) {
    e.preventDefault();
    canvas.current?.focus();
    const at = position(e);
    if (!at) return;
    buttons.current = rfbButtons(e.buttons);
    // A click is not coalesced, and carries its position: a move still waiting is older than it.
    pendingMove.current = null;
    send(encodePointer(at.x, at.y, buttons.current));
  }

  function onWheel(e: WheelEvent) {
    const at = position(e);
    if (!at || e.deltaY === 0) return;
    send(encodePointer(at.x, at.y, buttons.current, e.deltaY < 0 ? 1 : -1));
  }

  function noMenu(e: MouseEvent) {
    e.preventDefault();
  }

  return (
    <div className="screen" ref={area}>
      <div className="form-actions">
        <button type="button" onClick={onClose}>Fermer l'écran</button>
        {phase.name === "live" && isRDP ? <button type="button" onClick={ctrlAltDel}>Ctrl+Alt+Suppr</button> : null}
        {phase.name === "ended" ? <button type="button" className="primary" onClick={onReconnect}>Se reconnecter</button> : null}
      </div>
      {phase.name === "connecting" ? <p className="notice ok" role="status">Connexion à la cible…</p> : null}
      {phase.name === "live" && !hasFrame ? <p className="notice ok" role="status">Connecté. En attente de la première image enregistrée…</p> : null}
      {phase.name === "live" && hasFrame ? (
        <p className="hint" role="status">
          Session enregistrée{phase.expiresAt ? `, jusqu'à ${phase.expiresAt.toLocaleString("fr-FR")}` : ""}. Cliquez sur l'écran pour saisir. Le navigateur garde pour lui certains raccourcis (Alt+Tab, touche Windows).
        </p>
      ) : null}
      {phase.name === "ended" ? <p className="notice error" role="alert">{phase.message}</p> : null}
      <canvas
        ref={canvas}
        className={pointerDrawn ? "screen-canvas pointer-drawn" : "screen-canvas"}
        tabIndex={0}
        role="img"
        aria-label="Écran distant de la session, non lisible par un lecteur d'écran"
        hidden={!hasFrame}
        onKeyDown={onKeyDown}
        onKeyUp={onKeyUp}
        onBlur={onBlur}
        onPointerMove={onPointerMove}
        onPointerDown={onPointerButtons}
        onPointerUp={onPointerButtons}
        onWheel={onWheel}
        onContextMenu={noMenu}
      />
    </div>
  );
}
