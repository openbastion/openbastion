// The openbastion.screen.v1 contract (ADR-0071 §6), the browser's side of pkg/screenstream. Strict
// like it: what does not parse ends the session, it is never displayed "at best".

export const SUBPROTOCOL = "openbastion.screen.v1";

const VERSION = 1;
const HEADER_SIZE = 32;
const MAX_PNG_BYTES = 4 << 20;
const MAX_PIXELS = 16_777_216;
const MAX_SESSION_ID_BYTES = 1024;
const MAX_END_TEXT_BYTES = 200;
const INPUT_SIZE = 16;
const PNG_SIGNATURE = [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a];
// A partial frame (ADR-0092): at most this many rectangles, each with a 20-byte header.
const MAX_DELTA_RECTS = 64;
const DELTA_RECT_HEADER = 20;
// A clipboard text (ADR-0096): a direction, three reserved bytes, then UTF-8, within the target's
// bound in UTF-16 units.
const CLIPBOARD_HEADER = 4;
const MAX_CLIPBOARD_TEXT_UNITS = 32763;

// A changed rectangle of a partial frame: where it goes, and its pixels as a PNG of its size.
export interface DeltaRect {
  x: number;
  y: number;
  width: number;
  height: number;
  png: Uint8Array<ArrayBuffer>;
}

export type ScreenMessage =
  // pointerDrawn: the frames carry the target's pointer (ADR-0091), the page hides its own.
  // resizable: the session follows the size of the page's screen area (ADR-0095), which then sends it.
  | { type: "hello"; protocol: "rdp" | "vnc"; pointerDrawn: boolean; resizable: boolean; expiresAt: Date; sessionId: string }
  | { type: "frame"; sequence: bigint; width: number; height: number; png: Uint8Array<ArrayBuffer> }
  // A partial frame (ADR-0092): its rectangles replace pixels of the frame of the sequence before.
  | { type: "delta"; sequence: bigint; width: number; height: number; rects: DeltaRect[] }
  | { type: "end"; sequence: bigint; code: number; text: string }
  // A text that crossed the clipboard (ADR-0096), in the session's sequence, recorded before it came.
  | { type: "clipboard"; sequence: bigint; direction: "to-target" | "from-target"; text: string };

export class ScreenProtocolError extends Error {}

function refuse(what: string): never {
  throw new ScreenProtocolError(what);
}

const HELLO_POINTER_DRAWN = 0x01;
const HELLO_RESIZABLE = 0x02;

export function decodeScreenMessage(data: ArrayBuffer): ScreenMessage {
  if (data.byteLength < HEADER_SIZE) refuse("short message");
  const view = new DataView(data);
  if (view.getUint8(0) !== VERSION || view.getUint16(2) !== 0) refuse("unknown version or flags");
  const sequence = view.getBigUint64(4);
  const width = view.getUint32(20);
  const height = view.getUint32(24);
  const length = view.getUint32(28);
  if (length !== data.byteLength - HEADER_SIZE) refuse("length does not match");
  const payload = new Uint8Array(data, HEADER_SIZE);
  const text = new TextDecoder("utf-8", { fatal: true });
  switch (view.getUint8(1)) {
    case 1: {
      if (sequence === 0n || width === 0 || height === 0 || width * height > MAX_PIXELS) refuse("frame out of bounds");
      if (length === 0 || length > MAX_PNG_BYTES) refuse("frame size out of bounds");
      if (PNG_SIGNATURE.some((b, i) => payload[i] !== b)) refuse("not a PNG");
      return { type: "frame", sequence, width, height, png: payload };
    }
    case 2: {
      if (sequence !== 0n || width !== 0 || height !== 0 || length < 14) refuse("malformed hello");
      const protocol = payload[0] === 1 ? "rdp" : payload[0] === 2 ? "vnc" : refuse("unknown protocol");
      // The flags byte: bit 0 says the pointer is drawn, bit 1 that the session resizes; the others
      // are reserved and zero.
      if ((payload[1] & ~(HELLO_POINTER_DRAWN | HELLO_RESIZABLE)) !== 0) refuse("malformed hello");
      const fields = new DataView(data, HEADER_SIZE);
      const idLength = fields.getUint32(10);
      if (idLength === 0 || idLength > MAX_SESSION_ID_BYTES || idLength !== length - 14) refuse("malformed hello");
      return { type: "hello", protocol, pointerDrawn: (payload[1] & HELLO_POINTER_DRAWN) !== 0, resizable: (payload[1] & HELLO_RESIZABLE) !== 0, expiresAt: new Date(Number(fields.getBigUint64(2)) * 1000), sessionId: decodeText(text, payload.subarray(14)) };
    }
    case 3: {
      if (sequence === 0n || width !== 0 || height !== 0 || length < 4) refuse("malformed end");
      const fields = new DataView(data, HEADER_SIZE);
      const textLength = fields.getUint16(2);
      if (textLength > MAX_END_TEXT_BYTES || textLength !== length - 4) refuse("malformed end");
      return { type: "end", sequence, code: fields.getUint16(0), text: decodeText(text, payload.subarray(4)) };
    }
    case 4: {
      if (sequence === 0n || width === 0 || height === 0 || width * height > MAX_PIXELS) refuse("partial frame out of bounds");
      if (length > MAX_PNG_BYTES) refuse("partial frame too large");
      return { type: "delta", sequence, width, height, rects: decodeRects(data, width, height) };
    }
    case 5: {
      if (sequence === 0n || width !== 0 || height !== 0 || length < CLIPBOARD_HEADER) refuse("malformed clipboard text");
      if (payload[1] !== 0 || payload[2] !== 0 || payload[3] !== 0) refuse("malformed clipboard text");
      const direction = payload[0] === 1 ? "to-target" : payload[0] === 2 ? "from-target" : refuse("unknown clipboard direction");
      const clip = decodeText(text, payload.subarray(CLIPBOARD_HEADER));
      // UTF-16 units are what JavaScript strings count.
      if (clip.includes("\u0000") || clip.length > MAX_CLIPBOARD_TEXT_UNITS) refuse("clipboard text out of bounds");
      return { type: "clipboard", sequence, direction, text: clip };
    }
    default:
      return refuse("unknown message type");
  }
}

// The rectangles of a partial frame, as strict as pkg/screenstream: 1 to 64, each non-empty, inside
// the frame, a PNG; nothing left over and no length past the message.
function decodeRects(data: ArrayBuffer, width: number, height: number): DeltaRect[] {
  const view = new DataView(data, HEADER_SIZE);
  if (view.byteLength < 2) refuse("malformed partial frame");
  const count = view.getUint16(0);
  if (count === 0 || count > MAX_DELTA_RECTS) refuse("partial frame out of bounds");
  const rects: DeltaRect[] = [];
  let at = 2;
  for (let i = 0; i < count; i++) {
    if (view.byteLength - at < DELTA_RECT_HEADER) refuse("malformed partial frame");
    const x = view.getUint32(at), y = view.getUint32(at + 4), w = view.getUint32(at + 8), h = view.getUint32(at + 12);
    const n = view.getUint32(at + 16);
    at += DELTA_RECT_HEADER;
    if (n > view.byteLength - at) refuse("malformed partial frame");
    if (w === 0 || h === 0 || x + w > width || y + h > height || n < PNG_SIGNATURE.length) refuse("rectangle out of bounds");
    const png = new Uint8Array(data, HEADER_SIZE + at, n);
    if (PNG_SIGNATURE.some((b, j) => png[j] !== b)) refuse("not a PNG");
    rects.push({ x, y, width: w, height: h, png });
    at += n;
  }
  if (at !== view.byteLength) refuse("malformed partial frame");
  return rects;
}

function decodeText(decoder: TextDecoder, bytes: Uint8Array): string {
  try {
    return decoder.decode(bytes);
  } catch {
    return refuse("invalid text");
  }
}

function inputMessage(type: number): { bytes: Uint8Array<ArrayBuffer>; view: DataView } {
  const bytes = new Uint8Array(INPUT_SIZE);
  bytes[0] = VERSION;
  bytes[1] = type;
  return { bytes, view: new DataView(bytes.buffer) };
}

export function encodeKey(keysym: number, pressed: boolean): Uint8Array<ArrayBuffer> {
  const { bytes, view } = inputMessage(1);
  bytes[2] = pressed ? 1 : 0;
  view.setUint32(4, keysym);
  return bytes;
}

// RDP's key (ADR-0088): the physical key's Set-1 scancode, no keysym.
export function encodeScancode(scancode: number, pressed: boolean): Uint8Array<ArrayBuffer> {
  const { bytes, view } = inputMessage(1);
  bytes[2] = pressed ? 1 : 0;
  view.setUint16(8, scancode);
  return bytes;
}

// wheel is one notch at most: up (1) or down (-1).
export function encodePointer(x: number, y: number, buttons: number, wheel: -1 | 0 | 1 = 0): Uint8Array<ArrayBuffer> {
  const { bytes, view } = inputMessage(2);
  view.setUint16(10, x);
  view.setUint16(12, y);
  bytes[14] = buttons;
  view.setInt8(15, wheel);
  return bytes;
}

export function encodeReleaseAll(): Uint8Array<ArrayBuffer> {
  return inputMessage(3).bytes;
}

// The bounds of a resize (ADR-0095 §4), as the proxy holds them: past 2560 x 1600 a key frame risks
// the 4 MiB of a segment. The width is even.
export const RESIZE_BOUNDS = { minWidth: 640, minHeight: 480, maxWidth: 2560, maxHeight: 1600 } as const;

export function clampResize(width: number, height: number): { width: number; height: number } {
  const w = Math.min(Math.max(Math.floor(width), RESIZE_BOUNDS.minWidth), RESIZE_BOUNDS.maxWidth);
  const h = Math.min(Math.max(Math.floor(height), RESIZE_BOUNDS.minHeight), RESIZE_BOUNDS.maxHeight);
  return { width: w - (w % 2), height: h };
}

// A size for the target's desktop (ADR-0095 §5): the width in X, the height in Y, within the bounds.
export function encodeResize(width: number, height: number): Uint8Array<ArrayBuffer> {
  const size = clampResize(width, height);
  const { bytes, view } = inputMessage(4);
  view.setUint16(10, size.width);
  view.setUint16(12, size.height);
  return bytes;
}

// What an END means for the operator. The codes are the stable ones of ADR-0071 §12; the proxy's
// text is the same code, never a cause.
const END_MESSAGES: Record<string, string> = {
  session_ended: "La session est terminée.",
  session_revoked: "La session a été révoquée.",
  session_expired: "La session a expiré.",
  recording_unavailable: "Enregistrement indisponible : la session n'a pas été ouverte.",
  recording_lost: "L'enregistrement a été perdu : la session a été coupée.",
  input_invalid: "Une saisie a été refusée : la session a été coupée.",
  target_unreachable: "La cible n'a pas répondu ou a refusé la connexion.",
  pin_missing: "Le compte n'a pas de certificat TLS épinglé.",
  pin_mismatch: "La cible n'a pas présenté le certificat épinglé : aucun secret n'a été envoyé.",
  tls_required: "La cible n'accepte pas de connexion TLS.",
  nla_required: "La cible n'accepte pas l'authentification exigée.",
  protocol_version_unsupported: "La version du protocole de la cible n'est pas prise en charge.",
  codec_unsupported: "La cible utilise un encodage qui n'est pas pris en charge.",
  ticket_invalid: "Ce rattachement n'est plus valable : reconnectez-vous.",
};

export function endMessage(text: string): string {
  return END_MESSAGES[text] ?? "La session s'est arrêtée.";
}
