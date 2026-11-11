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

export type ScreenMessage =
  // pointerDrawn: the frames carry the target's pointer (ADR-0091), the page hides its own.
  | { type: "hello"; protocol: "rdp" | "vnc"; pointerDrawn: boolean; expiresAt: Date; sessionId: string }
  | { type: "frame"; sequence: bigint; width: number; height: number; png: Uint8Array<ArrayBuffer> }
  | { type: "end"; sequence: bigint; code: number; text: string };

export class ScreenProtocolError extends Error {}

function refuse(what: string): never {
  throw new ScreenProtocolError(what);
}

const HELLO_POINTER_DRAWN = 0x01;

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
      // The flags byte: bit 0 says the pointer is drawn; the others are reserved and zero.
      if ((payload[1] & ~HELLO_POINTER_DRAWN) !== 0) refuse("malformed hello");
      const fields = new DataView(data, HEADER_SIZE);
      const idLength = fields.getUint32(10);
      if (idLength === 0 || idLength > MAX_SESSION_ID_BYTES || idLength !== length - 14) refuse("malformed hello");
      return { type: "hello", protocol, pointerDrawn: (payload[1] & HELLO_POINTER_DRAWN) !== 0, expiresAt: new Date(Number(fields.getBigUint64(2)) * 1000), sessionId: decodeText(text, payload.subarray(14)) };
    }
    case 3: {
      if (sequence === 0n || width !== 0 || height !== 0 || length < 4) refuse("malformed end");
      const fields = new DataView(data, HEADER_SIZE);
      const textLength = fields.getUint16(2);
      if (textLength > MAX_END_TEXT_BYTES || textLength !== length - 4) refuse("malformed end");
      return { type: "end", sequence, code: fields.getUint16(0), text: decodeText(text, payload.subarray(4)) };
    }
    default:
      return refuse("unknown message type");
  }
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
