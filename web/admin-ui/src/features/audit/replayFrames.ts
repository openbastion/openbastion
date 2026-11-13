import { VideoRecordingSegment } from "../../shared/api";
import { DeltaRect, decodeScreenMessage } from "../screen/protocol";

// What a replay reads (ADR-0071, ADR-0088, ADR-0092): a key frame is a whole PNG, a partial frame
// changes rectangles of the frame before it. A segment is checked whole before anything is shown,
// and a frame is composed from the key frame at or before it.

const PNG_SIGNATURE = [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a];
const MAX_FRAME_BYTES = 4 << 20;

export type Frame =
  | { kind: "key"; sequence: number; at: Date; bytes: number; png: Uint8Array<ArrayBuffer> }
  | { kind: "delta"; sequence: number; at: Date; bytes: number; width: number; height: number; rects: DeltaRect[] }
  // A text that crossed the clipboard (ADR-0096): not a picture, the screen stays as it was.
  | { kind: "clipboard"; sequence: number; at: Date; bytes: number; direction: "to-target" | "from-target"; text: string };

// What a frame is put on the canvas with: the same primitives the live screen uses.
export interface ReplayPainter {
  // Decodes without an <img>, as the live screen does: the page's policy allows no blob: image.
  decode: (png: Uint8Array<ArrayBuffer>) => Promise<ImageBitmap>;
  draw: (canvas: HTMLCanvasElement, image: ImageBitmap) => void;
  // Puts a rectangle of a partial frame in place, replacing the pixels under it (ADR-0092 §6).
  patch: (canvas: HTMLCanvasElement, image: ImageBitmap, x: number, y: number) => void;
}

interface Size {
  width: number;
  height: number;
}

export class UnreadableSegment extends Error {}

// The size a key frame's PNG says (IHDR), or null: a partial frame is checked against it.
function pngSize(png: Uint8Array): Size | null {
  if (png.length < 24 || String.fromCharCode(...png.subarray(12, 16)) !== "IHDR") return null;
  const view = new DataView(png.buffer, png.byteOffset, png.byteLength);
  return { width: view.getUint32(16), height: view.getUint32(20) };
}

function pngSizeOf(frame: Frame): Size | null {
  return frame.kind === "key" ? pngSize(frame.png) : null;
}

// A segment's frames, checked: base64, at most 4 MiB, a date, as many as it says, and each a PNG
// (codec png), the partial frame of its own sequence (codec png-delta-v1), or the clipboard text of
// its own sequence (codec clipboard-text-v1).
export function framesOf(segment: VideoRecordingSegment): Frame[] {
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
    if (frame.codec === "clipboard-text-v1") {
      let message;
      try {
        message = decodeScreenMessage(data.buffer);
      } catch {
        throw new UnreadableSegment();
      }
      if (message.type !== "clipboard" || message.sequence !== BigInt(sequence)) throw new UnreadableSegment();
      return { kind: "clipboard", sequence, at, bytes: data.length, direction: message.direction, text: message.text };
    }
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

// The key frame at or before `target`; -1 when a recording starts with a partial frame.
function keyFrameBefore(frames: Frame[], target: number): number {
  let key = target;
  while (key >= 0 && frames[key].kind !== "key") key--;
  return key;
}

// Composes `target` on the canvas, from the frame already on it when that is the one just before —
// a run of partial frames is then patched in place — otherwise from the key frame at or before it.
// Returns the index of the last frame put in place, and stops between two frames when `stopped()`
// turns true: a newer position never lets an older frame paint over it.
export async function paintFrame({
  frames,
  target,
  from,
  canvas,
  painter,
  stopped,
}: {
  frames: Frame[];
  target: number;
  from: number | null;
  canvas: HTMLCanvasElement;
  painter: ReplayPainter;
  stopped: () => boolean;
}): Promise<number | null> {
  const key = keyFrameBefore(frames, target);
  if (key < 0) throw new Error("a partial frame without a key frame before it");
  if (from === target) return target;
  const start = from !== null && from >= key && from < target ? from + 1 : key;
  let screen = pngSizeOf(frames[key]);
  let last: number | null = null;
  for (let i = start; i <= target; i++) {
    const frame = frames[i];
    if (frame.kind === "clipboard") {
      last = i; // the screen as it was
      continue;
    }
    if (frame.kind === "key") {
      const image = await painter.decode(frame.png);
      if (stopped()) {
        image.close();
        return last;
      }
      painter.draw(canvas, image);
      image.close();
      screen = pngSizeOf(frame);
    } else {
      if (!screen || frame.width !== screen.width || frame.height !== screen.height) {
        throw new Error("a partial frame of another size than its screen");
      }
      const images = await Promise.all(frame.rects.map((rect) => painter.decode(rect.png)));
      try {
        if (images.some((image, j) => image.width !== frame.rects[j].width || image.height !== frame.rects[j].height)) {
          throw new Error("a rectangle of another size than announced");
        }
        if (stopped()) return last;
        frame.rects.forEach((rect, j) => painter.patch(canvas, images[j], rect.x, rect.y));
      } finally {
        images.forEach((image) => image.close());
      }
    }
    last = i;
  }
  return last;
}
