// From a browser key to an X11 keysym (ADR-0071 §6, the table pkg/vnc checks again). A key outside
// it would close the session on the proxy, so it is not sent at all.

const NAMED_KEYS: Record<string, number> = {
  Backspace: 0xff08, Tab: 0xff09, Enter: 0xff0d, Pause: 0xff13, ScrollLock: 0xff14, Escape: 0xff1b,
  Home: 0xff50, ArrowLeft: 0xff51, ArrowUp: 0xff52, ArrowRight: 0xff53, ArrowDown: 0xff54,
  PageUp: 0xff55, PageDown: 0xff56, End: 0xff57, Insert: 0xff63, ContextMenu: 0xff67, NumLock: 0xff7f,
  F1: 0xffbe, F2: 0xffbf, F3: 0xffc0, F4: 0xffc1, F5: 0xffc2, F6: 0xffc3,
  F7: 0xffc4, F8: 0xffc5, F9: 0xffc6, F10: 0xffc7, F11: 0xffc8, F12: 0xffc9,
  Shift: 0xffe1, Control: 0xffe3, CapsLock: 0xffe5, Alt: 0xffe9, Meta: 0xffeb, AltGraph: 0xfe03,
  Delete: 0xffff,
};

export function keysymOf(key: string): number | null {
  const named = NAMED_KEYS[key];
  if (named !== undefined) return named;
  const chars = Array.from(key);
  if (chars.length !== 1) return null; // "Dead", "Unidentified", a composed sequence: not one key.
  const code = chars[0].codePointAt(0)!;
  if ((code >= 0x20 && code <= 0x7e) || (code >= 0xa0 && code <= 0xff)) return code;
  if (code >= 0x100 && code <= 0x10ffff) return 0x01000000 + code;
  return null;
}

// DOM buttons (1 left, 2 right, 4 middle) to RFB's mask (1 left, 2 middle, 4 right).
export function rfbButtons(domButtons: number): number {
  return (domButtons & 1) | ((domButtons & 4) >> 1) | ((domButtons & 2) << 1);
}
