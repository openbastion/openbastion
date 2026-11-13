/** Accept only browser-safe image URLs; reject executable and protocol-relative sources. */
export function isSafeImageSource(source) {
  if (typeof source !== "string" || source.trim() === "") return false;
  const value = source.trim();
  if (value.startsWith("//") || /^(?:javascript|data|vbscript|file):/i.test(value)) return false;
  return /^(?:https:\/\/|\/(?!\/)|\.\/|\.\.\/)/i.test(value);
}

/** Return a safe source or null so callers can render a local placeholder. */
export function resolveImageSource(source, fallback = null) {
  if (isSafeImageSource(source)) return source.trim();
  return isSafeImageSource(fallback) ? fallback.trim() : null;
}
