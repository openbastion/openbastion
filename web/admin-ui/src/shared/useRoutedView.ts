import { useState } from "react";

// The tab of a page, either owned by the URL (ADR-0137 §6: the application gives `routed` and
// `onRoute`) or, for a screen rendered on its own (a unit test), by local state.
export function useRoutedView<V extends string>(initial: V, routed?: V, onRoute?: (view: V) => void): [V, (view: V) => void] {
  const [local, setLocal] = useState<V>(initial);
  if (routed !== undefined) return [routed, (view) => onRoute?.(view)];
  return [local, setLocal];
}
