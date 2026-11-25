import { useLayoutEffect, useRef } from "react";

export interface AppShortcutsOptions {
  /** Ctrl/Meta+K. Active even in a text field or a modal, as soon as the layout is committed. */
  onCommandPalette?: () => void;
  /** Alt+Shift+<digit>, digit 1…`destinationCount`. The application maps the index to its own table. */
  onDestination?: (index: number) => void;
  destinationCount?: number;
  /** True while a modal owns the keyboard: destination shortcuts are ignored. */
  suspended?: boolean;
}

export function isTextEntry(target: EventTarget | null): boolean {
  if (!(target instanceof HTMLElement)) return false;
  return target.isContentEditable || target.closest("input, textarea, select, [contenteditable=true]") !== null;
}

/**
 * Global keyboard shortcuts of an application shell. A layout effect (not a passive one) so that
 * Ctrl/Meta+K is not missed in the brief window after the shell is committed. Callbacks are read at
 * event time, so a changing closure never needs the listener to be re-registered.
 */
export function useAppShortcuts(options: AppShortcutsOptions): void {
  const latest = useRef(options);
  latest.current = options;

  useLayoutEffect(() => {
    const onKeyDown = (event: KeyboardEvent) => {
      const { onCommandPalette, onDestination, destinationCount = 6, suspended } = latest.current;
      if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === "k") {
        event.preventDefault();
        onCommandPalette?.();
        return;
      }
      if (isTextEntry(event.target) || suspended) return;
      // `event.key` is "!" for Shift+1 on a US layout: the physical key (`code`) is the reliable one.
      const digit = /^[1-9]$/.test(event.key) ? event.key : /^Digit([1-9])$/.exec(event.code)?.[1];
      if (event.altKey && event.shiftKey && digit) {
        const index = Number(digit) - 1;
        if (index >= destinationCount) return;
        event.preventDefault();
        onDestination?.(index);
      }
    };
    document.addEventListener("keydown", onKeyDown);
    return () => document.removeEventListener("keydown", onKeyDown);
  }, []);
}
