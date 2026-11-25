import { RefObject, useEffect, useRef } from "react";

export interface AppMobileNavigationProps {
  open: boolean;
  onClose: () => void;
  /** The navigation container that behaves as a modal dialog while open. */
  containerRef: RefObject<HTMLElement | null>;
  /** The control that opened it: receives the focus back when it closes. */
  returnFocusRef: RefObject<HTMLElement | null>;
  /** Controls excluded from the focus cycle (e.g. the desktop collapse toggle). */
  excludeSelector?: string;
  className?: string;
}

const focusableSelector =
  'button:not([disabled]), a[href], input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])';

/**
 * The modal behaviour of an off-canvas navigation: focus moves in on open, Tab cycles inside the
 * container, Escape and the backdrop close, and the focus returns to the opening control. Renders the
 * backdrop only; the application keeps its own container markup (`role="dialog"` while open).
 */
export function AppMobileNavigation({ open, onClose, containerRef, returnFocusRef, excludeSelector, className = "navigation-backdrop" }: AppMobileNavigationProps) {
  const wasOpen = useRef(false);
  const latestClose = useRef(onClose);
  latestClose.current = onClose;

  useEffect(() => {
    if (wasOpen.current && !open) returnFocusRef.current?.focus();
    wasOpen.current = open;
  }, [open, returnFocusRef]);

  useEffect(() => {
    if (!open) return;
    const container = containerRef.current;
    const focusable = () => Array.from(container?.querySelectorAll<HTMLElement>(focusableSelector) ?? [])
      .filter((item) => !excludeSelector || !item.matches(excludeSelector));
    focusable()[0]?.focus();
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === "Escape") {
        event.preventDefault();
        latestClose.current();
        return;
      }
      if (event.key !== "Tab") return;
      const items = focusable();
      if (items.length === 0) {
        event.preventDefault();
        return;
      }
      const first = items[0];
      const last = items[items.length - 1];
      const outside = !container?.contains(document.activeElement);
      if (event.shiftKey && (document.activeElement === first || outside)) {
        event.preventDefault();
        last.focus();
      } else if (!event.shiftKey && (document.activeElement === last || outside)) {
        event.preventDefault();
        first.focus();
      }
    };
    document.addEventListener("keydown", onKeyDown);
    return () => document.removeEventListener("keydown", onKeyDown);
  }, [open, containerRef, excludeSelector]);

  if (!open) return null;
  return <button type="button" className={className} aria-hidden="true" tabIndex={-1} onClick={onClose} />;
}
