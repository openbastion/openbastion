import { RefObject, useEffect, useRef } from "react";

export interface AppDismissableOptions {
  open: boolean;
  onClose: () => void;
  /** A pointer press outside this element closes. */
  containerRef: RefObject<HTMLElement | null>;
  /** Called on Escape instead of `onClose`, when the caller restores focus itself. */
  onEscape?: () => void;
}

/** Closes a popover-like surface on Escape or on a pointer press outside its container. */
export function useAppDismissable({ open, onClose, containerRef, onEscape }: AppDismissableOptions): void {
  const latest = useRef({ onClose, onEscape });
  latest.current = { onClose, onEscape };

  useEffect(() => {
    if (!open) return;
    const closeOnEscape = (event: KeyboardEvent) => {
      if (event.key === "Escape") (latest.current.onEscape ?? latest.current.onClose)();
    };
    const closeOnOutsidePointer = (event: PointerEvent) => {
      if (event.target instanceof Node && !containerRef.current?.contains(event.target)) latest.current.onClose();
    };
    document.addEventListener("keydown", closeOnEscape);
    document.addEventListener("pointerdown", closeOnOutsidePointer);
    return () => {
      document.removeEventListener("keydown", closeOnEscape);
      document.removeEventListener("pointerdown", closeOnOutsidePointer);
    };
  }, [open, containerRef]);
}
