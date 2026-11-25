import { ReactNode, RefObject, useEffect, useRef } from "react";
import { useAppDismissable } from "../hooks/use-app-dismissable";

export interface AppUserMenuProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  /** Content of the trigger (avatar, identity, chevron…): provided, translated, by the application. */
  trigger: ReactNode;
  /** Accessible name of the panel. */
  label: string;
  /** Panel content: identity summary, sections, items. The application owns the actions. */
  children: ReactNode;
  id?: string;
  triggerRef?: RefObject<HTMLButtonElement | null>;
  /** False while another surface took the focus (a dialog opened from the menu): no focus return. */
  restoreFocus?: boolean;
}

/**
 * A disclosure menu anchored on a trigger: Escape and an outside press close it, and the focus returns
 * to the trigger. It knows no action, label or role; the application renders them as children.
 */
export function AppUserMenu({ open, onOpenChange, trigger, label, children, id = "operator-menu", triggerRef, restoreFocus = true }: AppUserMenuProps) {
  const container = useRef<HTMLDivElement>(null);
  const ownTrigger = useRef<HTMLButtonElement>(null);
  const button = triggerRef ?? ownTrigger;
  const wasOpen = useRef(false);

  useAppDismissable({ open, onClose: () => onOpenChange(false), containerRef: container });

  useEffect(() => {
    if (wasOpen.current && !open && restoreFocus) button.current?.focus();
    wasOpen.current = open;
  }, [open, restoreFocus, button]);

  return (
    <div className="sidebar-user-menu" ref={container}>
      <button
        ref={button}
        type="button"
        className="user-menu-trigger sidebar-user-menu-trigger"
        aria-haspopup="true"
        aria-expanded={open}
        aria-controls={id}
        onClick={() => onOpenChange(!open)}
      >
        {trigger}
      </button>
      {open ? (
        <div className="user-menu-panel sidebar-user-menu-panel" id={id} aria-label={label}>
          {children}
        </div>
      ) : null}
    </div>
  );
}
