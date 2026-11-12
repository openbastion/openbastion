import { forwardRef, useState, type ButtonHTMLAttributes } from "react";
import { cn } from "../lib/cn";

export type ToggleProps = ButtonHTMLAttributes<HTMLButtonElement> & { pressed?: boolean; defaultPressed?: boolean; onPressedChange?: (pressed: boolean) => void };
export const Toggle = forwardRef<HTMLButtonElement, ToggleProps>(function Toggle({ pressed, defaultPressed = false, onPressedChange, className, onClick, ...props }, ref) {
  const [internalPressed, setInternalPressed] = useState(defaultPressed);
  const active = pressed ?? internalPressed;
  return <button {...props} ref={ref} type={props.type ?? "button"} aria-pressed={active} data-state={active ? "on" : "off"} className={cn("ob-toggle", className)} onClick={(event) => { onClick?.(event); if (event.defaultPrevented || props.disabled) return; const next = !active; if (pressed === undefined) setInternalPressed(next); onPressedChange?.(next); }} />;
});
Toggle.displayName = "Toggle";
