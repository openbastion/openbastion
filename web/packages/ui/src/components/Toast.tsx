import { useEffect, useRef, type HTMLAttributes } from "react";
import { cn } from "../lib/cn";
import type { ToastVariant } from "../hooks/use-toast";

export type ToastProps = HTMLAttributes<HTMLDivElement> & { title: string; description?: string; variant?: ToastVariant; duration?: number; onDismiss?: () => void; closeLabel?: string };
export function Toast({ title, description, variant = "default", duration = 5000, onDismiss, closeLabel = "Fermer la notification", className, ...props }: ToastProps) {
  const dismissRef = useRef(onDismiss);
  useEffect(() => { dismissRef.current = onDismiss; }, [onDismiss]);
  useEffect(() => {
    if (!onDismiss || duration <= 0) return;
    const timer = window.setTimeout(() => dismissRef.current?.(), duration);
    return () => window.clearTimeout(timer);
  }, [duration, Boolean(onDismiss)]);
  return <div {...props} role={variant === "danger" ? "alert" : "status"} aria-atomic="true" data-variant={variant} className={cn("ob-toast", className)}><div className="ob-toast-copy"><strong className="ob-toast-title">{title}</strong>{description ? <p className="ob-toast-description">{description}</p> : null}</div>{onDismiss ? <button type="button" className="ob-toast-close" aria-label={closeLabel} onClick={onDismiss}>×</button> : null}</div>;
}
