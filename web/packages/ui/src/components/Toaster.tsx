import type { HTMLAttributes } from "react";
import { cn } from "../lib/cn";
import { useToast } from "../hooks/use-toast";
import { Toast } from "./Toast";

export type ToasterProps = HTMLAttributes<HTMLDivElement> & { position?: "top-left" | "top-right" | "bottom-left" | "bottom-right" | "top-center" | "bottom-center" };
export function Toaster({ position = "bottom-right", className, ...props }: ToasterProps) {
  const { toasts, dismiss } = useToast();
  return <div {...props} role="region" aria-label="Notifications" data-position={position} className={cn("ob-toaster", className)}>{toasts.map((entry) => <Toast key={entry.id} title={entry.title} description={entry.description} variant={entry.variant} duration={entry.duration} onDismiss={() => dismiss(entry.id)} />)}</div>;
}
