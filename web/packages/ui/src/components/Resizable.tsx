import { useState, type HTMLAttributes, type ReactNode } from "react";
import { cn } from "../lib/cn";

export type ResizableProps = HTMLAttributes<HTMLDivElement> & { axis?: "horizontal" | "vertical" | "both"; label: string; children: ReactNode };
export function Resizable({ axis = "both", label, className, children, onKeyDown, ...props }: ResizableProps) {
  const [size, setSize] = useState(0);
  return <div {...props} role="region" aria-label={label} aria-description="Utilisez les flèches pour ajuster la taille." aria-keyshortcuts="ArrowLeft ArrowRight ArrowUp ArrowDown" tabIndex={0} data-axis={axis} data-size={size} className={cn("ob-resizable", className)} onKeyDown={(event) => { onKeyDown?.(event); if (event.defaultPrevented) return; const horizontal = axis === "horizontal" || axis === "both"; const vertical = axis === "vertical" || axis === "both"; if ((horizontal && event.key === "ArrowRight") || (vertical && event.key === "ArrowDown")) { event.preventDefault(); setSize((current) => Math.min(current + 1, 12)); } else if ((horizontal && event.key === "ArrowLeft") || (vertical && event.key === "ArrowUp")) { event.preventDefault(); setSize((current) => Math.max(current - 1, 0)); } }}>{children}</div>;
}
