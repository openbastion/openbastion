import { forwardRef, type HTMLAttributes } from "react";
import { cn } from "../lib/cn";

export type ScrollAreaProps = HTMLAttributes<HTMLDivElement> & { label: string; axis?: "vertical" | "horizontal" | "both" };
export const ScrollArea = forwardRef<HTMLDivElement, ScrollAreaProps>(function ScrollArea({ label, axis = "vertical", className, ...props }, ref) { return <div {...props} ref={ref} role="region" aria-label={label} tabIndex={0} data-axis={axis} className={cn("ob-scroll-area", className)} />; });
ScrollArea.displayName = "ScrollArea";
