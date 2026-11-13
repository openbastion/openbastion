import { forwardRef, type ProgressHTMLAttributes } from "react";
import { cn } from "../lib/cn";

export type ProgressProps = ProgressHTMLAttributes<HTMLProgressElement> & { label: string };
export const Progress = forwardRef<HTMLProgressElement, ProgressProps>(function Progress({ className, max = 100, label, ...props }, ref) { return <progress {...props} ref={ref} max={max} aria-label={label} className={cn("ob-progress", className)} />; });
Progress.displayName = "Progress";
