import type { HTMLAttributes } from "react";
import { cn } from "../lib/cn";

export type BadgeTone = "neutral" | "info" | "success" | "warning" | "danger";
export type BadgeProps = HTMLAttributes<HTMLSpanElement> & { tone?: BadgeTone };

export function Badge({ tone = "neutral", className, ...props }: BadgeProps) {
  return <span {...props} className={cn("ob-badge", `ob-badge--${tone}`, className)} />;
}
