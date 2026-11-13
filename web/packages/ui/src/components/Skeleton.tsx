import type { HTMLAttributes } from "react";
import { cn } from "../lib/cn";

export type SkeletonProps = HTMLAttributes<HTMLSpanElement>;
export function Skeleton({ className, "aria-label": label = "Chargement", ...props }: SkeletonProps) {
  return <span {...props} className={cn("ob-skeleton", className)} role="status" aria-label={label} />;
}
