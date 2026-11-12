import type { HTMLAttributes } from "react";
import { cn } from "../lib/cn";

export type SeparatorProps = HTMLAttributes<HTMLDivElement> & { orientation?: "horizontal" | "vertical" };
export function Separator({ orientation = "horizontal", className, ...props }: SeparatorProps) {
  return <div {...props} role="separator" aria-orientation={orientation} className={cn("ob-separator", `ob-separator--${orientation}`, className)} />;
}
