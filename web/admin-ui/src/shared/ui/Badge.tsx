import type { HTMLAttributes } from "react";

export type BadgeTone = "neutral" | "info" | "success" | "warning" | "danger";

export function Badge({
  tone = "neutral",
  className,
  ...props
}: HTMLAttributes<HTMLSpanElement> & { tone?: BadgeTone }) {
  const classes = ["ob-badge", `ob-badge--${tone}`, className].filter(Boolean).join(" ");
  return <span {...props} className={classes} />;
}
