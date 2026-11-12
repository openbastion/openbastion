import type { HTMLAttributes } from "react";

export type NoticeTone = "info" | "success" | "warning" | "danger";

export function InlineNotice({
  tone = "info",
  role,
  className,
  ...props
}: HTMLAttributes<HTMLParagraphElement> & { tone?: NoticeTone }) {
  const resolvedRole = role ?? (tone === "danger" ? "alert" : "status");
  const classes = ["ob-notice", `ob-notice--${tone}`, className].filter(Boolean).join(" ");
  return <p {...props} className={classes} role={resolvedRole} aria-live={resolvedRole === "alert" ? "assertive" : "polite"} />;
}
