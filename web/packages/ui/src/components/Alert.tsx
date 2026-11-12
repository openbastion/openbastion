import type { HTMLAttributes } from "react";
import { cn } from "../lib/cn";

export type AlertTone = "info" | "success" | "warning" | "danger";
export type AlertProps = HTMLAttributes<HTMLDivElement> & { tone?: AlertTone; role?: "alert" | "status" | "region" };

export function Alert({ tone = "info", role, className, ...props }: AlertProps) {
  const resolvedRole = role ?? (tone === "danger" ? "alert" : "status");
  return (
    <div
      {...props}
      className={cn("ob-notice", `ob-notice--${tone}`, className)}
      role={resolvedRole}
      aria-live={resolvedRole === "alert" ? "assertive" : resolvedRole === "status" ? "polite" : undefined}
    />
  );
}
