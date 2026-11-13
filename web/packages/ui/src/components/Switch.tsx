import { forwardRef, type InputHTMLAttributes } from "react";
import { cn } from "../lib/cn";

export type SwitchProps = Omit<InputHTMLAttributes<HTMLInputElement>, "type">;
export const Switch = forwardRef<HTMLInputElement, SwitchProps>(function Switch({ className, role = "switch", ...props }, ref) {
  return <input {...props} ref={ref} type="checkbox" role={role} className={cn("ob-switch", className)} />;
});
Switch.displayName = "Switch";
