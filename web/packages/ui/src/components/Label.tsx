import { forwardRef, type LabelHTMLAttributes } from "react";
import { cn } from "../lib/cn";

export type LabelProps = LabelHTMLAttributes<HTMLLabelElement>;
export const Label = forwardRef<HTMLLabelElement, LabelProps>(function Label({ className, ...props }, ref) {
  return <label {...props} ref={ref} className={cn("ob-label", className)} />;
});
Label.displayName = "Label";
