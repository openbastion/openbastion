import { forwardRef, type InputHTMLAttributes } from "react";
import { cn } from "../lib/cn";

export type InputOTPProps = Omit<InputHTMLAttributes<HTMLInputElement>, "type" | "maxLength"> & {
  length?: number;
};
export const InputOTP = forwardRef<HTMLInputElement, InputOTPProps>(function InputOTP({ length = 6, inputMode = "numeric", autoComplete = "one-time-code", pattern = "[0-9]*", className, ...props }, ref) {
  const boundedLength = Number.isInteger(length) && length > 0 && length <= 32 ? length : 6;
  return <input {...props} ref={ref} type="text" inputMode={inputMode} autoComplete={autoComplete} pattern={pattern} maxLength={boundedLength} className={cn("ob-input-otp", className)} />;
});
InputOTP.displayName = "InputOTP";
