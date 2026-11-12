import { forwardRef, type InputHTMLAttributes } from "react";
import { cn } from "../lib/cn";

export type SliderProps = Omit<InputHTMLAttributes<HTMLInputElement>, "type">;
export const Slider = forwardRef<HTMLInputElement, SliderProps>(function Slider({ className, min = 0, max = 100, step = 1, ...props }, ref) {
  return <input {...props} ref={ref} type="range" min={min} max={max} step={step} className={cn("ob-slider", className)} />;
});
Slider.displayName = "Slider";
