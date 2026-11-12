import { forwardRef, type InputHTMLAttributes } from "react";
import { cn } from "../lib/cn";

export type CalendarProps = Omit<InputHTMLAttributes<HTMLInputElement>, "type">;
export const Calendar = forwardRef<HTMLInputElement, CalendarProps>(function Calendar({ className, ...props }, ref) { return <input {...props} ref={ref} type="date" className={cn("ob-calendar", className)} />; });
Calendar.displayName = "Calendar";
