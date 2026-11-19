import { createContext, forwardRef, useContext, useState, type HTMLAttributes, type ReactNode } from "react";
import { cn } from "../lib/cn";
import { Toggle, type ToggleProps } from "./Toggle";

type ToggleGroupContextValue = { type: "single" | "multiple"; values: string[]; select: (value: string) => void; disabled: boolean };
const ToggleGroupContext = createContext<ToggleGroupContextValue | null>(null);
export type ToggleGroupProps = Omit<HTMLAttributes<HTMLDivElement>, "onChange"> & { type: "single" | "multiple"; value?: string | string[]; defaultValue?: string | string[]; onValueChange?: (value: string | string[]) => void; disabled?: boolean; children: ReactNode };
export function ToggleGroup({ type, value, defaultValue, onValueChange, disabled = false, className, children, ...props }: ToggleGroupProps) {
  const initial = Array.isArray(defaultValue) ? defaultValue : defaultValue ? [defaultValue] : [];
  const [internal, setInternal] = useState(initial);
  const values = value === undefined ? internal : Array.isArray(value) ? value : value ? [value] : [];
  const select = (next: string) => { if (disabled) return; const updated = type === "single" ? (values.includes(next) ? [] : [next]) : values.includes(next) ? values.filter((entry) => entry !== next) : [...values, next]; if (value === undefined) setInternal(updated); onValueChange?.(type === "single" ? (updated[0] ?? "") : updated); };
  return <ToggleGroupContext.Provider value={{ type, values, select, disabled }}><div {...props} role="group" className={cn("ob-toggle-group", className)}>{children}</div></ToggleGroupContext.Provider>;
}
export type ToggleGroupItemProps = Omit<ToggleProps, "pressed" | "onPressedChange"> & { value: string };
export const ToggleGroupItem = forwardRef<HTMLButtonElement, ToggleGroupItemProps>(function ToggleGroupItem({ value, className, onClick, ...props }, ref) {
  const context = useContext(ToggleGroupContext);
  if (!context) throw new Error("ToggleGroupItem doit être utilisé dans ToggleGroup.");
  const active = context.values.includes(value);
  return <Toggle {...props} ref={ref} pressed={active} disabled={context.disabled || props.disabled} className={cn("ob-toggle", className)} onClick={onClick} onPressedChange={() => context.select(value)} />;
});
ToggleGroupItem.displayName = "ToggleGroupItem";
