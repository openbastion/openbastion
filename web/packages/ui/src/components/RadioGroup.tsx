import { createContext, forwardRef, useContext, useId, useState, type FieldsetHTMLAttributes, type InputHTMLAttributes, type ReactNode } from "react";
import { cn } from "../lib/cn";

type RadioGroupContextValue = {
  name: string;
  value: string | undefined;
  disabled: boolean;
  select: (value: string) => void;
};
const RadioGroupContext = createContext<RadioGroupContextValue | null>(null);

export type RadioGroupProps = Omit<FieldsetHTMLAttributes<HTMLFieldSetElement>, "onChange"> & {
  name?: string;
  value?: string;
  defaultValue?: string;
  onValueChange?: (value: string) => void;
  disabled?: boolean;
  label?: ReactNode;
  orientation?: "horizontal" | "vertical";
};
export function RadioGroup({ name, value, defaultValue, onValueChange, disabled = false, label, orientation = "vertical", className, children, ...props }: RadioGroupProps) {
  const generatedName = useId();
  const [internalValue, setInternalValue] = useState(defaultValue);
  const selected = value === undefined ? internalValue : value;
  const select = (next: string) => {
    if (disabled) return;
    if (value === undefined) setInternalValue(next);
    onValueChange?.(next);
  };
  return (
    <RadioGroupContext.Provider value={{ name: name ?? generatedName, value: selected, disabled, select }}>
      <fieldset {...props} disabled={disabled} className={cn("ob-radio-group", `ob-radio-group--${orientation}`, className)}>
        {label ? <legend className="ob-radio-group__legend">{label}</legend> : null}
        {children}
      </fieldset>
    </RadioGroupContext.Provider>
  );
}

export type RadioGroupItemProps = Omit<InputHTMLAttributes<HTMLInputElement>, "type" | "name" | "value" | "checked" | "defaultChecked" | "onChange"> & {
  value: string;
  label: ReactNode;
};
export const RadioGroupItem = forwardRef<HTMLInputElement, RadioGroupItemProps>(function RadioGroupItem({ value, label, id, className, ...props }, ref) {
  const context = useContext(RadioGroupContext);
  if (!context) throw new Error("RadioGroupItem doit être utilisé dans RadioGroup.");
  const generatedId = useId();
  const inputId = id ?? generatedId;
  return (
    <label className={cn("ob-radio-group__item", className)} htmlFor={inputId}>
      <input {...props} ref={ref} id={inputId} type="radio" name={context.name} value={value} checked={context.value === value} disabled={context.disabled || props.disabled} onChange={() => context.select(value)} className="ob-radio-group__control" />
      <span>{label}</span>
    </label>
  );
});
RadioGroupItem.displayName = "RadioGroupItem";
