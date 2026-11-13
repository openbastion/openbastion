import { cloneElement, forwardRef, isValidElement, type FormHTMLAttributes, type HTMLAttributes, type ReactElement, type ReactNode } from "react";
import { cn } from "../lib/cn";

export type FormProps = FormHTMLAttributes<HTMLFormElement>;
export const Form = forwardRef<HTMLFormElement, FormProps>(function Form({ className, ...props }, ref) {
  return <form {...props} ref={ref} className={cn("ob-form", className)} />;
});
Form.displayName = "Form";

export type FormFieldProps = {
  id: string;
  label: ReactNode;
  description?: ReactNode;
  error?: ReactNode;
  required?: boolean;
  className?: string;
  children: ReactNode;
};
export function FormField({ id, label, description, error, required = false, className, children }: FormFieldProps) {
  const descriptionId = description ? `${id}-description` : undefined;
  const errorId = error ? `${id}-error` : undefined;
  return (
    <div className={cn("ob-form-field", className)}>
      <label className="ob-form-field__label" htmlFor={id}>
        {label}{required ? <span aria-hidden="true"> *</span> : null}
      </label>
      {isValidElement(children)
        ? cloneElement(children as ReactElement<Record<string, unknown>>, {
            id,
            "aria-describedby": [descriptionId, errorId].filter(Boolean).join(" ") || undefined,
            "aria-invalid": error ? true : undefined,
            required,
          })
        : children}
      {description ? <div className="ob-form-field__description" id={descriptionId}>{description}</div> : null}
      {error ? <div className="ob-form-field__error" id={errorId} role="alert">{error}</div> : null}
    </div>
  );
}

export type FormDescriptionProps = HTMLAttributes<HTMLParagraphElement>;
export function FormDescription({ className, ...props }: FormDescriptionProps) {
  return <p {...props} className={cn("ob-form-description", className)} />;
}
