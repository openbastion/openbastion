import { forwardRef, type ButtonHTMLAttributes } from "react";

export type ButtonVariant = "primary" | "secondary" | "danger" | "ghost" | "icon";

export type ButtonProps = ButtonHTMLAttributes<HTMLButtonElement> & {
  variant?: ButtonVariant;
};

export const Button = forwardRef<HTMLButtonElement, ButtonProps>(function Button(
  { variant = "secondary", type = "button", className, ...props },
  ref,
) {
  const classes = ["ob-button", `ob-button--${variant}`, className].filter(Boolean).join(" ");
  return <button {...props} ref={ref} type={type} className={classes} />;
});
