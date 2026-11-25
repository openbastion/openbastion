import { forwardRef } from "react";
import { Button, type ButtonProps } from "../components/Button";

export type AppCapabilityButtonProps = ButtonProps & {
  // Decided by the application from ITS capability model; the package knows no capability name.
  allowed: boolean;
  // Why it is greyed (title and accessible description). Required when not allowed.
  reason?: string;
};

// An action that follows the caller's rights: enabled when allowed, otherwise greyed with the
// reason in its title and accessible description. A hint, never protection: the server decides.
export const AppCapabilityButton = forwardRef<HTMLButtonElement, AppCapabilityButtonProps>(
  function AppCapabilityButton({ allowed, reason, disabled, ...props }, ref) {
    if (allowed) return <Button {...props} ref={ref} disabled={disabled} />;
    return (
      <span className="ob-gated-action" title={reason}>
        <Button {...props} ref={ref} disabled aria-description={reason} />
      </span>
    );
  },
);
