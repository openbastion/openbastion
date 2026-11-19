import { Button, type ButtonProps } from "@openbastion/ui";
import { Capability, useCapabilities } from "../capabilities";
import { useAppTranslation } from "../i18n";

// An action button that follows the caller's capabilities (ADR-0131): enabled when the server
// said the caller may take the action, greyed otherwise, with what it needs in its title and
// its accessible description. `extraAllowed` opens it for a reason the capability does not
// cover (the requester terminating their own session, for instance). The server still decides.
export function GatedButton({
  capability,
  extraAllowed = false,
  disabled,
  title,
  ...props
}: ButtonProps & { capability: Capability; extraAllowed?: boolean }) {
  const { t } = useAppTranslation();
  const { can, status } = useCapabilities();
  const allowed = extraAllowed || can(capability);
  if (allowed) return <Button {...props} disabled={disabled} title={title} />;
  const reason = status === "ready"
    ? t("capabilities.missing", { name: t(`capabilities.names.${capability.replace(".", "_")}`) })
    : t("capabilities.unknown");
  return (
    <span className="ob-gated-action" title={reason} data-capability-missing={capability}>
      <Button {...props} disabled aria-description={reason} />
    </span>
  );
}
