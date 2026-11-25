import { AppCapabilityButton, type ButtonProps } from "@openbastion/ui";
import { Capability, useCapabilities } from "../capabilities";
import { useAppTranslation } from "../i18n";

// An action button that follows the caller's capabilities (ADR-0131): enabled when the server
// said the caller may take the action, greyed otherwise, with what it needs in its title and
// its accessible description. `extraAllowed` opens it for a reason the capability does not
// cover (the requester terminating their own session, for instance). The server still decides.
// The capability model stays here; the generic button is AppCapabilityButton in @openbastion/ui.
export function GatedButton({
  capability,
  extraAllowed = false,
  ...props
}: ButtonProps & { capability: Capability; extraAllowed?: boolean }) {
  const { t } = useAppTranslation();
  const { can, status } = useCapabilities();
  const allowed = extraAllowed || can(capability);
  const reason = allowed
    ? undefined
    : status === "ready"
      ? t("capabilities.missing", { name: t(`capabilities.names.${capability.replace(".", "_")}`) })
      : t("capabilities.unknown");
  return <AppCapabilityButton {...props} allowed={allowed} reason={reason} data-capability-missing={allowed ? undefined : capability} />;
}
