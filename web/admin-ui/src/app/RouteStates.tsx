import type { ReactNode } from "react";
import { AppForbiddenPage, AppNotFoundPage } from "@openbastion/ui";
import { useAppTranslation } from "../shared/i18n";
import { useCapabilities } from "../shared/capabilities";
import { tabAllowed, tabNeeds, type Tab } from "./navigation";

// ADR-0137 §5: a destination the caller has no capability for answers with an explicit 403 that
// names the capability, never with another screen. A route guard protects nothing: the server
// stays the authority (ADR-0131 §6).
export function CapabilityGate({ tab, children }: { tab: Tab; children: ReactNode }) {
  const { t } = useAppTranslation();
  const capabilities = useCapabilities();
  if (tabAllowed(capabilities, tab)) return <>{children}</>;
  return (
    <AppForbiddenPage
      title={t("shell.forbidden.title")}
      detail={t("shell.forbidden.detail", { capability: tabNeeds(tab).join(", ") })}
    />
  );
}

export function NotFound() {
  const { t } = useAppTranslation();
  return <AppNotFoundPage title={t("shell.notFound.title")} detail={t("shell.notFound.detail")} />;
}
