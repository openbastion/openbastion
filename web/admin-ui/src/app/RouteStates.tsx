import type { ReactNode } from "react";
import { AppErrorBoundary, AppForbiddenPage, AppNotFoundPage } from "@openbastion/ui";
import { useAppTranslation } from "../shared/i18n";
import { useCapabilities } from "../shared/capabilities";
import { tabAllowed, tabNeeds, viewOf, type Tab } from "./navigation";

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

// A sub-route (a tab of the page): unknown view = 404, a view the caller has no capability for =
// the same explicit 403 as a destination, naming what it needs (ADR-0137 §5).
export function ViewGate({ tab, view, children }: { tab: Tab; view: string | undefined; children: ReactNode }) {
  const { t } = useAppTranslation();
  const capabilities = useCapabilities();
  const declared = viewOf(tab, view);
  if (!declared) return <NotFound />;
  const needs = declared.needs ?? tabNeeds(tab);
  if (needs.length === 0 || capabilities.visible(...needs)) return <>{children}</>;
  return (
    <AppForbiddenPage
      title={t("shell.forbidden.title")}
      detail={t("shell.forbidden.detail", { capability: needs.join(", ") })}
    />
  );
}

// ADR-0137 §5: one error boundary per route. A render error in a screen shows an explicit,
// recoverable state inside the shell (navigation stays usable) instead of a blank page. The
// error message is never printed: it may carry sensitive text. The boundary clears itself when
// the address changes, so a failed screen does not keep the next one hostage.
export function RouteBoundary({ routeKey, children }: { routeKey: string; children: ReactNode }) {
  const { t } = useAppTranslation();
  return (
    <AppErrorBoundary
      resetKeys={[routeKey]}
      fallback={(_error, reset) => (
        <div role="alert" className="route-error">
          <h2>{t("shell.routeError.title")}</h2>
          <p>{t("shell.routeError.detail")}</p>
          <button type="button" className="ob-button ob-button--secondary" onClick={reset}>{t("common.actions.retry")}</button>
        </div>
      )}
    >
      {children}
    </AppErrorBoundary>
  );
}
