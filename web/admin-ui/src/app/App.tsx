import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { Api, claims } from "../shared/api";
import { SignedInContext } from "../shared/session";
import { Login } from "../features/login/Login";
import { OidcCallback } from "../features/login/OidcCallback";
import { Accounts } from "../features/accounts/Accounts";
import { Overview } from "../features/overview/Overview";
import { AuditCompliance } from "../features/audit/AuditCompliance";
import { SecurityCenter } from "../features/security/SecurityCenter";
import { Infrastructure } from "../features/infrastructure/Infrastructure";
import { Settings } from "../features/settings/Settings";
import { Sessions } from "../features/sessions/Sessions";
import { LegalNotice } from "../shared/LegalNotice";
import { AppShell, Tab } from "./AppShell";
import { tabAllowed } from "./tabAccess";
import { readOperatorPreferences } from "../shared/operatorPreferences";
import { Capabilities, CapabilitiesContext, capabilitiesFrom, parseCapabilities } from "../shared/capabilities";

export function App({
  api: given,
  location = window.location,
  navigate = (u: string) => window.location.assign(u),
}: {
  api?: Api;
  location?: Location;
  navigate?: (u: string) => void;
}) {
  // ONE client for the life of the page: a default made at each render would lose the token set
  // at login, and every call after it would go out without one (found and fixed in main.tsx by
  // Bony Kiss's environment work; kept here so that the component cannot fall into it again).
  const own = useRef<Api | null>(null);
  if (!given && !own.current) own.current = new Api();
  const api = given ?? own.current!;
  const [token, setToken] = useState<string | null>(null);
  const [tab, setTab] = useState<Tab>(() => readOperatorPreferences().defaultTab);
  const [accountsInitialView, setAccountsInitialView] = useState<"resources" | "accounts" | "policies" | "requests">("resources");
  const [sessionLookup, setSessionLookup] = useState<string | null>(null);
  const onToken = useCallback(
    (t: string) => {
      api.setToken(t);
      setToken(t);
    },
    [api],
  );
  const navigateToTab = useCallback((next: Tab | "policies") => {
    if (next === "policies") {
      setAccountsInitialView("policies");
      setTab("accounts");
      return;
    }
    setTab(next);
  }, []);
  const findSession = useCallback((id: string) => {
    setTab("sessions");
    setSessionLookup(id);
  }, []);
  const clearSessionLookup = useCallback(() => setSessionLookup(null), []);
  const signOut = useCallback(() => {
    api.setToken(null);
    setToken(null);
  }, [api]);
  const who = useMemo(() => (token ? claims(token) : null), [token]);
  // ADR-0131: the caller's capabilities, read once per token. Until they answer, and if they
  // cannot be read, gated actions are greyed (capabilitiesFrom fails closed for actions).
  const [capabilities, setCapabilities] = useState<Capabilities>(() => capabilitiesFrom("loading"));
  useEffect(() => {
    if (!token) return;
    let current = true;
    setCapabilities(capabilitiesFrom("loading"));
    api.request<unknown>("GET", "/auth/me/capabilities")
      .then((body) => { if (current) setCapabilities(capabilitiesFrom("ready", parseCapabilities(body))); })
      .catch(() => { if (current) setCapabilities(capabilitiesFrom("unavailable")); });
    return () => { current = false; };
  }, [api, token]);

  // A page the caller has no capability for is not rendered, even when the stored default
  // or a link asks for it: the overview stands in.
  const shownTab: Tab = tabAllowed(capabilities, tab) ? tab : "overview";

  if (!token) {
    if (location.pathname.startsWith("/ui/oidc/callback"))
      return (
        <>
          <OidcCallback api={api} onToken={onToken} location={location} />
          <LegalNotice />
        </>
      );
    return <Login api={api} onToken={onToken} navigate={navigate} />;
  }
  return (
    <SignedInContext.Provider value={{ api, who, signOut }}>
      <CapabilitiesContext.Provider value={capabilities}>
      <AppShell who={who} tab={shownTab} onTab={setTab} onDefaultTabChange={setTab} onSignOut={signOut} onFindSession={findSession}>
        {shownTab === "overview" && <Overview onNavigate={navigateToTab} />}
        {shownTab === "accounts" && <Accounts onNavigate={navigateToTab} initialView={accountsInitialView} />}
        {shownTab === "sessions" && <Sessions requestedSessionId={sessionLookup} onSessionLookupComplete={clearSessionLookup} />}
        {shownTab === "infrastructure" && <Infrastructure onNavigate={navigateToTab} />}
        {shownTab === "security" && <AuditCompliance onNavigate={navigateToTab} />}
        {shownTab === "posture" && <SecurityCenter />}
        {shownTab === "settings" && <Settings />}
      </AppShell>
      </CapabilitiesContext.Provider>
    </SignedInContext.Provider>
  );
}
