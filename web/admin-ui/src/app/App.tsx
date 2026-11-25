import { ReactNode, useCallback, useEffect, useMemo, useRef, useState } from "react";
import { BrowserRouter, MemoryRouter, Navigate, Route, Routes, useLocation, useNavigate } from "react-router";
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
import { AppShell } from "./AppShell";
import { Tab, routerBasename, tabAllowed, tabFromPath, tabPath, destinations } from "./navigation";
import { CapabilityGate, NotFound } from "./RouteStates";
import type { TokenClaims } from "../shared/api";
import { readOperatorPreferences } from "../shared/operatorPreferences";
import { Capabilities, CapabilitiesContext, capabilitiesFrom, parseCapabilities } from "../shared/capabilities";

export function App({
  api: given,
  location = window.location,
  navigate = (u: string) => window.location.assign(u),
  initialEntries,
}: {
  api?: Api;
  location?: Location;
  navigate?: (u: string) => void;
  initialEntries?: string[];
}) {
  // ONE client for the life of the page: a default made at each render would lose the token set
  // at login, and every call after it would go out without one (found and fixed in main.tsx by
  // Bony Kiss's environment work; kept here so that the component cannot fall into it again).
  const own = useRef<Api | null>(null);
  if (!given && !own.current) own.current = new Api();
  const api = given ?? own.current!;
  const [token, setToken] = useState<string | null>(null);
  const onToken = useCallback(
    (t: string) => {
      api.setToken(t);
      setToken(t);
    },
    [api],
  );
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
    <Router initialEntries={initialEntries}>
      <SignedInContext.Provider value={{ api, who, signOut }}>
        <CapabilitiesContext.Provider value={capabilities}>
          <SignedInRoutes who={who} capabilities={capabilities} onSignOut={signOut} />
        </CapabilitiesContext.Provider>
      </SignedInContext.Provider>
    </Router>
  );
}

// BrowserRouter in the page (basename = Vite's BASE_URL, ADR-0137 §2); tests may give a history.
function Router({ initialEntries, children }: { initialEntries?: string[]; children: ReactNode }) {
  if (initialEntries) return <MemoryRouter initialEntries={initialEntries}>{children}</MemoryRouter>;
  return <BrowserRouter basename={routerBasename}>{children}</BrowserRouter>;
}

// The destination lives in the URL, not in React state: it can be shared, survives a reload (after
// the sign-in, which returns to the SAME address because the sign-in screen is not a route) and
// the Back/Forward buttons walk it.
function SignedInRoutes({ who, capabilities, onSignOut }: { who: TokenClaims | null; capabilities: Capabilities; onSignOut: () => void }) {
  const navigate = useNavigate();
  const { pathname } = useLocation();
  const [accountsInitialView, setAccountsInitialView] = useState<"resources" | "accounts" | "policies" | "requests">("resources");
  const [sessionLookup, setSessionLookup] = useState<string | null>(null);
  const goTo = useCallback((next: Tab | "policies") => {
    if (next === "policies") {
      setAccountsInitialView("policies");
      navigate(tabPath("accounts"));
      return;
    }
    navigate(tabPath(next));
  }, [navigate]);
  const findSession = useCallback((id: string) => {
    navigate(tabPath("sessions"));
    setSessionLookup(id);
  }, [navigate]);
  const clearSessionLookup = useCallback(() => setSessionLookup(null), []);

  const screens: Record<Tab, ReactNode> = {
    overview: <Overview onNavigate={goTo} />,
    accounts: <Accounts onNavigate={goTo} initialView={accountsInitialView} />,
    sessions: <Sessions requestedSessionId={sessionLookup} onSessionLookupComplete={clearSessionLookup} />,
    infrastructure: <Infrastructure onNavigate={goTo} />,
    security: <AuditCompliance onNavigate={goTo} />,
    posture: <SecurityCenter />,
    settings: <Settings />,
  };
  // The stored default screen opens at "/"; one the caller may not see falls back to the overview.
  const defaultTab = readOperatorPreferences().defaultTab;
  const landing = tabAllowed(capabilities, defaultTab) ? defaultTab : "overview";

  return (
    <AppShell
      who={who}
      tab={tabFromPath(pathname) ?? null}
      onTab={goTo}
      onDefaultTabChange={goTo}
      onSignOut={onSignOut}
      onFindSession={findSession}
    >
      <Routes>
        <Route path="/" element={<Navigate to={tabPath(landing)} replace />} />
        {destinations.map((destination) => (
          <Route
            key={destination.id}
            path={destination.path}
            element={<CapabilityGate tab={destination.id}>{screens[destination.id]}</CapabilityGate>}
          />
        ))}
        <Route path="*" element={<NotFound />} />
      </Routes>
    </AppShell>
  );
}
