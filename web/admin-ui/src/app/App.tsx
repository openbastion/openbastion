import { ReactNode, useCallback, useEffect, useMemo, useRef, useState } from "react";
import { BrowserRouter, MemoryRouter, Navigate, Route, Routes, useLocation, useNavigate, useParams } from "react-router";
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
import type { View as AccountsView } from "../features/accounts/Accounts";
import type { View as SessionsView } from "../features/sessions/Sessions";
import type { View as AuditView } from "../features/audit/AuditCompliance";
import type { SettingsTab } from "../features/settings/Settings";
import { LegalNotice } from "../shared/LegalNotice";
import { AppShell } from "./AppShell";
import { Tab, routerBasename, tabAllowed, tabFromPath, tabPath, viewPath, destinations } from "./navigation";
import { CapabilityGate, NotFound, RouteBoundary, ViewGate } from "./RouteStates";
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
  const [sessionLookup, setSessionLookup] = useState<string | null>(null);
  const goTo = useCallback((next: Tab | "policies") => {
    if (next === "policies") {
      navigate(viewPath("accounts", "policies"));
      return;
    }
    navigate(tabPath(next));
  }, [navigate]);
  const findSession = useCallback((id: string) => {
    navigate(viewPath("sessions", "live"));
    setSessionLookup(id);
  }, [navigate]);
  const clearSessionLookup = useCallback(() => setSessionLookup(null), []);

  // ADR-0137 §4: the tabs of Accès privilégiés, Sessions and Audit & conformité are sub-routes;
  // the tab shown is the address, and choosing one navigates.
  // A tab fires its change on press AND on focus, before the router has re-rendered: only an address
  // other than the last one asked for is a history entry.
  const requested = useRef(pathname);
  requested.current = pathname;
  const toView = (tab: Tab) => (view: string) => {
    const to = viewPath(tab, view);
    if (to === requested.current) return;
    requested.current = to;
    navigate(to);
  };
  const screens: Record<Tab, (view?: string) => ReactNode> = {
    overview: () => <Overview onNavigate={goTo} />,
    accounts: (view) => <Accounts onNavigate={goTo} view={view as AccountsView} onViewChange={toView("accounts")} />,
    sessions: (view) => <Sessions requestedSessionId={sessionLookup} onSessionLookupComplete={clearSessionLookup} view={view as SessionsView} onViewChange={toView("sessions")} />,
    infrastructure: () => <Infrastructure onNavigate={goTo} />,
    security: (view) => <AuditCompliance onNavigate={goTo} view={view as AuditView} onViewChange={toView("security")} />,
    posture: () => <SecurityCenter />,
    settings: (view) => <Settings view={view as SettingsTab} onViewChange={toView("settings")} />,
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
        {destinations.map((destination) =>
          destination.views ? (
            [
              <Route key={destination.id} path={destination.path} element={<Navigate to={viewPath(destination.id, destination.views[0].id)} replace />} />,
              <Route
                key={`${destination.id}/view`}
                path={`${destination.path}/:view`}
                element={<RouteBoundary routeKey={pathname}><ViewRoute tab={destination.id} render={screens[destination.id]} /></RouteBoundary>}
              />,
            ]
          ) : (
            <Route
              key={destination.id}
              path={destination.path}
              element={<RouteBoundary routeKey={pathname}><CapabilityGate tab={destination.id}>{screens[destination.id]()}</CapabilityGate></RouteBoundary>}
            />
          ),
        )}
        <Route path="*" element={<RouteBoundary routeKey={pathname}><NotFound /></RouteBoundary>} />
      </Routes>
    </AppShell>
  );
}

// `/access/:view`, `/sessions/:view`, `/audit/:view`: the destination's gate, then the tab's.
function ViewRoute({ tab, render }: { tab: Tab; render: (view?: string) => ReactNode }) {
  const { view } = useParams();
  return (
    <CapabilityGate tab={tab}>
      <ViewGate tab={tab} view={view}>{render(view)}</ViewGate>
    </CapabilityGate>
  );
}
