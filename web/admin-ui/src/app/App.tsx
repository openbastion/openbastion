import { useCallback, useMemo, useRef, useState } from "react";
import { Api, claims } from "../shared/api";
import { SignedInContext } from "../shared/session";
import { Login } from "../features/login/Login";
import { OidcCallback } from "../features/login/OidcCallback";
import { Accounts } from "../features/accounts/Accounts";
import { Policies } from "../features/policies/Policies";
import { Sessions } from "../features/sessions/Sessions";
import { Recording } from "../features/audit/Recording";

const tabs = { accounts: "Comptes", policies: "Politiques", sessions: "Sessions", audit: "Enregistrements" } as const;
type Tab = keyof typeof tabs;

export function App({ api: given, location = window.location, navigate = (u: string) => window.location.assign(u) }: { api?: Api; location?: Location; navigate?: (u: string) => void }) {
  // ONE client for the life of the page: a default made at each render would lose the token set
  // at login, and every call after it would go out without one (found and fixed in main.tsx by
  // Bony Kiss's environment work; kept here so that the component cannot fall into it again).
  const own = useRef<Api | null>(null);
  if (!given && !own.current) own.current = new Api();
  const api = given ?? own.current!;
  const [token, setToken] = useState<string | null>(null);
  const [tab, setTab] = useState<Tab>("accounts");
  const onToken = useCallback((t: string) => {
    api.setToken(t);
    setToken(t);
  }, [api]);
  const signOut = useCallback(() => {
    api.setToken(null);
    setToken(null);
  }, [api]);
  const who = useMemo(() => (token ? claims(token) : null), [token]);

  if (!token) {
    if (location.pathname.startsWith("/ui/oidc/callback")) return <OidcCallback api={api} onToken={onToken} location={location} />;
    return <Login api={api} onToken={onToken} navigate={navigate} />;
  }
  return (
    <SignedInContext.Provider value={{ api, who, signOut }}>
      <header>
        <strong>OpenBastion</strong>
        <nav>
          {(Object.keys(tabs) as Tab[]).map((t) => (
            <button type="button" key={t} aria-current={tab === t ? "page" : undefined} onClick={() => setTab(t)}>{tabs[t]}</button>
          ))}
        </nav>
        <span className="who">{who?.username} {who?.roles.length ? `(${who.roles.join(", ")})` : ""}</span>
        <button type="button" onClick={signOut}>Se déconnecter</button>
      </header>
      <main>
        {tab === "accounts" && <Accounts />}
        {tab === "policies" && <Policies />}
        {tab === "sessions" && <Sessions />}
        {tab === "audit" && <Recording />}
      </main>
    </SignedInContext.Provider>
  );
}
