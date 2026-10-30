import { useEffect, useRef, useState } from "react";
import { Api } from "../../shared/api";
import { Notice } from "../../shared/Notice";

// The return page of a federated login (ADR-0036 rule 6): code and state are read, wiped from
// the address bar before anything else — they are not left in the history — then sent to the
// Gateway, once.
export function OidcCallback({ api, onToken, location }: { api: Api; onToken: (t: string) => void; location: Location }) {
  const [error, setError] = useState<unknown>();
  const sent = useRef(false);
  useEffect(() => {
    if (sent.current) return;
    sent.current = true;
    const q = new URLSearchParams(location.search);
    const code = q.get("code") ?? "";
    const state = q.get("state") ?? "";
    const providerError = q.get("error");
    window.history.replaceState(null, "", "/ui/");
    if (providerError || !code || !state) {
      setError(new Error(providerError ? "le fournisseur a refusé la connexion" : "retour du fournisseur incomplet"));
      return;
    }
    api
      .request<{ accessToken: string }>("POST", "/auth/oidc/callback", { code, state })
      .then((r) => onToken(r.accessToken))
      .catch(setError);
  }, [api, onToken, location]);
  return (
    <main className="login">
      <h1>OpenBastion</h1>
      {error ? <Notice error={error} /> : <p>Connexion en cours…</p>}
      {error ? <a href="/ui/">Recommencer</a> : null}
    </main>
  );
}
