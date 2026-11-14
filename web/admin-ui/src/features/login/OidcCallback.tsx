import { useEffect, useRef, useState } from "react";
import { Api } from "../../shared/api";
import { Notice } from "../../shared/Notice";
import { useAppTranslation } from "../../shared/i18n";

// The return page of a federated login (ADR-0036 rule 6): code and state are read, wiped from
// the address bar before anything else — they are not left in the history — then sent to the
// Gateway, once.
export function OidcCallback({ api, onToken, location }: { api: Api; onToken: (t: string) => void; location: Location }) {
  const { t } = useAppTranslation();
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
      setError(new Error(providerError ? t("login.oidc.refused") : t("login.oidc.incomplete")));
      return;
    }
    api
      .request<{ accessToken: string }>("POST", "/auth/oidc/callback", { code, state })
      .then((r) => onToken(r.accessToken))
      .catch(setError);
  }, [api, onToken, location, t]);
  return (
    <main className="login">
      <div className="ob-surface ob-panel login-card">
        <h1>OpenBastion</h1>
        {error ? <Notice error={error} /> : <p className="ob-hint">{t("login.oidc.pending")}</p>}
        {error ? <a href="/ui/">{t("secondFactor.restart")}</a> : null}
      </div>
    </main>
  );
}
