import { FormEvent, useEffect, useState } from "react";
import { Api } from "../../shared/api";
import { Notice } from "../../shared/Notice";
import { BrandMark } from "../../shared/BrandMark";

// Login: a local account (POST /auth/login), the organisation's directory when the Gateway says it
// is on (POST /auth/ldap/login, ADR-0061), or the organisation's provider (ADR-0035).
type Source = "local" | "ldap";
const loginPath: Record<Source, string> = { local: "/auth/login", ldap: "/auth/ldap/login" };

export function Login({ api, onToken, navigate }: { api: Api; onToken: (t: string) => void; navigate: (url: string) => void }) {
  const [directory, setDirectory] = useState(false);
  const [choice, setChoice] = useState<Source | null>(null);
  // Derived, not set by an effect: the choice shown is the one a submit uses, at every render.
  const source: Source = choice ?? (directory ? "ldap" : "local");
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<unknown>();
  const [busy, setBusy] = useState(false);

  // Whether directory login is on: when it is, it is the default, unless a choice was made.
  useEffect(() => {
    let live = true;
    api
      .request<{ enabled: boolean }>("GET", "/auth/ldap")
      .then((r) => {
        if (live && r.enabled) setDirectory(true);
      })
      .catch(() => {}); // unknown: local login only, as before
    return () => {
      live = false;
    };
  }, [api]);

  async function local(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(undefined);
    try {
      const r = await api.request<{ accessToken: string }>("POST", loginPath[source], { username, password });
      setPassword("");
      onToken(r.accessToken);
    } catch (err) {
      setError(err);
    } finally {
      setBusy(false);
    }
  }

  async function federated() {
    setBusy(true);
    setError(undefined);
    try {
      const r = await api.request<{ authorizationUrl: string }>("POST", "/auth/oidc/start");
      navigate(r.authorizationUrl);
    } catch (err) {
      setError(err);
      setBusy(false);
    }
  }

  return (
    <main className="login">
      <div className="login-card">
        <div className="login-head">
          <BrandMark />
          <div>
            <h1>OpenBastion</h1>
            <p className="login-sub">Console d'administration des accès privilégiés</p>
          </div>
        </div>
        <form onSubmit={local} aria-label={source === "ldap" ? "Connexion par l'annuaire" : "Connexion locale"}>
          {directory && (
            <fieldset className="login-source">
              <legend>Compte</legend>
              {(["ldap", "local"] as Source[]).map((s) => (
                <label key={s} className="inline">
                  <input
                    type="radio"
                    name="source"
                    value={s}
                    checked={source === s}
                    onChange={() => setChoice(s)}
                  />
                  {s === "ldap" ? "Annuaire de l'entreprise" : "Compte local"}
                </label>
              ))}
            </fieldset>
          )}
          <label>
            Utilisateur
            <input name="username" autoComplete="username" value={username} onChange={(e) => setUsername(e.target.value)} required />
          </label>
          <label>
            Mot de passe
            <input name="password" type="password" autoComplete="current-password" value={password} onChange={(e) => setPassword(e.target.value)} required />
          </label>
          <button type="submit" className="primary" disabled={busy}>Se connecter</button>
        </form>
        <p className="or">ou</p>
        <button type="button" onClick={federated} disabled={busy}>Se connecter avec le fournisseur d'identité</button>
        <Notice error={error} />
      </div>
    </main>
  );
}
