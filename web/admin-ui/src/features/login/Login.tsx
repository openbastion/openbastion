import { FormEvent, useState } from "react";
import { Api } from "../../shared/api";
import { SecondFactor } from "./SecondFactor";
import { Challenge, mfaChallenge, useLoginSources } from "./sources";
import { Notice } from "../../shared/Notice";
import { BrandMark } from "../../shared/BrandMark";

// "local", or "ldap:<id>" ("ldap:" for the directory of the LDAP_* variables, whose id is empty).
type Source = string;

// Login: a local account (POST /auth/login), one of the organisation's directories when the Gateway
// lists them (POST /auth/ldap/login, ADR-0061), or one of its providers (ADR-0035). With several,
// each is named by its id (ADR-0076): the page never picks one for the user.
export function Login({ api, onToken, navigate }: { api: Api; onToken: (t: string) => void; navigate: (url: string) => void }) {
  const { directories, oidc } = useLoginSources(api);
  const [choice, setChoice] = useState<Source | null>(null);
  // Derived, not set by an effect: the choice shown is the one a submit uses, at every render.
  const source: Source = choice ?? (directories.length > 0 ? "ldap:" + directories[0].id : "local");
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<unknown>();
  const [busy, setBusy] = useState(false);
  const [challenge, setChallenge] = useState<Challenge | null>(null);

  async function local(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(undefined);
    try {
      // A directory is always the one chosen, by its id; "" is the directory of the LDAP_* variables.
      const directory = source.startsWith("ldap:") ? source.slice("ldap:".length) : null;
      const body = directory ? { directory, username, password } : { username, password };
      const r = await api.request<{ accessToken: string }>("POST", directory === null ? "/auth/login" : "/auth/ldap/login", body);
      setPassword("");
      onToken(r.accessToken);
    } catch (err) {
      const mfa = mfaChallenge(err);
      if (mfa) {
        setPassword("");
        setChallenge(mfa);
        return;
      }
      setError(err);
    } finally {
      setBusy(false);
    }
  }

  async function federated(provider: string) {
    setBusy(true);
    setError(undefined);
    try {
      const r = await api.request<{ authorizationUrl: string }>("POST", "/auth/oidc/start", provider ? { provider } : undefined);
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
        {challenge ? (
          <SecondFactor api={api} challenge={challenge} onToken={onToken} onCancel={() => setChallenge(null)} />
        ) : (
          <>
            <form onSubmit={local} aria-label={source === "local" ? "Connexion locale" : "Connexion par l'annuaire"}>
              {directories.length > 0 && (
                <fieldset className="login-source">
                  <legend>Compte</legend>
                  {[...directories.map((d) => ({ s: "ldap:" + d.id, label: d.label || "Annuaire de l'entreprise" })), { s: "local", label: "Compte local" }].map(
                    ({ s, label }) => (
                      <label key={s} className="inline">
                        <input type="radio" name="source" value={s} checked={source === s} onChange={() => setChoice(s)} />
                        {label}
                      </label>
                    ),
                  )}
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
              <button type="submit" className="primary" disabled={busy}>
                Se connecter
              </button>
            </form>
            {(oidc === null || oidc.length > 0) && <p className="or">ou</p>}
            {(oidc ?? [{ id: "", label: "" }]).map((p) => (
              <button key={p.id} type="button" onClick={() => federated(p.id)} disabled={busy}>
                {p.label ? `Se connecter avec ${p.label}` : "Se connecter avec le fournisseur d'identité"}
              </button>
            ))}
          </>
        )}
        <Notice error={error} />
      </div>
    </main>
  );
}
