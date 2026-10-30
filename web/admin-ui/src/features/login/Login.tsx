import { FormEvent, useState } from "react";
import { Api } from "../../shared/api";
import { Notice } from "../../shared/Notice";
import { BrandMark } from "../../shared/BrandMark";

// Login: a local account (POST /auth/login), or the organisation's provider (ADR-0035).
export function Login({ api, onToken, navigate }: { api: Api; onToken: (t: string) => void; navigate: (url: string) => void }) {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<unknown>();
  const [busy, setBusy] = useState(false);

  async function local(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(undefined);
    try {
      const r = await api.request<{ accessToken: string }>("POST", "/auth/login", { username, password });
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
        <form onSubmit={local} aria-label="Connexion locale">
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
