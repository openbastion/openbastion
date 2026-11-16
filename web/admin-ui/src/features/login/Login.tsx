import { FormEvent, useState } from "react";
import { Api } from "../../shared/api";
import { SecondFactor } from "./SecondFactor";
import { Challenge, mfaChallenge, useLoginSources } from "./sources";
import { Notice } from "../../shared/Notice";
import { BrandMark } from "../../shared/BrandMark";
import { Button } from "../../shared/ui/Button";
import { LanguageSwitcher } from "../../shared/ui/LanguageSwitcher";
import { useAppTranslation } from "../../shared/i18n";

// "local", or "ldap:<id>" ("ldap:" for the directory of the LDAP_* variables, whose id is empty).
type Source = string;

// Login: a local account (POST /auth/login), one of the organisation's directories when the Gateway
// lists them (POST /auth/ldap/login, ADR-0061), or one of its providers (ADR-0035). With several,
// each is named by its id (ADR-0076): the page never picks one for the user.
export function Login({ api, onToken, navigate }: { api: Api; onToken: (t: string) => void; navigate: (url: string) => void }) {
  const { t } = useAppTranslation();
  const { directories, oidc } = useLoginSources(api);
  const [choice, setChoice] = useState<Source | null>(null);
  // Derived, not set by an effect: the choice shown is the one a submit uses, at every render.
  const source: Source = choice ?? (directories.length > 0 ? "ldap:" + directories[0].id : "local");
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [showPassword, setShowPassword] = useState(false);
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
      <div className="login-language">
        <LanguageSwitcher />
      </div>
      <div className="login-layout">
        <aside className="login-brand-panel" aria-label={t("login.brand.aria")}>
          <div className="login-brand-lockup">
            <BrandMark className="login-brand-mark" />
            <div>
              <strong>OpenBastion</strong>
              <span>{t("login.brand.product")}</span>
            </div>
          </div>
          <div className="login-brand-message">
            <p className="login-eyebrow">{t("login.brand.eyebrow")}</p>
            <h2>{t("login.brand.title")}</h2>
            <p>{t("login.brand.description")}</p>
          </div>
          <section className="login-security-note" aria-labelledby="login-security-title">
            <h3 id="login-security-title">{t("login.brand.securityTitle")}</h3>
            <ul>
              <li>{t("login.brand.security.mfa")}</li>
              <li>{t("login.brand.security.recording")}</li>
              <li>{t("login.brand.security.secrets")}</li>
            </ul>
          </section>
          <p className="login-brand-footer">{t("login.brand.footer")}</p>
        </aside>
        <div className="login-content">
          <div className="login-card">
            {challenge ? (
              <>
                <div className="login-heading">
                  <p className="login-form-eyebrow">{t("login.secureAccess")}</p>
                  <h1>{t("secondFactor.aria")}</h1>
                  <p className="login-sub">{t("secondFactor.factorRequired")}</p>
                </div>
                <SecondFactor api={api} challenge={challenge} onToken={onToken} onCancel={() => setChallenge(null)} />
              </>
            ) : (
              <>
                <div className="login-heading">
                  <p className="login-form-eyebrow">{t("login.secureAccess")}</p>
                  <h1>{t("login.title")}</h1>
                  <p className="login-sub">{t("login.subtitle")}</p>
                </div>
                {(oidc === null || oidc.length > 0) && (
                  <div className="login-sso">
                    {(oidc ?? [{ id: "", label: "" }]).map((p) => (
                      <Button key={p.id} onClick={() => federated(p.id)} disabled={busy}>
                        <span className="login-sso-icon" aria-hidden="true">↳</span>
                        {p.label ? t("login.withProvider", { provider: p.label }) : t("login.withIdentityProvider")}
                      </Button>
                    ))}
                  </div>
                )}
                <p className="login-divider">{t("login.orWithAccount")}</p>
                <form className="ob-form-fields login-form" onSubmit={local} aria-label={source === "local" ? t("login.formAria.local") : t("login.formAria.directory")}>
                  {directories.length > 0 && (
                    <fieldset className="login-source">
                      <legend>{t("login.source.legend")}</legend>
                      {[...directories.map((d) => ({ s: "ldap:" + d.id, label: d.label || t("login.source.directory") })), { s: "local", label: t("login.source.local") }].map(
                        ({ s, label }) => (
                          <label key={s} className="inline">
                            <input type="radio" name="source" value={s} checked={source === s} onChange={() => setChoice(s)} />
                            {label}
                          </label>
                        ),
                      )}
                    </fieldset>
                  )}
                  <label className="login-field">
                    {t("login.username")}
                    <input name="username" type="text" autoComplete="username" placeholder={t("login.emailPlaceholder")} value={username} onChange={(e) => setUsername(e.target.value)} required />
                  </label>
                  <label className="login-field">
                    <span className="login-field-label">
                      {t("login.password")}
                      <span className="login-field-action" aria-hidden="true">{t("login.forgotPassword")}</span>
                    </span>
                    <span className="login-password-wrap">
                      <input name="password" aria-label={t("login.password")} type={showPassword ? "text" : "password"} autoComplete="current-password" value={password} onChange={(e) => setPassword(e.target.value)} required />
                      <button className="login-password-toggle" type="button" onClick={() => setShowPassword((visible) => !visible)} aria-label={showPassword ? t("login.hidePassword") : t("login.showPassword")}>
                        {showPassword ? t("login.hidePassword") : t("login.showPassword")}
                      </button>
                    </span>
                  </label>
                  <Button type="submit" variant="primary" disabled={busy}>
                    {t("login.submit")}
                  </Button>
                </form>
                <div className="login-assurance">
                  <BrandMark className="login-assurance-icon" />
                  <p>{t("login.additionalVerification")}</p>
                </div>
              </>
            )}
            <Notice error={error} />
          </div>
          <footer className="login-content-footer">
            <p>{t("login.help")}</p>
            <p>{t("login.legal")}</p>
          </footer>
        </div>
      </div>
    </main>
  );
}
