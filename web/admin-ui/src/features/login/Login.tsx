import { FormEvent, useState } from "react";
import { Api } from "../../shared/api";
import { SecondFactor } from "./SecondFactor";
import { Challenge, mfaChallenge, useLoginSources } from "./sources";
import { Notice } from "../../shared/Notice";
import { BrandMark } from "../../shared/BrandMark";
import { Button } from "../../shared/ui/Button";
import { LanguageSwitcher } from "../../shared/ui/LanguageSwitcher";
import { useAppTranslation } from "../../shared/i18n";
import { LegalLinks } from "../../shared/LegalNotice";
import { Checkbox, Form, Input, Label, RadioGroup, RadioGroupItem } from "@openbastion/ui";

// "local", or "ldap:<id>" ("ldap:" for the directory of the LDAP_* variables, whose id is empty).
type Source = string;

const rememberedUsernameKey = "openbastion.login.remembered-username";

function readRememberedUsername(): string {
  try {
    return window.localStorage.getItem(rememberedUsernameKey) ?? "";
  } catch {
    return "";
  }
}

function rememberUsername(username: string | null): void {
  try {
    if (username === null) window.localStorage.removeItem(rememberedUsernameKey);
    else window.localStorage.setItem(rememberedUsernameKey, username);
  } catch {
    // Remembering an identifier is optional; storage denial must never block authentication.
  }
}

// Login: a local account (POST /auth/login), one of the organisation's directories when the Gateway
// lists them (POST /auth/ldap/login, ADR-0061), or one of its providers (ADR-0035). With several,
// each is named by its id (ADR-0076): the page never picks one for the user.
export function Login({ api, onToken, navigate }: { api: Api; onToken: (t: string) => void; navigate: (url: string) => void }) {
  const { t } = useAppTranslation();
  const { directories, oidc } = useLoginSources(api);
  const [choice, setChoice] = useState<Source | null>(null);
  // Derived, not set by an effect: the choice shown is the one a submit uses, at every render.
  const source: Source = choice ?? (directories.length > 0 ? "ldap:" + directories[0].id : "local");
  const [username, setUsername] = useState(readRememberedUsername);
  const [rememberEmail, setRememberEmail] = useState(() => readRememberedUsername() !== "");
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
      rememberUsername(rememberEmail ? username : null);
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
            <span className="login-brand-mark" aria-hidden="true">
              <svg viewBox="0 0 26 34" fill="none">
                <path d="M13 0L0 5.5V15.5C0 23.8 5.5 31.2 13 33C20.5 31.2 26 23.8 26 15.5V5.5L13 0Z" fill="var(--ob-color-login-panel-text)" />
                <path d="M13 4L6 7V13C6 17.5 9 21.5 13 22.5C17 21.5 20 17.5 20 13V7L13 4Z" fill="var(--ob-color-login-panel-mark-accent)" />
                <circle cx="13" cy="12.5" r="2" fill="var(--ob-color-login-panel)" />
                <path d="M13 14.5V17.5" stroke="var(--ob-color-login-panel)" strokeWidth="1.8" strokeLinecap="round" />
              </svg>
            </span>
            <div>
              <strong>OpenBastion</strong>
              <span>{t("login.brand.product")}</span>
            </div>
          </div>
          <div className="login-brand-message">
            <p className="login-eyebrow">{t("login.brand.eyebrow")}</p>
            <h2 aria-label={t("login.brand.titleAccessible")}>
              <span>{t("login.brand.titleFirstLine")}</span>
              <span>{t("login.brand.titleSecondLine")}</span>
            </h2>
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
          <footer className="login-brand-footer">
            <span>{t("login.brand.footerContext")}</span>
            <span>{t("login.brand.footerDeployment")}</span>
            <span>{t("login.brand.footer")}</span>
          </footer>
        </aside>
        <div className="login-content">
          <div className="login-card">
            {challenge ? (
              <SecondFactor
                api={api}
                challenge={challenge}
                identifier={username}
                onToken={onToken}
                onCancel={() => setChallenge(null)}
              />
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
                <Form className="ob-form-fields login-form" onSubmit={local} aria-label={source === "local" ? t("login.formAria.local") : t("login.formAria.directory")}>
                  {directories.length > 0 && (
                    <RadioGroup
                      className="login-source"
                      name="source"
                      label={t("login.source.legend")}
                      value={source}
                      onValueChange={setChoice}
                      orientation="horizontal"
                    >
                      {[...directories.map((d) => ({ s: "ldap:" + d.id, label: d.label || t("login.source.directory") })), { s: "local", label: t("login.source.local") }].map(
                        ({ s, label }) => <RadioGroupItem key={s} value={s} label={label} className="inline" />,
                      )}
                    </RadioGroup>
                  )}
                  <Label className="login-field">
                    {t("login.username")}
                    <Input name="username" type="text" autoComplete="username" placeholder={t("login.emailPlaceholder")} value={username} onChange={(e) => setUsername(e.target.value)} required />
                  </Label>
                  <div className="login-field">
                    <span className="login-field-label">
                      <Label htmlFor="login-password">{t("login.password")}</Label>
                      <span className="login-field-action" aria-hidden="true">{t("login.forgotPassword")}</span>
                    </span>
                    <span className="login-password-wrap">
                      <Input id="login-password" name="password" type={showPassword ? "text" : "password"} autoComplete="current-password" value={password} onChange={(e) => setPassword(e.target.value)} required />
                      <Button className="login-password-toggle" type="button" variant="ghost" onClick={() => setShowPassword((visible) => !visible)} aria-label={showPassword ? t("login.hidePassword") : t("login.showPassword")}>
                        {showPassword ? t("login.hidePassword") : t("login.showPassword")}
                      </Button>
                    </span>
                  </div>
                  <Label className="login-remember">
                    <Checkbox
                      checked={rememberEmail}
                      onChange={(event) => {
                        setRememberEmail(event.target.checked);
                        if (!event.target.checked) rememberUsername(null);
                      }}
                    />
                    {t("login.rememberEmail")}
                  </Label>
                  <Button type="submit" variant="primary" disabled={busy}>
                    {t("login.submit")}
                  </Button>
                </Form>
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
            <div className="login-footer-links">
              <span>{t("login.legal")}</span>
              <LegalLinks className="login-license-links" />
            </div>
          </footer>
        </div>
      </div>
    </main>
  );
}
