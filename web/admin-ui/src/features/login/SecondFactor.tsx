import { FormEvent, useState } from "react";
import { Api } from "../../shared/api";
import { Notice } from "../../shared/Notice";
import { Credentials, register, sign } from "../../shared/webauthn";
import { Challenge } from "./sources";
import { Button } from "../../shared/ui/Button";
import { useAppTranslation } from "../../shared/i18n";
import { Form, Input, InputOTP, Label } from "@openbastion/ui";

// The second step of a login whose password was right, when its roles require a second factor
// (ADR-0062, ADR-0065): a security key or the code of the authenticator application — whichever
// the challenge accepts; for a strict role, the key only — or, not yet enrolled, the
// administrator's enrollment code, then the factor to enroll.

export function SecondFactor({
  api,
  challenge,
  onToken,
  onCancel,
  credentials,
  identifier,
}: {
  api: Api;
  challenge: Challenge;
  onToken: (t: string) => void;
  onCancel: () => void;
  credentials?: Credentials;
  identifier?: string;
}) {
  const { t } = useAppTranslation();
  const [code, setCode] = useState("");
  const [enrollmentCode, setEnrollmentCode] = useState("");
  const [enrollment, setEnrollment] = useState<{ secret: string; otpauthUri: string } | null>(null);
  const [error, setError] = useState<unknown>();
  const [busy, setBusy] = useState(false);
  const [adding, setAdding] = useState(false);
  const totp = challenge.factors.includes("totp");
  const key = challenge.factors.includes("webauthn");

  async function step(run: () => Promise<void>) {
    setBusy(true);
    setError(undefined);
    try {
      await run();
    } catch (err) {
      setError(err);
    } finally {
      setBusy(false);
    }
  }

  const post = <T,>(path: string, body: Record<string, unknown>) => api.request<T>("POST", path, { challenge: challenge.challenge, ...body });

  function verify(e: FormEvent) {
    e.preventDefault();
    const path = challenge.kind === "required" ? "/auth/mfa/verify" : "/auth/mfa/enroll/confirm";
    void step(async () => {
      const r = await post<{ accessToken: string }>(path, { code });
      setEnrollment(null); // the secret leaves the page with the login
      onToken(r.accessToken);
    });
  }

  function useKey() {
    void step(async () => {
      const credential = await sign(challenge.webauthn, credentials);
      const r = await post<{ accessToken: string }>("/auth/mfa/webauthn/verify", { credential });
      onToken(r.accessToken);
    });
  }

  // One more key (ADR-0066): the current key signs, with the administrator's code, then the new key.
  function addKey(e: FormEvent) {
    e.preventDefault();
    void step(async () => {
      const credential = await sign(challenge.webauthn, credentials);
      const r = await post<{ webauthn: unknown }>("/auth/mfa/webauthn/keys/add", { credential, enrollmentCode });
      setEnrollmentCode("");
      const created = await register(r.webauthn, credentials);
      const done = await post<{ accessToken: string }>("/auth/mfa/webauthn/enroll/confirm", { credential: created });
      onToken(done.accessToken);
    });
  }

  function enroll(factor: "totp" | "webauthn") {
    void step(async () => {
      const r = await post<{ secret?: string; otpauthUri?: string; webauthn?: unknown }>("/auth/mfa/enroll", { enrollmentCode, factor });
      setEnrollmentCode("");
      if (factor === "webauthn") {
        const credential = await register(r.webauthn, credentials);
        const done = await post<{ accessToken: string }>("/auth/mfa/webauthn/enroll/confirm", { credential });
        onToken(done.accessToken);
        return;
      }
      setEnrollment({ secret: r.secret ?? "", otpauthUri: r.otpauthUri ?? "" });
    });
  }

  const codeForm = (
    <Form className="ob-form-fields second-factor-code-form" onSubmit={verify} aria-label={t("secondFactor.codeFormAria")}>
      <Label htmlFor="second-factor-code" className="second-factor-code-label">{t("secondFactor.codeLabel")}</Label>
      <div className="second-factor-code-control" data-filled={code.length}>
        {Array.from({ length: 6 }, (_, index) => (
          <span
            key={index}
            className={`second-factor-code-cell${index === code.length && code.length < 6 ? " is-active" : ""}`}
            aria-hidden="true"
          >
            {code[index] ?? ""}
          </span>
        ))}
        <InputOTP
          id="second-factor-code"
          className="second-factor-code-input"
          autoFocus
          name="code"
          length={6}
          pattern="[0-9]{6}"
          value={code}
          aria-describedby="second-factor-code-hint"
          onChange={(e) => setCode(e.target.value.replace(/\D/g, "").slice(0, 6))}
          required
        />
      </div>
      <p className="second-factor-code-hint" id="second-factor-code-hint">{t("secondFactor.codeHint")}</p>
      <Button type="submit" variant="primary" disabled={busy || code.length !== 6}>
        {t("secondFactor.validate")}
      </Button>
    </Form>
  );

  const enrolling = challenge.kind === "enrollment_required";
  const title = enrolling ? t("secondFactor.enrollTitle") : t("secondFactor.title");
  const description = enrolling
    ? (key && !totp ? t("secondFactor.enrollKeyOnly") : t("secondFactor.enrollFactor"))
    : (key && !totp ? t("secondFactor.keyOnly") : t("secondFactor.description"));

  return (
    <section className="second-factor" aria-label={t("secondFactor.aria")}>
      <Button className="second-factor-back" variant="ghost" onClick={onCancel} disabled={busy}>
        <svg viewBox="0 0 16 16" aria-hidden="true"><path d="M10.5 3.5 6 8l4.5 4.5M6.5 8H14" /></svg>
        {t("secondFactor.back")}
      </Button>
      <div className="second-factor-icon" aria-hidden="true">
        <svg viewBox="0 0 28 28" fill="none">
          <rect x="5.5" y="3.5" width="10" height="19" rx="2" />
          <path d="M8.5 19.5h4M19 8c2 2.4 2 5.6 0 8M22 5.5c3.7 4.2 3.7 9.8 0 14" />
        </svg>
      </div>
      <header className="second-factor-heading">
        <h1>{title}</h1>
        <p>{description}</p>
      </header>
      {identifier ? (
        <div className="second-factor-account" aria-label={`${t("secondFactor.account")}: ${identifier}`}>
          <span>{t("secondFactor.account")}</span>
          <strong>{identifier}</strong>
        </div>
      ) : null}
      {challenge.kind === "required" && (
        <>
          {key && !adding && !totp && (
            <Button variant="primary" onClick={useKey} disabled={busy}>
              {t("secondFactor.useKey")}
            </Button>
          )}
          {key && adding && (
            <Form className="ob-form-fields" onSubmit={addKey} aria-label={t("secondFactor.addKeyAria")}>
              <p className="ob-hint login-sub">{t("secondFactor.addKeyHint")}</p>
              <Label>
                {t("secondFactor.enrollmentCode")}
                <Input name="enrollmentCode" autoComplete="off" value={enrollmentCode} onChange={(e) => setEnrollmentCode(e.target.value)} required />
              </Label>
              <Button type="submit" variant="primary" disabled={busy || !enrollmentCode}>{t("secondFactor.signThenAdd")}</Button>
            </Form>
          )}
          {totp && !adding && codeForm}
          {key && totp && !adding && (
            <Button className="second-factor-alternate" variant="ghost" onClick={useKey} disabled={busy}>
              {t("secondFactor.useKey")}
            </Button>
          )}
          {key && !adding && (
            <Button className="second-factor-add-key" variant="ghost" onClick={() => setAdding(true)} disabled={busy}>
              {t("secondFactor.addKey")}
            </Button>
          )}
        </>
      )}
      {enrolling && !enrollment && (
        <Form className="ob-form-fields second-factor-enroll-form" onSubmit={(e) => (e.preventDefault(), enroll(totp ? "totp" : "webauthn"))} aria-label={t("secondFactor.enrollAria")}>
          <Label>
            {t("secondFactor.enrollmentCode")}
            <Input name="enrollmentCode" autoComplete="off" value={enrollmentCode} onChange={(e) => setEnrollmentCode(e.target.value)} required />
          </Label>
          {key && <Button variant="primary" onClick={() => enroll("webauthn")} disabled={busy || !enrollmentCode}>{t("secondFactor.enrollKey")}</Button>}
          {totp && <Button type="submit" variant={key ? "secondary" : "primary"} disabled={busy}>{t("secondFactor.receiveSecret")}</Button>}
        </Form>
      )}
      {enrolling && enrollment && (
        <>
          <p className="ob-hint login-sub">{t("secondFactor.secretHint")}</p>
          <dl className="ob-detail-list enrollment">
            <dt>{t("secondFactor.secret")}</dt><dd><code>{enrollment.secret}</code></dd>
            <dt>{t("secondFactor.uri")}</dt><dd><code>{enrollment.otpauthUri}</code></dd>
          </dl>
          {codeForm}
        </>
      )}
      {challenge.kind === "required" && !adding && (
        <aside className="second-factor-help">
          <p>{t("secondFactor.helpTitle")}</p>
          <p>{t("secondFactor.helpBody")}</p>
        </aside>
      )}
      <Notice error={error} />
    </section>
  );
}
