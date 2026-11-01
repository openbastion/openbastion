import { FormEvent, useState } from "react";
import { Api } from "../../shared/api";
import { Notice } from "../../shared/Notice";

// The second step of a login whose password was right, when its roles require a second factor
// (ADR-0062): the code of the authenticator application, or — not yet enrolled — the
// administrator's enrollment code, then the secret to copy, then a first code.
export type Challenge = { kind: "required" | "enrollment_required"; challenge: string };

export function SecondFactor({ api, challenge, onToken, onCancel }: { api: Api; challenge: Challenge; onToken: (t: string) => void; onCancel: () => void }) {
  const [code, setCode] = useState("");
  const [enrollmentCode, setEnrollmentCode] = useState("");
  const [enrollment, setEnrollment] = useState<{ secret: string; otpauthUri: string } | null>(null);
  const [error, setError] = useState<unknown>();
  const [busy, setBusy] = useState(false);

  async function step<T>(path: string, body: Record<string, string>, then: (r: T) => void) {
    setBusy(true);
    setError(undefined);
    try {
      then(await api.request<T>("POST", path, { challenge: challenge.challenge, ...body }));
    } catch (err) {
      setError(err);
    } finally {
      setBusy(false);
    }
  }

  function verify(e: FormEvent) {
    e.preventDefault();
    const path = challenge.kind === "required" ? "/auth/mfa/verify" : "/auth/mfa/enroll/confirm";
    void step<{ accessToken: string }>(path, { code }, (r) => {
      setEnrollment(null); // the secret leaves the page with the login
      onToken(r.accessToken);
    });
  }

  function enroll(e: FormEvent) {
    e.preventDefault();
    void step<{ secret: string; otpauthUri: string }>("/auth/mfa/enroll", { enrollmentCode }, (r) => {
      setEnrollmentCode("");
      setEnrollment(r);
    });
  }

  const codeForm = (
    <form onSubmit={verify} aria-label="Code du second facteur">
      <label>
        Code de l'application d'authentification
        <input
          name="code"
          inputMode="numeric"
          autoComplete="one-time-code"
          pattern="[0-9]{6}"
          maxLength={6}
          value={code}
          onChange={(e) => setCode(e.target.value.replace(/\D/g, ""))}
          required
        />
      </label>
      <button type="submit" className="primary" disabled={busy || code.length !== 6}>
        Valider
      </button>
    </form>
  );

  return (
    <section className="second-factor" aria-label="Second facteur">
      {challenge.kind === "required" && (
        <>
          <p className="login-sub">Votre rôle demande un second facteur.</p>
          {codeForm}
        </>
      )}
      {challenge.kind === "enrollment_required" && !enrollment && (
        <form onSubmit={enroll} aria-label="Enrôlement du second facteur">
          <p className="login-sub">Votre rôle demande un second facteur, que ce compte n'a pas encore. Un administrateur vous a remis un code d'enrôlement.</p>
          <label>
            Code d'enrôlement
            <input name="enrollmentCode" autoComplete="off" value={enrollmentCode} onChange={(e) => setEnrollmentCode(e.target.value)} required />
          </label>
          <button type="submit" className="primary" disabled={busy}>
            Recevoir le secret
          </button>
        </form>
      )}
      {challenge.kind === "enrollment_required" && enrollment && (
        <>
          <p className="login-sub">Ajoutez ce secret à votre application d'authentification, puis saisissez le code qu'elle affiche. Il n'est montré qu'une fois.</p>
          <dl className="enrollment">
            <dt>Secret</dt>
            <dd>
              <code>{enrollment.secret}</code>
            </dd>
            <dt>URI</dt>
            <dd>
              <code>{enrollment.otpauthUri}</code>
            </dd>
          </dl>
          {codeForm}
        </>
      )}
      <button type="button" onClick={onCancel} disabled={busy}>
        Recommencer
      </button>
      <Notice error={error} />
    </section>
  );
}
