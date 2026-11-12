import { FormEvent, useState } from "react";
import { Api } from "../../shared/api";
import { Notice } from "../../shared/Notice";
import { Credentials, register, sign } from "../../shared/webauthn";
import { Challenge } from "./sources";
import { Button } from "../../shared/ui/Button";

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
}: {
  api: Api;
  challenge: Challenge;
  onToken: (t: string) => void;
  onCancel: () => void;
  credentials?: Credentials;
}) {
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
    <form className="ob-form-fields" onSubmit={verify} aria-label="Code du second facteur">
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
      <Button type="submit" variant="primary" disabled={busy || code.length !== 6}>
        Valider
      </Button>
    </form>
  );

  return (
    <section className="second-factor" aria-label="Second facteur">
      {challenge.kind === "required" && (
        <>
          <p className="ob-hint login-sub">{key && !totp ? "Votre rôle demande votre clé de sécurité." : "Votre rôle demande un second facteur."}</p>
          {key && !adding && (
            <>
              <Button variant="primary" onClick={useKey} disabled={busy}>
                Utiliser ma clé de sécurité
              </Button>
              <Button onClick={() => setAdding(true)} disabled={busy}>
                Ajouter une clé de secours
              </Button>
            </>
          )}
          {key && adding && (
            <form className="ob-form-fields" onSubmit={addKey} aria-label="Ajout d'une clé de secours">
              <p className="ob-hint login-sub">Votre clé actuelle signera d'abord ; puis le navigateur enregistrera la nouvelle. Il faut un code d'enrôlement d'un administrateur.</p>
              <label>
                Code d'enrôlement
                <input name="enrollmentCode" autoComplete="off" value={enrollmentCode} onChange={(e) => setEnrollmentCode(e.target.value)} required />
              </label>
              <Button type="submit" variant="primary" disabled={busy || !enrollmentCode}>
                Signer avec ma clé, puis ajouter la nouvelle
              </Button>
            </form>
          )}
          {totp && !adding && codeForm}
        </>
      )}
      {challenge.kind === "enrollment_required" && !enrollment && (
        <form className="ob-form-fields" onSubmit={(e) => (e.preventDefault(), enroll(totp ? "totp" : "webauthn"))} aria-label="Enrôlement du second facteur">
          <p className="ob-hint login-sub">
            {key && !totp
              ? "Votre rôle demande une clé de sécurité, que ce compte n'a pas encore. Un administrateur vous a remis un code d'enrôlement."
              : "Votre rôle demande un second facteur, que ce compte n'a pas encore. Un administrateur vous a remis un code d'enrôlement."}
          </p>
          <label>
            Code d'enrôlement
            <input name="enrollmentCode" autoComplete="off" value={enrollmentCode} onChange={(e) => setEnrollmentCode(e.target.value)} required />
          </label>
          {key && (
            <Button variant="primary" onClick={() => enroll("webauthn")} disabled={busy || !enrollmentCode}>
              Enrôler une clé de sécurité
            </Button>
          )}
          {totp && (
            <Button type="submit" variant={key ? "secondary" : "primary"} disabled={busy}>
              Recevoir le secret
            </Button>
          )}
        </form>
      )}
      {challenge.kind === "enrollment_required" && enrollment && (
        <>
          <p className="ob-hint login-sub">Ajoutez ce secret à votre application d'authentification, puis saisissez le code qu'elle affiche. Il n'est montré qu'une fois.</p>
          <dl className="ob-detail-list enrollment">
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
      <Button onClick={onCancel} disabled={busy}>
        Recommencer
      </Button>
      <Notice error={error} />
    </section>
  );
}
