import { FormEvent, useRef, useState } from "react";
import { ApiError, SecretActionStepUpChallenge, Session, sessionPath } from "../../shared/api";
import { Notice } from "../../shared/Notice";
import { useSignedIn } from "../../shared/session";
import { Form, FormField, Input } from "@openbastion/ui";
import { ConfirmDialog } from "../../shared/ui/ConfirmDialog";
import { Button } from "../../shared/ui/Button";
import { GatedButton } from "../../shared/ui/GatedButton";
import { Credentials, sign } from "../../shared/webauthn";
import { useAppTranslation } from "../../shared/i18n";

interface ActiveChallenge extends SecretActionStepUpChallenge {
  expiresAt: number;
}

function hasWebAuthnRequestOptions(value: unknown): boolean {
  if (!value || typeof value !== "object") return false;
  const publicKey = (value as { publicKey?: unknown }).publicKey;
  return Boolean(publicKey && typeof publicKey === "object" &&
    typeof (publicKey as { challenge?: unknown }).challenge === "string");
}

function errorText(error: unknown): string {
  return error instanceof ApiError
    ? `${error.status} — ${error.message}`
    : String((error as Error)?.message ?? error);
}

// Injects only the Vault credential bound to this persisted session. The browser handles MFA
// proof, but never receives the credential, the Vault scope, or a caller-selectable account.
// onConflict is told of a refusal that may mean the session changed elsewhere (409): the page reads
// the session again and shows its true status.
export function SecretInjection({ session, credentials, onConflict }: { session: Session; credentials?: Credentials; onConflict?: (err: unknown) => void }) {
  const { t } = useAppTranslation();
  const { api } = useSignedIn();
  const [confirming, setConfirming] = useState(false);
  const [startError, setStartError] = useState<string>();
  const [challenge, setChallenge] = useState<ActiveChallenge>();
  const [code, setCode] = useState("");
  const [busy, setBusy] = useState(false);
  const inFlight = useRef(false);
  const [error, setError] = useState<unknown>();
  const [ok, setOk] = useState<string>();

  if (session.status !== "active" || !["ssh", "vnc", "rdp"].includes(session.protocol)) return null;

  async function begin(): Promise<boolean> {
    setStartError(undefined);
    setError(undefined);
    setOk(undefined);
    try {
      const result = await api.request<SecretActionStepUpChallenge>("POST", `${sessionPath(session.id)}/secret-injection-step-up`);
      if (!result || typeof result.challenge !== "string" || result.challenge.length === 0 || result.challenge.length > 4096 ||
          result.expires_in !== 120 || !Array.isArray(result.factors) || result.factors.length === 0 ||
          result.factors.length > 2 || !result.factors.every((factor) => factor === "totp" || factor === "webauthn") ||
          new Set(result.factors).size !== result.factors.length) {
        throw new Error(t("sessions.secretInjection.invalidChallenge"));
      }
      const factors = result.factors.filter((factor) =>
        factor === "totp" || (factor === "webauthn" && hasWebAuthnRequestOptions(result.webauthn)),
      );
      if (factors.length === 0) throw new Error(t("sessions.secretInjection.noUsableFactor"));
      setChallenge({ ...result, factors, expiresAt: Date.now() + result.expires_in * 1000 });
      setCode("");
      return true;
    } catch (err) {
      setStartError(errorText(err));
      onConflict?.(err);
      return false;
    }
  }

  function cancelChallenge() {
    setChallenge(undefined);
    setCode("");
    setError(undefined);
  }

  async function sendProof(proof: { factor: "totp"; totp_code: string } | { factor: "webauthn"; webauthn_response: Record<string, unknown> }) {
    if (!challenge) return;
    if (Date.now() >= challenge.expiresAt) {
      cancelChallenge();
      setError(new Error(t("sessions.secretInjection.expired")));
      return;
    }
    setError(undefined);
    setOk(undefined);
    const result = await api.request<{ status?: string; injection_id?: string; message?: string }>("POST", `${sessionPath(session.id)}/secret-injection`, {
      challenge: challenge.challenge,
      ...proof,
    });
    if (result?.status === "outcome_unknown") {
      setChallenge(undefined);
      setCode("");
      throw new Error(t("sessions.secretInjection.outcomeUnknown", { id: result.injection_id ?? "unknown" }));
    }
    setChallenge(undefined);
    setCode("");
    setOk(t("sessions.secretInjection.success"));
  }

  async function submitTOTP(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (inFlight.current || !/^\d{6,8}$/.test(code)) return;
    const totpCode = code;
    setCode("");
    inFlight.current = true;
    setBusy(true);
    try {
      await sendProof({ factor: "totp", totp_code: totpCode });
    } catch (err) {
      setError(err);
      onConflict?.(err);
    } finally {
      inFlight.current = false;
      setBusy(false);
    }
  }

  async function useSecurityKey() {
    if (!challenge?.webauthn || inFlight.current) return;
    inFlight.current = true;
    setBusy(true);
    setError(undefined);
    try {
      const assertion = await sign(challenge.webauthn, credentials);
      await sendProof({ factor: "webauthn", webauthn_response: assertion });
    } catch (err) {
      setError(err);
      onConflict?.(err);
    } finally {
      inFlight.current = false;
      setBusy(false);
    }
  }

  return (
    <section className="ob-surface ob-panel secret-injection" aria-labelledby={`secret-injection-${session.id}`}>
      <h3 id={`secret-injection-${session.id}`}>{t("sessions.secretInjection.title")}</h3>
      <p className="ob-hint">{t("sessions.secretInjection.account", { account: session.privilegedAccountId })}</p>
      {!challenge ? (
        <GatedButton capability="secrets.inject" variant="primary" onClick={() => { setStartError(undefined); setConfirming(true); }}>
          {t("sessions.secretInjection.start")}
        </GatedButton>
      ) : (
        <div className="ob-form-fields" aria-busy={busy}>
          <p className="ob-hint">{t("sessions.secretInjection.challengeExpires", { seconds: challenge.expires_in })}</p>
          {challenge.factors.includes("totp") ? (
            <Form onSubmit={submitTOTP} aria-label={t("sessions.secretInjection.totpForm")}>
              <FormField id="secret-injection-totp" label={t("secondFactor.codeLabel")} required>
                <Input
                  name="totp_code"
                  inputMode="numeric"
                  autoComplete="one-time-code"
                  pattern="[0-9]{6,8}"
                  maxLength={8}
                  disabled={busy}
                  value={code}
                  onChange={(event) => setCode(event.target.value.replace(/\D/g, "").slice(0, 8))}
                />
              </FormField>
              <Button type="submit" variant="primary" disabled={busy || !/^\d{6,8}$/.test(code)}>
                {busy ? t("common.actions.working") : t("sessions.secretInjection.confirm")}
              </Button>
            </Form>
          ) : null}
          {challenge.factors.includes("webauthn") ? (
            <Button variant={challenge.factors.includes("totp") ? "secondary" : "primary"} onClick={() => void useSecurityKey()} disabled={busy}>
              {busy ? t("common.actions.working") : t("secondFactor.useKey")}
            </Button>
          ) : null}
          <Button onClick={cancelChallenge} disabled={busy}>{t("common.actions.cancel")}</Button>
        </div>
      )}
      <Notice error={error} ok={ok} />
      {confirming ? (
        <ConfirmDialog
          title={t("sessions.secretInjection.confirmTitle")}
          description={t("sessions.secretInjection.warning", { protocol: session.protocol.toUpperCase() })}
          confirmLabel={t("sessions.secretInjection.continue")}
          danger={false}
          error={startError}
          onCancel={() => setConfirming(false)}
          onConfirm={begin}
        />
      ) : null}
    </section>
  );
}
