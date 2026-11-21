import { FormEvent, useRef, useState } from "react";
import { Form, FormField, Input } from "@openbastion/ui";
import { ApiError, SecretActionStepUpChallenge, sessionPath } from "../../shared/api";
import { useSignedIn } from "../../shared/session";
import { Button } from "../../shared/ui/Button";
import { GatedButton } from "../../shared/ui/GatedButton";
import { InlineNotice } from "../../shared/ui/InlineNotice";
import { Modal } from "../../shared/ui/Modal";
import { Credentials, sign } from "../../shared/webauthn";
import { useAppTranslation } from "../../shared/i18n";
import { MAX_PASTE_CHARACTERS, hexToBytes, sealPaste, validPassword } from "./pasteCrypto";
import { encodePasteInput } from "./protocol";

// An operator's password, typed into the screen session by the proxy (ADR-0133). The text is read
// from a masked field, never from the clipboard; the second factor is asked for each input; the
// Broker returns a one-use token; the text is encrypted here for the proxy's key of this session (the
// HELLO's) and sent over the screen stream. The Gateway relays only the ciphertext; the Broker never
// sees the text. A compromised Gateway, which serves this code, could: ADR-0133 says so.

type Proof = { factor: "totp"; totp_code: string } | { factor: "webauthn"; webauthn_response: Record<string, unknown> };

function errorText(error: unknown): string {
  return error instanceof ApiError ? `${error.status} — ${error.message}` : String((error as Error)?.message ?? error);
}

export function OperatorPaste({ sessionId, protocol, pasteKey, send, credentials }: {
  sessionId: string;
  protocol: "rdp" | "vnc";
  pasteKey: Uint8Array;
  send: (message: Uint8Array<ArrayBuffer>) => void;
  credentials?: Credentials;
}) {
  const { t } = useAppTranslation();
  const { api } = useSignedIn();
  const [open, setOpen] = useState(false);
  const [password, setPassword] = useState("");
  const [challenge, setChallenge] = useState<SecretActionStepUpChallenge>();
  const [code, setCode] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string>();
  const [sent, setSent] = useState(false);
  const inFlight = useRef(false);

  function close() {
    setOpen(false);
    setPassword("");
    setChallenge(undefined);
    setCode("");
    setError(undefined);
  }

  async function run(step: () => Promise<void>) {
    if (inFlight.current) return;
    inFlight.current = true;
    setBusy(true);
    setError(undefined);
    try {
      await step();
    } catch (err) {
      setError(t("screen.paste.failed", { reason: errorText(err) }));
    } finally {
      inFlight.current = false;
      setBusy(false);
    }
  }

  // First the password is taken (and checked as the proxy will), then the factor is asked.
  function begin(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!validPassword(password)) {
      setError(t("screen.paste.invalid", { max: MAX_PASTE_CHARACTERS }));
      return;
    }
    void run(async () => {
      const result = await api.request<SecretActionStepUpChallenge>("POST", `${sessionPath(sessionId)}/secret-paste-step-up`);
      if (!result || typeof result.challenge !== "string" || !result.challenge || !Array.isArray(result.factors) || result.factors.length === 0) {
        throw new Error(t("sessions.secretInjection.invalidChallenge"));
      }
      setChallenge(result);
    });
  }

  // The proof gives the token; the password is encrypted for the proxy and sent, then forgotten.
  function prove(proof: () => Promise<Proof>) {
    void run(async () => {
      if (!challenge) return;
      const grant = await api.request<{ pasteToken?: string }>("POST", `${sessionPath(sessionId)}/secret-paste`, { challenge: challenge.challenge, ...(await proof()) });
      if (!grant || typeof grant.pasteToken !== "string" || !/^[0-9a-f]{64}$/.test(grant.pasteToken)) {
        throw new Error("invalid paste token");
      }
      const sealed = await sealPaste(pasteKey, sessionId, protocol, hexToBytes(grant.pasteToken), password);
      const message = encodePasteInput(sealed.token, sealed.clientKey, sealed.nonce, sealed.ciphertext);
      if (!message) throw new Error("invalid paste message");
      send(message);
      setSent(true);
      close();
    });
  }

  function submitTOTP(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!/^\d{6,8}$/.test(code)) return;
    const totpCode = code;
    setCode("");
    prove(async () => ({ factor: "totp", totp_code: totpCode }));
  }

  return (
    <>
      <GatedButton capability="secrets.paste" onClick={() => { setSent(false); setOpen(true); }}>
        {t("screen.paste.start")}
      </GatedButton>
      {sent ? <InlineNotice tone="info">{t("screen.paste.sent")}</InlineNotice> : null}
      {open ? (
        <Modal open onOpenChange={(next) => { if (!next && !busy) close(); }} title={t("screen.paste.title")} description={t("screen.paste.description")} className="operator-paste-dialog">
          <InlineNotice tone="warning">{t("screen.paste.warning")}</InlineNotice>
          {!challenge ? (
            <Form onSubmit={begin} aria-label={t("screen.paste.title")}>
              <FormField id="operator-paste-password" label={t("screen.paste.label")} required>
                <Input type="password" autoComplete="off" spellCheck={false} value={password} disabled={busy}
                  onChange={(event) => setPassword(event.target.value)} />
              </FormField>
              <div className="ob-form-actions">
                <Button type="button" onClick={close} disabled={busy}>{t("common.actions.cancel")}</Button>
                <Button type="submit" variant="primary" disabled={busy || password === ""}>
                  {busy ? t("common.actions.working") : t("screen.paste.continue")}
                </Button>
              </div>
            </Form>
          ) : (
            <div className="ob-form-fields" aria-busy={busy}>
              {challenge.factors.includes("totp") ? (
                <Form onSubmit={submitTOTP} aria-label={t("sessions.secretInjection.totpForm")}>
                  <FormField id="operator-paste-totp" label={t("secondFactor.codeLabel")} required>
                    <Input name="totp_code" inputMode="numeric" autoComplete="one-time-code" pattern="[0-9]{6,8}" maxLength={8} disabled={busy}
                      value={code} onChange={(event) => setCode(event.target.value.replace(/\D/g, "").slice(0, 8))} />
                  </FormField>
                  <Button type="submit" variant="primary" disabled={busy || !/^\d{6,8}$/.test(code)}>
                    {busy ? t("common.actions.working") : t("screen.paste.confirm")}
                  </Button>
                </Form>
              ) : null}
              {challenge.factors.includes("webauthn") && challenge.webauthn ? (
                <Button onClick={() => prove(async () => ({ factor: "webauthn", webauthn_response: await sign(challenge.webauthn!, credentials) }))} disabled={busy}>
                  {busy ? t("common.actions.working") : t("secondFactor.useKey")}
                </Button>
              ) : null}
              <Button onClick={close} disabled={busy}>{t("common.actions.cancel")}</Button>
            </div>
          )}
          {error ? <InlineNotice tone="danger">{error}</InlineNotice> : null}
        </Modal>
      ) : null}
    </>
  );
}
