import { FormEvent, useRef, useState } from "react";
import { Button, FormField, Input, Select, Textarea } from "@openbastion/ui";
import { ApiError, Session } from "../../shared/api";
import { useSignedIn } from "../../shared/session";
import { useAppTranslation } from "../../shared/i18n";
import { FormCard } from "../../shared/ui/FormCard";

const TICKET_MAX = 128;

type Field = "targetAccountId" | "justification" | "durationMinutes";

// A session request (POST /sessions), as docs/ui/reference-screens/openbastion-sessions-nouvelle-
// demande-*.svg draws it. The ticket is what an account that requires approval asks for
// (ADR-0067), in the format the platform declared; the Broker ignores it on any other account.
//
// One request per click: the lock is a ref, set before the first await, so two submits in the
// same tick cannot both pass it; the state only drives what the page shows. A missing field is
// said under it and nothing is sent; the Broker still checks everything (the protocol must be
// the account's, the ticket's format, the duration's bound). A request the server did not
// confirm keeps every field.
export function SessionRequest({ onDone, onCancel }: { onDone: (s: Session) => void; onCancel?: () => void }) {
  const { t } = useAppTranslation();
  const { api } = useSignedIn();
  const [f, setF] = useState({ targetAccountId: "", protocol: "ssh", justification: "", durationMinutes: "30", ticket: "" });
  const [error, setError] = useState<unknown>();
  const [invalid, setInvalid] = useState<Partial<Record<Field, string>>>({});
  const [submitting, setSubmitting] = useState(false);
  const inFlight = useRef(false);
  const set = (k: keyof typeof f) => (e: { target: { value: string } }) => {
    setF({ ...f, [k]: e.target.value });
    if (k in invalid) setInvalid(({ [k as Field]: _gone, ...rest }) => rest);
  };

  function validate(): Partial<Record<Field, string>> {
    const problems: Partial<Record<Field, string>> = {};
    if (!f.targetAccountId.trim()) problems.targetAccountId = t("sessions.request.errors.account");
    if (!f.justification.trim()) problems.justification = t("sessions.request.errors.justification");
    const minutes = Number(f.durationMinutes);
    if (!Number.isInteger(minutes) || minutes < 1) problems.durationMinutes = t("sessions.request.errors.duration");
    return problems;
  }

  async function submit(e: FormEvent) {
    e.preventDefault();
    if (inFlight.current) return;
    const problems = validate();
    setInvalid(problems);
    if (Object.keys(problems).length > 0) {
      setError(undefined);
      return;
    }
    inFlight.current = true;
    setSubmitting(true);
    setError(undefined);
    try {
      const { ticket, ...rest } = f;
      // The protocol must be the account's: the Broker refuses any other, and routes on its own.
      const s = await api.request<Session>("POST", "/sessions", {
        ...rest,
        ...(ticket ? { ticket } : {}),
        durationMinutes: Number(f.durationMinutes),
      });
      setF({ ...f, justification: "", ticket: "" });
      onDone(s);
    } catch (err) {
      const detail = err instanceof ApiError ? `${err.status} — ${err.message}` : String((err as Error)?.message ?? err);
      setError(new Error(`${t("sessions.request.errors.server")} (${detail})`));
    } finally {
      inFlight.current = false;
      setSubmitting(false);
    }
  }

  const hasProblems = Object.keys(invalid).length > 0;
  return (
    <FormCard
      label={t("sessions.request.label")}
      title={t("sessions.request.title")}
      submitLabel={t("sessions.request.submit")}
      submittingLabel={t("sessions.request.submitting")}
      submitting={submitting}
      noValidate
      onSubmit={submit}
      error={error}
      footer={
        <>
          {hasProblems ? <p className="ob-form-field__error" role="alert">{t("sessions.request.errors.summary")}</p> : null}
          <p className="ob-hint">{t("sessions.request.notApproval")}</p>
          <p className="ob-hint">{t("sessions.request.requiredNote")}</p>
        </>
      }
      secondaryAction={onCancel ? <Button type="button" onClick={onCancel}>{t("sessions.request.cancel")}</Button> : undefined}
    >
      <FormField id="session-request-account" label={t("sessions.request.account")} description={t("sessions.request.accountHelp")} error={invalid.targetAccountId} required>
        <Input value={f.targetAccountId} onChange={set("targetAccountId")} autoComplete="off" />
      </FormField>
      <FormField id="session-request-protocol" label={t("sessions.request.protocol")} description={t("sessions.request.protocolHelp")}>
        <Select value={f.protocol} onChange={set("protocol")}>
          <option value="ssh">SSH</option>
          <option value="vnc">VNC</option>
          <option value="rdp">RDP</option>
        </Select>
      </FormField>
      <FormField id="session-request-duration" label={t("sessions.request.duration")} description={t("sessions.request.durationHelp")} error={invalid.durationMinutes} required>
        <Input type="number" min={1} step={1} value={f.durationMinutes} onChange={set("durationMinutes")} />
      </FormField>
      <FormField id="session-request-justification" label={t("sessions.columns.justification")} description={t("sessions.request.justificationHelp")} error={invalid.justification} required className="wide">
        <Textarea value={f.justification} onChange={set("justification")} rows={3} />
      </FormField>
      <FormField
        id="session-request-ticket"
        label={t("sessions.request.ticket")}
        description={<>{t("sessions.request.ticketHelp")} <span aria-live="polite">{t("sessions.request.ticketCount", { count: f.ticket.length, max: TICKET_MAX })}</span></>}
      >
        <Input value={f.ticket} onChange={set("ticket")} maxLength={TICKET_MAX} autoComplete="off" />
      </FormField>
    </FormCard>
  );
}
