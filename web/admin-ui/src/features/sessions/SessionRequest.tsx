import { FormEvent, useState } from "react";
import { FormField, Input, Select } from "@openbastion/ui";
import { Session } from "../../shared/api";
import { useSignedIn } from "../../shared/session";
import { FormCard } from "../../shared/ui/FormCard";
import { useAppTranslation } from "../../shared/i18n";

// A session request (POST /sessions). The ticket is what an account that requires approval asks
// for (ADR-0067), in the format the platform declared; the Broker ignores it on any other account.
export function SessionRequest({ onDone }: { onDone: (s: Session) => void }) {
  const { t } = useAppTranslation();
  const { api } = useSignedIn();
  const [f, setF] = useState({ targetAccountId: "", protocol: "ssh", justification: "", durationMinutes: "30", ticket: "" });
  const [error, setError] = useState<unknown>();
  const set = (k: keyof typeof f) => (e: { target: { value: string } }) => setF({ ...f, [k]: e.target.value });

  async function submit(e: FormEvent) {
    e.preventDefault();
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
      setError(err);
    }
  }

  return (
    <FormCard
      label={t("sessions.request.label")}
      title={t("sessions.request.title")}
      submitLabel={t("sessions.request.submit")}
      onSubmit={submit}
      error={error}
    >
      <FormField id="session-request-account" label={t("sessions.request.account")} required>
        <Input value={f.targetAccountId} onChange={set("targetAccountId")} />
      </FormField>
      <FormField id="session-request-protocol" label={t("sessions.request.protocol")}>
        <Select value={f.protocol} onChange={set("protocol")}>
          <option value="ssh">SSH</option>
          <option value="vnc">VNC</option>
          <option value="rdp">RDP</option>
        </Select>
      </FormField>
      <FormField id="session-request-duration" label={t("sessions.request.duration")} required>
        <Input type="number" min={1} value={f.durationMinutes} onChange={set("durationMinutes")} />
      </FormField>
      <FormField id="session-request-justification" label={t("sessions.columns.justification")} required className="wide">
        <Input value={f.justification} onChange={set("justification")} />
      </FormField>
      <FormField id="session-request-ticket" label={t("sessions.request.ticket")}>
        <Input value={f.ticket} onChange={set("ticket")} maxLength={128} autoComplete="off" />
      </FormField>
    </FormCard>
  );
}
