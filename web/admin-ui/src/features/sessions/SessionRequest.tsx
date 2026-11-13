import { FormEvent, useState } from "react";
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
      <label>
        {t("sessions.request.account")}
        <input value={f.targetAccountId} onChange={set("targetAccountId")} required />
      </label>
      <label>
        {t("sessions.request.protocol")}
        <select value={f.protocol} onChange={set("protocol")}>
          <option value="ssh">SSH</option>
          <option value="vnc">VNC</option>
          <option value="rdp">RDP</option>
        </select>
      </label>
      <label>
        {t("sessions.request.duration")}
        <input type="number" min={1} value={f.durationMinutes} onChange={set("durationMinutes")} required />
      </label>
      <label className="wide">
        {t("sessions.columns.justification")}
        <input value={f.justification} onChange={set("justification")} required />
      </label>
      <label>
        {t("sessions.request.ticket")}
        <input value={f.ticket} onChange={set("ticket")} maxLength={128} autoComplete="off" />
      </label>
    </FormCard>
  );
}
