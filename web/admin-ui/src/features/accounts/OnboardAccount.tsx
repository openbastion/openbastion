import { FormEvent, useState } from "react";
import { useSignedIn } from "../../shared/session";
import { FormCard } from "../../shared/ui/FormCard";
import { useAppTranslation } from "../../shared/i18n";

// Onboarding one privileged account: the target, how its secret rotates, the identity its target
// must present, and the secret — typed once, sent once, never shown again (the API never returns
// it). A VNC or RDP account has no host key and no rotation; its TLS pin comes next, by its own
// route (ADR-0071).
export function OnboardAccount({ onDone }: { onDone: (id: string) => void }) {
  const { t } = useAppTranslation();
  const { api } = useSignedIn();
  const [f, setF] = useState({
    id: "",
    name: "",
    username: "",
    targetHost: "",
    protocol: "ssh",
    rotationPolicy: "manual",
    initialSecret: "",
    reconciliationAccountId: "",
    hostKey: "",
    rotationIntervalDays: "30",
  });
  const [approvalRequired, setApprovalRequired] = useState(false);
  const [error, setError] = useState<unknown>();
  const set = (k: keyof typeof f) => (e: { target: { value: string } }) => setF({ ...f, [k]: e.target.value });
  const ssh = f.protocol === "ssh";

  async function submit(e: FormEvent) {
    e.preventDefault();
    setError(undefined);
    try {
      // The API takes the secret as bytes (base64 in JSON); it is never sent anywhere else.
      const bytes = new TextEncoder().encode(f.initialSecret);
      let bin = "";
      bytes.forEach((b) => (bin += String.fromCharCode(b)));
      // Only a scheduled account takes an interval (ADR-0040): the Vault refuses one elsewhere.
      const { rotationIntervalDays, ...rest } = f;
      const schedule = f.rotationPolicy === "scheduled" ? { rotationIntervalDays: Number(rotationIntervalDays) } : {};
      // A VNC or RDP account has no host key and no rotation; its TLS pin comes next, by its own route.
      const shape = ssh ? { ...rest, ...schedule } : { ...rest, rotationPolicy: "manual", reconciliationAccountId: "", hostKey: "" };
      await api.request("POST", "/vault/accounts", { ...shape, approvalRequired, initialSecret: btoa(bin) });
      setF({ ...f, id: "", name: "", initialSecret: "", hostKey: "" });
      onDone(f.id);
    } catch (err) {
      setError(err);
    }
  }

  return (
    <FormCard
      label={t("accounts.onboard.label")}
      title={t("accounts.onboard.label")}
      submitLabel={t("accounts.onboard.submit")}
      onSubmit={submit}
      error={error}
    >
      <label>
        {t("accounts.onboard.id")}
        <input value={f.id} onChange={set("id")} required pattern="[A-Za-z0-9_.\-]+" />
      </label>
      <label>
        {t("accounts.onboard.name")}
        <input value={f.name} onChange={set("name")} required />
      </label>
      <label>
        {t("accounts.onboard.target")}
        <input value={f.targetHost} onChange={set("targetHost")} required />
      </label>
      <label>
        {t("accounts.onboard.username")}
        <input value={f.username} onChange={set("username")} required />
      </label>
      <label>
        {t("accounts.onboard.protocol")}
        <select value={f.protocol} onChange={set("protocol")}>
          <option value="ssh">SSH</option>
          <option value="vnc">VNC</option>
          <option value="rdp">RDP</option>
        </select>
      </label>
      {ssh ? (
        <label>
          {t("accounts.onboard.rotation")}
          <select value={f.rotationPolicy} onChange={set("rotationPolicy")}>
            <option value="manual">{t("accounts.onboard.rotationManual")}</option>
            <option value="post_use">{t("accounts.onboard.rotationPostUse")}</option>
            <option value="scheduled">{t("accounts.onboard.rotationScheduled")}</option>
          </select>
        </label>
      ) : null}
      {ssh && f.rotationPolicy === "scheduled" ? (
        <label>
          {t("accounts.onboard.interval")}
          <input type="number" min={1} max={365} value={f.rotationIntervalDays} onChange={set("rotationIntervalDays")} required />
        </label>
      ) : null}
      {ssh ? (
        <label>
          {t("accounts.onboard.reconciliation")}
          <input value={f.reconciliationAccountId} onChange={set("reconciliationAccountId")} />
        </label>
      ) : null}
      {ssh ? (
        <label className="wide">
          {t("accounts.onboard.hostKey")}
          <textarea value={f.hostKey} onChange={set("hostKey")} required rows={2} spellCheck={false} placeholder="ssh-ed25519 AAAA…" />
        </label>
      ) : (
        <p className="ob-hint wide">{t("accounts.onboard.tlsHint")}</p>
      )}
      <label className="check">
        <input type="checkbox" checked={approvalRequired} onChange={(e) => setApprovalRequired(e.target.checked)} />
        {t("accounts.onboard.approval")}
      </label>
      <label>
        {t("accounts.onboard.initialSecret")}
        <input type="password" autoComplete="new-password" value={f.initialSecret} onChange={set("initialSecret")} required />
      </label>
    </FormCard>
  );
}
