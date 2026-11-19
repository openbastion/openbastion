import { FormEvent, useState } from "react";
import { Checkbox, FormField, Input, Label, Select, Textarea } from "@openbastion/ui";
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
      <FormField id="onboard-id" label={t("accounts.onboard.id")} required>
        <Input value={f.id} onChange={set("id")} pattern="[A-Za-z0-9_.\-]+" />
      </FormField>
      <FormField id="onboard-name" label={t("accounts.onboard.name")} required>
        <Input value={f.name} onChange={set("name")} />
      </FormField>
      <FormField id="onboard-target" label={t("accounts.onboard.target")} required>
        <Input value={f.targetHost} onChange={set("targetHost")} />
      </FormField>
      <FormField id="onboard-username" label={t("accounts.onboard.username")} required>
        <Input value={f.username} onChange={set("username")} />
      </FormField>
      <FormField id="onboard-protocol" label={t("accounts.onboard.protocol")}>
        <Select value={f.protocol} onChange={set("protocol")}>
          <option value="ssh">SSH</option>
          <option value="vnc">VNC</option>
          <option value="rdp">RDP</option>
        </Select>
      </FormField>
      {ssh ? (
        <FormField id="onboard-rotation" label={t("accounts.onboard.rotation")}>
          <Select value={f.rotationPolicy} onChange={set("rotationPolicy")}>
            <option value="manual">{t("accounts.onboard.rotationManual")}</option>
            <option value="post_use">{t("accounts.onboard.rotationPostUse")}</option>
            <option value="scheduled">{t("accounts.onboard.rotationScheduled")}</option>
          </Select>
        </FormField>
      ) : null}
      {ssh && f.rotationPolicy === "scheduled" ? (
        <FormField id="onboard-interval" label={t("accounts.onboard.interval")} required>
          <Input type="number" min={1} max={365} value={f.rotationIntervalDays} onChange={set("rotationIntervalDays")} />
        </FormField>
      ) : null}
      {ssh ? (
        <FormField id="onboard-reconciliation" label={t("accounts.onboard.reconciliation")}>
          <Input value={f.reconciliationAccountId} onChange={set("reconciliationAccountId")} />
        </FormField>
      ) : null}
      {ssh ? (
        <FormField id="onboard-host-key" label={t("accounts.onboard.hostKey")} required className="wide">
          <Textarea value={f.hostKey} onChange={set("hostKey")} rows={2} spellCheck={false} placeholder="ssh-ed25519 AAAA…" />
        </FormField>
      ) : (
        <p className="ob-hint wide">{t("accounts.onboard.tlsHint")}</p>
      )}
      <Label className="check">
        <Checkbox checked={approvalRequired} onChange={(e) => setApprovalRequired(e.target.checked)} />
        {t("accounts.onboard.approval")}
      </Label>
      <FormField id="onboard-secret" label={t("accounts.onboard.initialSecret")} required>
        <Input type="password" autoComplete="new-password" value={f.initialSecret} onChange={set("initialSecret")} />
      </FormField>
    </FormCard>
  );
}
