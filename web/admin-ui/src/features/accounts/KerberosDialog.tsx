import { FormEvent, useState } from "react";
import { FormField, Input, Textarea } from "@openbastion/ui";
import { Account, KerberosSettings } from "../../shared/api";
import { Button } from "../../shared/ui/Button";
import { InlineNotice } from "../../shared/ui/InlineNotice";
import { Modal } from "../../shared/ui/Modal";
import { useAppTranslation } from "../../shared/i18n";

export const maxKerberosKDCs = 4;

// The KDCs as typed: one per line (commas taken too), blank lines dropped.
export function parseKDCs(text: string): string[] {
  return text.split(/[\n,]/).map((line) => line.trim()).filter((line) => line !== "");
}

const ipLiteral = /^(\d{1,3}(\.\d{1,3}){3}|[0-9a-f:]*:[0-9a-f:.]*)$/i;

// The checks made first, so the form says what is wrong before it is sent. The Vault normalizes and
// checks again; it is the authority (ADR-0100).
export function kerberosProblem(settings: KerberosSettings, account: Account): "noRealm" | "noKDC" | "tooManyKDCs" | "duplicateKDC" | "ipName" | "domainUser" | undefined {
  if (settings.realm.trim() === "") return "noRealm";
  if (settings.kdcs.length === 0) return "noKDC";
  if (settings.kdcs.length > maxKerberosKDCs) return "tooManyKDCs";
  // host and host:88 are the same KDC; a bare IPv6 address has colons but no port.
  const withPort = (kdc: string) => {
    if (kdc.startsWith("[")) return /\]:\d+$/.test(kdc) ? kdc : `${kdc}:88`;
    if ((kdc.match(/:/g) ?? []).length > 1) return `[${kdc}]:88`;
    return kdc.includes(":") ? kdc : `${kdc}:88`;
  };
  const lower = settings.kdcs.map((kdc) => withPort(kdc).toLowerCase());
  if (new Set(lower).size !== lower.length) return "duplicateKDC";
  // A ticket names a host: the account pinned to an IP address takes no Kerberos (the Vault says 409).
  if (account.targetDomain && ipLiteral.test(account.targetDomain)) return "ipName";
  // The user is a name in the realm: DOMAIN\user or user@realm would ask the KDC for another principal.
  if (/[\\@]/.test(account.username)) return "domainUser";
  return undefined;
}

// The Kerberos settings of an RDP account (ADR-0100), set by its administrator: the realm and its
// KDCs. Set, the account's sessions authenticate with Kerberos alone, never NTLM; "Back to NTLM"
// removes them. The service principal is not asked: the proxy asks a ticket for TERMSRV/<the pinned
// name>, shown here. The screen owns the call; this dialog owns the form.
export function KerberosDialog({
  account,
  error,
  onSave,
  onCancel,
}: {
  account: Account;
  error?: string;
  onSave: (kerberos: KerberosSettings | null) => Promise<boolean>;
  onCancel: () => void;
}) {
  const { t } = useAppTranslation();
  const [realm, setRealm] = useState(account.kerberos?.realm ?? "");
  const [kdcText, setKdcText] = useState((account.kerberos?.kdcs ?? []).join("\n"));
  const [working, setWorking] = useState(false);
  const settings: KerberosSettings = { realm: realm.trim().toUpperCase(), kdcs: parseKDCs(kdcText) };
  const problem = kerberosProblem(settings, account);

  async function save(value: KerberosSettings | null) {
    setWorking(true);
    try {
      if (await onSave(value)) onCancel();
    } finally {
      setWorking(false);
    }
  }

  function submit(event: FormEvent) {
    event.preventDefault();
    if (!problem) void save(settings);
  }

  return (
    <Modal
      open
      onOpenChange={(open) => { if (!open && !working) onCancel(); }}
      title={t("accounts.kerberos.title", { id: account.id })}
      description={t("accounts.kerberos.description")}
      className="kerberos-dialog"
    >
      <form className="kerberos-form" onSubmit={submit} aria-label={t("accounts.kerberos.title", { id: account.id })}>
        <FormField id="kerberos-realm" label={t("accounts.kerberos.realm")} description={t("accounts.kerberos.realmHint")}>
          <Input value={realm} onChange={(e) => setRealm(e.target.value)} autoComplete="off" spellCheck={false} />
        </FormField>
        <FormField id="kerberos-kdcs" label={t("accounts.kerberos.kdcs")} description={t("accounts.kerberos.kdcsHint", { max: maxKerberosKDCs })}>
          <Textarea value={kdcText} onChange={(e) => setKdcText(e.target.value)} rows={4} spellCheck={false} />
        </FormField>
        <p className="ob-hint">
          {account.targetDomain
            ? t("accounts.kerberos.principal", { principal: `TERMSRV/${account.targetDomain}` })
            : t("accounts.kerberos.notPinned")}
        </p>
        <p className="ob-hint">{t("accounts.kerberos.hint")}</p>
        {problem ? <InlineNotice tone="warning">{t(`accounts.kerberos.problems.${problem}`, { max: maxKerberosKDCs })}</InlineNotice> : null}
        {error ? <InlineNotice tone="danger">{error}</InlineNotice> : null}
        <div className="ob-form-actions">
          <Button type="button" disabled={working} onClick={onCancel}>{t("common.actions.cancel")}</Button>
          {account.kerberos ? (
            <Button type="button" disabled={working} onClick={() => void save(null)}>{t("accounts.kerberos.remove")}</Button>
          ) : null}
          <Button type="submit" variant="primary" disabled={working || Boolean(problem)}>
            {working ? t("common.actions.working") : t("accounts.kerberos.save")}
          </Button>
        </div>
      </form>
    </Modal>
  );
}
