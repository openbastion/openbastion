import { Account } from "../../shared/api";
import { translate } from "../../shared/i18n";

// Whoever changes a pin decides which server receives the secret: the Vault audits it. Both
// questions cancel the whole gesture (null), and nothing is sent.

export function askHostKey(a: Account): string | null {
  return window.prompt(
    translate("accounts.prompts.hostKey", { host: a.targetHost }) +
      (a.hostKeyFingerprint ? translate("accounts.prompts.hostKeyReplace", { fingerprint: a.hostKeyFingerprint }) : ""),
  );
}

// The same decision for a graphical target: this certificate, for this name, gets the secret.
export function askTlsPin(a: Account): { fingerprint: string; domain: string } | null {
  const fingerprint = window.prompt(
    translate("accounts.prompts.tlsFingerprint", { host: a.targetHost }) +
      (a.tlsCertificateSha256
        ? translate("accounts.prompts.tlsFingerprintReplace", { fingerprint: a.tlsCertificateSha256 })
        : ""),
  );
  if (!fingerprint) return null;
  const domain = window.prompt(translate("accounts.prompts.tlsDomain"), a.targetDomain ?? "");
  if (!domain) return null;
  return { fingerprint: fingerprint.trim(), domain: domain.trim() };
}
