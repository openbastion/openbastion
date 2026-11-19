import type { TFunction } from "i18next";
import { Account } from "../../shared/api";

// `rotation` marks the reasons that concern a rotation: the "rotations in anomaly" counter reads
// that flag instead of searching a translated sentence, which a translation would break.
export type Reason = { text: string; rotation: boolean };
export type Finding = { account: Account; reasons: Reason[] };

// Concrete account metadata only: a missing pinned identity (ADR-0039, ADR-0071) and what the
// Vault reports about a rotation (ADR-0040, ADR-0041, ADR-0044). No scoring, no inference.
export function findingsFor(accounts: Account[], now: number, t: TFunction): Finding[] {
  return accounts.flatMap((account) => {
    const reasons: Reason[] = [];
    const protocol = account.protocol.toLowerCase();
    if (protocol === "ssh" && !account.hostKeyFingerprint) {
      reasons.push({ text: t("security.reasons.hostKey"), rotation: false });
    }
    if ((protocol === "vnc" || protocol === "rdp") && (!account.tlsCertificateSha256 || !account.targetDomain)) {
      reasons.push({ text: t("security.reasons.tls"), rotation: false });
    }
    if (account.rotationOwedSince) {
      reasons.push({ text: t("security.reasons.rotationOwed"), rotation: true });
    }
    if ((account.rotationFailures ?? 0) > 0) {
      reasons.push({ text: t("security.reasons.rotationFailures", { count: account.rotationFailures }), rotation: true });
    }
    if (account.rotationPolicy === "scheduled" && account.nextRotationAt && Date.parse(account.nextRotationAt) <= now) {
      reasons.push({ text: t("security.reasons.rotationOverdue"), rotation: true });
    }
    return reasons.length ? [{ account, reasons }] : [];
  });
}

export function countByKind(findings: Finding[]): { unpinned: number; rotation: number } {
  return {
    unpinned: findings.filter((finding) => finding.reasons.some((reason) => !reason.rotation)).length,
    rotation: findings.filter((finding) => finding.reasons.some((reason) => reason.rotation)).length,
  };
}
