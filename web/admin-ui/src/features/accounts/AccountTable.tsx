import { Account } from "../../shared/api";
import { Badge } from "../../shared/ui/Badge";
import { Button } from "../../shared/ui/Button";
import { useAppTranslation } from "../../shared/i18n";

// What a row can ask of its account. The screen owns the calls and the notices; the table only
// says which account each button names.
export interface AccountActions {
  pinKey: (account: Account) => void;
  pinTls: (account: Account) => void;
  toggleApproval: (account: Account) => void;
  rotate: (account: Account) => void;
  disable: (account: Account) => void;
}

// The state of an access point, as the Vault's fields alone allow it: an account that cannot
// present a pinned identity opens no session (ADR-0039, ADR-0071), and a disabled account opens
// none either. Nothing here is inferred from usage.
export function accountState(account: Account): "disabled" | "unpinned" | "available" {
  if (account.disabledAt) return "disabled";
  const pinned = account.protocol === "ssh" ? Boolean(account.hostKeyFingerprint) : Boolean(account.tlsCertificateSha256 && account.targetDomain);
  return pinned ? "available" : "unpinned";
}

export function AccountStatePill({ account }: { account: Account }) {
  const { t } = useAppTranslation();
  const state = accountState(account);
  return (
    <Badge
      className="reference-pill"
      tone={state === "available" ? "info" : state === "unpinned" ? "warning" : "neutral"}
    >
      {t(`accounts.state.${state}`)}
    </Badge>
  );
}

export function AccountTable({ accounts, actions }: { accounts: Account[]; actions: AccountActions }) {
  const { t } = useAppTranslation();
  return (
    <div className="ob-table-wrap reference-table-wrap">
      <table className="ob-data-table reference-table account-table">
        <caption className="ob-visually-hidden">{t("accounts.table.caption")}</caption>
        <thead>
          <tr>
            <th scope="col">{t("accounts.reference.columns.resource")}</th>
            <th scope="col">{t("accounts.reference.columns.address")}</th>
            <th scope="col">{t("accounts.reference.columns.protocol")}</th>
            <th scope="col">{t("accounts.reference.columns.environment")}</th>
            <th scope="col">{t("accounts.reference.columns.access")}</th>
            <th scope="col">{t("accounts.reference.columns.state")}</th>
            <th scope="col">{t("accounts.table.actions")}</th>
          </tr>
        </thead>
        <tbody>
          {accounts.map((a) => (
            <tr key={a.id}>
              <td>
                <strong className="reference-identifier">{a.name || a.id}</strong>
                <span className="reference-cell-note"><code>{a.id}</code></span>
              </td>
              <td>
                <code className="reference-address">{a.targetHost}</code>
                <span className="reference-cell-note"><TargetIdentity account={a} /></span>
              </td>
              <td><Badge className="reference-pill" tone="neutral">{a.protocol.toUpperCase()}</Badge></td>
              <td><EnvironmentCell /></td>
              <td>
                {a.approvalRequired
                  ? <Badge className="reference-pill" tone="neutral">{t("accounts.table.approvalRequired")}</Badge>
                  : <span className="reference-cell-muted">{t("accounts.reference.directAccess")}</span>}
                <span className="reference-cell-note">{a.username}</span>
              </td>
              <td>
                <AccountStatePill account={a} />
                <span className="reference-cell-note"><Rotation account={a} /></span>
              </td>
              <td className="ob-table-actions">
                <div className="reference-row-actions">
                  {a.protocol === "ssh" ? (
                    <Button onClick={() => actions.pinKey(a)}>
                      {a.hostKeyFingerprint ? t("accounts.table.changeHostKey") : t("accounts.table.pinHostKey")}
                    </Button>
                  ) : (
                    <Button onClick={() => actions.pinTls(a)}>
                      {a.tlsCertificateSha256 ? t("accounts.table.changeCertificate") : t("accounts.table.pinCertificate")}
                    </Button>
                  )}
                  <Button onClick={() => actions.toggleApproval(a)}>
                    {a.approvalRequired ? t("accounts.table.noApproval") : t("accounts.table.requireApproval")}
                  </Button>
                  {a.protocol === "ssh" ? (
                    <Button onClick={() => actions.rotate(a)}>
                      {t("accounts.table.rotate")}
                    </Button>
                  ) : null}
                  <Button variant="danger" onClick={() => actions.disable(a)}>
                    {t("accounts.table.disable")}
                  </Button>
                </div>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

// The environment of a target is not part of the account: the Vault stores the target's address,
// never a deployment stage. The reference column keeps its place and says so.
export function EnvironmentCell() {
  const { t } = useAppTranslation();
  return <span className="reference-cell-muted" title={t("accounts.reference.environmentUnavailable")}>—</span>;
}

// The pinned identity of the target: a host key for SSH (ADR-0039), a TLS certificate for a
// graphical target (ADR-0071). An account without one opens no session.
function TargetIdentity({ account: a }: { account: Account }) {
  const { t } = useAppTranslation();
  if (a.protocol === "ssh") {
    return a.hostKeyFingerprint
      ? <code title={a.hostKey}>{a.hostKeyFingerprint}</code>
      : <span className="reference-cell-warning">{t("accounts.table.notPinned")}</span>;
  }
  return a.tlsCertificateSha256
    ? <code title={a.targetDomain}>{a.tlsCertificateSha256}</code>
    : <span className="reference-cell-warning">{t("accounts.table.notPinned")}</span>;
}

// The rotation a secret is under, and what the Vault reports about it: a cadence (ADR-0040), a
// rotation owed after a session (ADR-0044), and scheduled rotations that keep failing (ADR-0041).
function Rotation({ account: a }: { account: Account }) {
  const { t } = useAppTranslation();
  return (
    <>
      <span>{a.rotationPolicy}</span>
      {a.rotationIntervalDays ? (
        <span> — {t("accounts.table.every", { days: a.rotationIntervalDays, next: a.nextRotationAt ?? "—" })}</span>
      ) : null}
      {a.rotationOwedSince ? (
        <Badge
          className="reference-pill"
          tone="warning"
          title={t("accounts.table.rotationOwedTitle", { since: a.rotationOwedSince })}
        >
          {t("accounts.table.rotationOwed")}
        </Badge>
      ) : null}
      {a.rotationFailures ? (
        <Badge className="reference-pill" tone="warning" title={t("accounts.table.rotationFailedTitle")}>
          {t("accounts.table.rotationFailed", { count: a.rotationFailures })}
        </Badge>
      ) : null}
    </>
  );
}
