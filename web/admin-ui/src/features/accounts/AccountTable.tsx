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

export function AccountTable({ accounts, actions }: { accounts: Account[]; actions: AccountActions }) {
  const { t } = useAppTranslation();
  return (
    <div className="ob-table-wrap">
      <table className="ob-data-table">
        <caption className="ob-visually-hidden">{t("accounts.table.caption")}</caption>
        <thead>
          <tr>
            <th scope="col">{t("accounts.table.id")}</th>
            <th scope="col">{t("accounts.table.name")}</th>
            <th scope="col">{t("accounts.table.target")}</th>
            <th scope="col">{t("accounts.table.username")}</th>
            <th scope="col">{t("accounts.table.identity")}</th>
            <th scope="col">{t("accounts.table.rotation")}</th>
            <th scope="col">{t("accounts.table.lastRotation")}</th>
            <th scope="col">{t("accounts.table.approval")}</th>
            <th scope="col">{t("accounts.table.actions")}</th>
          </tr>
        </thead>
        <tbody>
          {accounts.map((a) => (
            <tr key={a.id}>
              <td>
                <code>{a.id}</code>
              </td>
              <td>{a.name}</td>
              <td>{a.targetHost}</td>
              <td>{a.username}</td>
              <td>
                <TargetIdentity account={a} />
              </td>
              <td>
                <Rotation account={a} />
              </td>
              <td>{a.lastRotatedAt ?? "—"}</td>
              <td>{a.approvalRequired ? <Badge>{t("accounts.table.approvalRequired")}</Badge> : "—"}</td>
              <td className="ob-table-actions">
                <div>
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

// The pinned identity of the target: a host key for SSH (ADR-0039), a TLS certificate for a
// graphical target (ADR-0071). An account without one opens no session.
function TargetIdentity({ account: a }: { account: Account }) {
  const { t } = useAppTranslation();
  if (a.protocol === "ssh") {
    return a.hostKeyFingerprint
      ? <code title={a.hostKey}>{a.hostKeyFingerprint}</code>
      : <Badge tone="warning">{t("accounts.table.notPinned")}</Badge>;
  }
  return a.tlsCertificateSha256
    ? <code title={a.targetDomain}>{a.tlsCertificateSha256}</code>
    : <Badge tone="warning">{t("accounts.table.notPinned")}</Badge>;
}

// The rotation a secret is under, and what the Vault reports about it: a cadence (ADR-0040), a
// rotation owed after a session (ADR-0044), and scheduled rotations that keep failing (ADR-0041).
function Rotation({ account: a }: { account: Account }) {
  const { t } = useAppTranslation();
  return (
    <>
      <Badge>{a.rotationPolicy}</Badge>
      {a.rotationIntervalDays ? (
        <span className="cell-note">
          {t("accounts.table.every", { days: a.rotationIntervalDays, next: a.nextRotationAt ?? "—" })}
        </span>
      ) : null}
      {a.rotationOwedSince ? (
        <Badge tone="warning" title={t("accounts.table.rotationOwedTitle", { since: a.rotationOwedSince })}>
          {t("accounts.table.rotationOwed")}
        </Badge>
      ) : null}
      {a.rotationFailures ? (
        <Badge tone="warning" title={t("accounts.table.rotationFailedTitle")}>
          {t("accounts.table.rotationFailed", { count: a.rotationFailures })}
        </Badge>
      ) : null}
    </>
  );
}
