import { Account } from "../../shared/api";
import { Badge } from "../../shared/ui/Badge";
import { Button } from "../../shared/ui/Button";
import { useAppTranslation } from "../../shared/i18n";
import { AccountStatePill, EnvironmentCell } from "./AccountTable";

// The same accounts, read as access points: which target, over which protocol, under which
// access rule, and whether that access point can actually open a session. Opening one hands the
// operator to the account view, where the identity, the rotation and the actions live.
export function ResourceTable({ accounts, onOpen }: { accounts: Account[]; onOpen: (account: Account) => void }) {
  const { t } = useAppTranslation();
  return (
    <div className="ob-table-wrap reference-table-wrap">
      <table className="ob-data-table reference-table resource-table">
        <caption className="ob-visually-hidden">{t("accounts.reference.resourcesCaption")}</caption>
        <thead>
          <tr>
            <th scope="col">{t("accounts.reference.columns.resource")}</th>
            <th scope="col">{t("accounts.reference.columns.address")}</th>
            <th scope="col">{t("accounts.reference.columns.protocol")}</th>
            <th scope="col">{t("accounts.reference.columns.environment")}</th>
            <th scope="col">{t("accounts.reference.columns.access")}</th>
            <th scope="col">{t("accounts.reference.columns.state")}</th>
            <th scope="col"><span className="ob-visually-hidden">{t("accounts.reference.columns.open")}</span></th>
          </tr>
        </thead>
        <tbody>
          {accounts.map((account) => (
            <tr key={account.id}>
              <td><strong className="reference-identifier">{account.name || account.id}</strong></td>
              <td><code className="reference-address">{account.targetHost}</code></td>
              <td><Badge className="reference-pill" tone="neutral">{account.protocol.toUpperCase()}</Badge></td>
              <td><EnvironmentCell /></td>
              <td>
                {account.approvalRequired
                  ? <Badge className="reference-pill" tone="neutral">{t("accounts.table.approvalRequired")}</Badge>
                  : <span className="reference-cell-muted">{t("accounts.reference.directAccess")}</span>}
              </td>
              <td><AccountStatePill account={account} /></td>
              <td className="reference-open-cell">
                <Button variant="ghost" className="reference-link" onClick={() => onOpen(account)}>
                  {t("accounts.reference.open")} <span aria-hidden="true">↗</span>
                </Button>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
