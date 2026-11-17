import { useEffect, useMemo, useState } from "react";
import { Account, Page, Session } from "../../shared/api";
import { useSignedIn } from "../../shared/session";
import { AdminPage } from "../../shared/ui/AdminPage";
import { Button } from "../../shared/ui/Button";
import { StatusBadge } from "../../shared/ui/StatusBadge";
import { useAppTranslation } from "../../shared/i18n";
import { AccessControl as AccessControlIcon  } from '@openbastion/icons';

type Widget<T> = { data?: Page<T>; error?: unknown; loading: boolean };

function Metric({
  label,
  value,
  detail,
  loading,
  error,
  tone = "blue",
  action,
}: {
  label: string;
  value?: number;
  detail: string;
  loading: boolean;
  error?: unknown;
  tone?: "blue" | "cyan" | "amber" | "violet";
  action?: { label: string; onClick: () => void };
}) {
  const { t } = useAppTranslation();
  return (
    <article className={`dashboard-metric dashboard-metric-${tone}`}>
      <div className="dashboard-metric-topline">
        <p className="dashboard-metric-label">{label}</p>
        <span className="dashboard-metric-mark" aria-hidden="true" />
      </div>
      {loading ? <p className="dashboard-metric-value" role="status">…</p>
        : error ? <p className="dashboard-metric-unavailable">{t("common.unavailable")}</p>
        : <p className="dashboard-metric-value">{value ?? "—"}</p>}
      <p className="dashboard-metric-detail">{error ? t("overview.apiUnavailable") : detail}</p>
      {action && !loading && !error ? (
        <button type="button" className="dashboard-metric-link" onClick={action.onClick}>
          {action.label}<span aria-hidden="true">→</span>
        </button>
      ) : null}
    </article>
  );
}

function formatTime(value: string | undefined, locale: string): string {
  if (!value) return "—";
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? "—" : date.toLocaleTimeString(locale, { hour: "2-digit", minute: "2-digit" });
}

// Operational dashboard: every number is derived from a public, permission-checked API response.
// The current API has no global active-session feed or time-series endpoint; the view states this
// instead of fabricating chart points, recent sessions, identities or risk scores.
export function Overview({ onNavigate }: { onNavigate?: (tab: "accounts" | "sessions" | "policies" | "security") => void } = {}) {
  const { t, i18n } = useAppTranslation();
  const { api } = useSignedIn();
  const [accounts, setAccounts] = useState<Widget<Account>>({ loading: true });
  const [approvals, setApprovals] = useState<Widget<Session>>({ loading: true });
  const [refreshKey, setRefreshKey] = useState(0);

  useEffect(() => {
    let current = true;
    setAccounts({ loading: true });
    setApprovals({ loading: true });
    api.request<Page<Account>>("GET", "/vault/accounts?page=1&pageSize=100")
      .then((data) => { if (current) setAccounts({ data, loading: false }); })
      .catch((error: unknown) => { if (current) setAccounts({ error, loading: false }); });
    api.request<Page<Session>>("GET", "/sessions?status=pending_approval&page=1&pageSize=100")
      .then((data) => { if (current) setApprovals({ data, loading: false }); })
      .catch((error: unknown) => { if (current) setApprovals({ error, loading: false }); });
    return () => { current = false; };
  }, [api, refreshKey]);

  const accountItems = accounts.data?.items ?? [];
  const rotationAttention = useMemo(() => accountItems.filter((account) =>
    Boolean(account.rotationOwedSince) || (account.rotationFailures ?? 0) > 0 ||
    (account.rotationPolicy === "scheduled" && Boolean(account.nextRotationAt) && new Date(account.nextRotationAt!).getTime() < Date.now()),
  ).length, [accountItems]);
  const unpinnedTargets = useMemo(() => accountItems.filter((account) =>
    account.protocol === "ssh" ? !account.hostKeyFingerprint :
      (account.protocol === "rdp" || account.protocol === "vnc") ? !account.tlsCertificateSha256 : false,
  ).length, [accountItems]);

  const locale = i18n.language;
  const pendingItems = approvals.data?.items ?? [];

  return (
    <AdminPage
      title={t("overview.title")}
      hints={[t("overview.hint")]}
      actions={<Button variant="secondary" onClick={() => setRefreshKey((key) => key + 1)}>{t("overview.refresh")}</Button>}
    >
      <section className="dashboard-welcome" aria-label={t("overview.welcome.aria")}>
        <AccessControlIcon />
        <div className="dashboard-welcome-copy">
          <h3>{t("overview.welcome.title")}</h3>
          <p>{t("overview.welcome.body")}</p>
        </div>
        {onNavigate ? <button type="button" className="dashboard-metric-link" onClick={() => onNavigate("policies")}>{t("overview.welcome.action")} <span aria-hidden="true">→</span></button> : null}
      </section>

      <div className="dashboard-metrics" role="group" aria-label={t("overview.metricsAria")}>
        <Metric label={t("overview.accounts.label")} value={accounts.data?.totalItems} detail={t("overview.accounts.detail")} loading={accounts.loading} error={accounts.error} tone="blue" action={onNavigate ? { label: t("overview.accounts.action"), onClick: () => onNavigate("accounts") } : undefined} />
        <Metric label={t("overview.approvals.label")} value={approvals.data?.totalItems} detail={t("overview.approvals.detail")} loading={approvals.loading} error={approvals.error} tone="cyan" action={onNavigate ? { label: t("overview.approvals.action"), onClick: () => onNavigate("sessions") } : undefined} />
        <Metric label={t("overview.rotations.label")} value={rotationAttention} detail={t("overview.rotations.detail")} loading={accounts.loading} error={accounts.error} tone="amber" action={onNavigate ? { label: t("overview.accounts.action"), onClick: () => onNavigate("accounts") } : undefined} />
        <Metric label={t("overview.unpinned.label")} value={unpinnedTargets} detail={t("overview.unpinned.detail")} loading={accounts.loading} error={accounts.error} tone="violet" action={onNavigate ? { label: t("overview.security.action"), onClick: () => onNavigate("security") } : undefined} />
      </div>

      <div className="dashboard-content-grid">
        <section className="dashboard-panel dashboard-activity" aria-labelledby="dashboard-activity-title">
          <div className="dashboard-panel-heading">
            <div>
              <h3 id="dashboard-activity-title">{t("overview.activity.title")}</h3>
              <p>{t("overview.activity.subtitle")}</p>
            </div>
            <span className="dashboard-panel-tag">{t("overview.activity.tag")}</span>
          </div>
          <div className="dashboard-unavailable-state">
            <span className="dashboard-empty-icon" aria-hidden="true">⌁</span>
            <strong>{t("overview.activity.unavailableTitle")}</strong>
            <p>{t("overview.activity.unavailableBody")}</p>
          </div>
        </section>

        <section className="dashboard-panel dashboard-posture" aria-labelledby="dashboard-posture-title">
          <div className="dashboard-panel-heading">
            <div>
              <h3 id="dashboard-posture-title">{t("overview.posture.title")}</h3>
              <p>{t("overview.posture.subtitle")}</p>
            </div>
            <span className="dashboard-posture-tag">{t("overview.posture.tag")}</span>
          </div>
          <div className="dashboard-posture-list">
            <div className="dashboard-posture-row">
              <span><i className="dashboard-posture-dot dashboard-dot-blue" />{t("overview.posture.accounts")}</span>
              <strong>{accounts.loading ? "…" : accounts.error ? "—" : accounts.data?.totalItems ?? 0}</strong>
            </div>
            <div className="dashboard-posture-row">
              <span><i className="dashboard-posture-dot dashboard-dot-amber" />{t("overview.posture.rotations")}</span>
              <strong>{accounts.loading ? "…" : accounts.error ? "—" : rotationAttention}</strong>
            </div>
            <div className="dashboard-posture-row">
              <span><i className="dashboard-posture-dot dashboard-dot-violet" />{t("overview.posture.unpinned")}</span>
              <strong>{accounts.loading ? "…" : accounts.error ? "—" : unpinnedTargets}</strong>
            </div>
          </div>
          {accounts.data && accounts.data.totalItems > accountItems.length ? (
            <p className="dashboard-panel-note">{t("overview.scope.rotationNote", { loaded: accountItems.length, total: accounts.data.totalItems })}</p>
          ) : null}
          {onNavigate ? <button type="button" className="dashboard-posture-action" onClick={() => onNavigate("security")}>{t("overview.posture.action")} <span aria-hidden="true">→</span></button> : null}
        </section>
      </div>

      <section className="dashboard-panel dashboard-approvals" aria-labelledby="dashboard-approvals-title">
        <div className="dashboard-panel-heading">
          <div>
            <h3 id="dashboard-approvals-title">{t("overview.recent.title")}</h3>
            <p>{t("overview.recent.subtitle")}</p>
          </div>
          {onNavigate ? <button type="button" className="dashboard-text-link" onClick={() => onNavigate("sessions")}>{t("overview.recent.action")} <span aria-hidden="true">→</span></button> : null}
        </div>
        {approvals.loading ? <p className="dashboard-table-state" role="status">{t("common.loading")}</p> : null}
        {approvals.error ? <p className="dashboard-table-state" role="alert">{t("overview.apiUnavailable")}</p> : null}
        {!approvals.loading && !approvals.error && pendingItems.length === 0 ? <p className="dashboard-table-state">{t("overview.recent.empty")}</p> : null}
        {!approvals.loading && !approvals.error && pendingItems.length > 0 ? (
          <div className="dashboard-table-wrap">
            <table className="dashboard-table">
              <thead><tr>
                <th>{t("overview.recent.requester")}</th><th>{t("overview.recent.account")}</th><th>{t("overview.recent.protocol")}</th><th>{t("overview.recent.started")}</th><th>{t("overview.recent.status")}</th>
              </tr></thead>
              <tbody>{pendingItems.slice(0, 5).map((session) => (
                <tr key={session.id}>
                  <td><strong>{session.requestedBy}</strong><small>{session.id}</small></td>
                  <td>{session.privilegedAccountId}</td>
                  <td><span className="dashboard-protocol">{session.protocol.toUpperCase()}</span></td>
                  <td><time dateTime={session.createdAt}>{formatTime(session.createdAt, locale)}</time></td>
                  <td><StatusBadge status={session.status} /></td>
                </tr>
              ))}</tbody>
            </table>
          </div>
        ) : null}
        {approvals.data?.truncated ? <p className="dashboard-panel-note">{t("overview.scope.truncated")}</p> : null}
      </section>
    </AdminPage>
  );
}
